/*
 * Copyright (c) 2015, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "libutil/util.h"
#include "libutil/map.h"
#include "libutil/upstream.h"
#include "libserver/protocol.h"
#include "libserver/cfg_file.h"
#include "libserver/url.h"
#include "libserver/dns.h"
#include "libmime/message.h"
#include "main.h"
#include "keypairs_cache.h"

gpointer init_http_proxy (struct rspamd_config *cfg);
void start_http_proxy (struct rspamd_worker *worker);

worker_t http_proxy_worker = {
	"http_proxy",               /* Name */
	init_http_proxy,            /* Init function */
	start_http_proxy,           /* Start function */
	TRUE,                       /* Has socket */
	FALSE,                      /* Non unique */
	FALSE,                      /* Non threaded */
	TRUE,                       /* Killable */
	SOCK_STREAM                 /* TCP socket */
};

struct rspamd_http_upstream {
	gchar *name;
	struct upstream_list *u;
	gpointer key;
};

struct http_proxy_ctx {
	gdouble timeout;
	struct timeval io_tv;
	/* DNS resolver */
	struct rspamd_dns_resolver *resolver;
	/* Events base */
	struct event_base *ev_base;
	/* Encryption key for clients */
	gpointer key;
	/* Keys cache */
	struct rspamd_keypair_cache *keys_cache;
	/* Upstreams to use */
	GHashTable *upstreams;
	/* Default upstream */
	struct rspamd_http_upstream *default_upstream;
	/* Local rotating keypair for upstreams */
	gpointer local_key;
	struct event rotate_ev;
};

struct http_proxy_session {
	struct http_proxy_ctx *ctx;
	struct event_base *ev_base;
	gpointer local_key;
	gpointer remote_key;
	struct upstream *up;
	gint client_sock;
	gint backend_sock;
	rspamd_inet_addr_t *client_addr;
	struct rspamd_http_connection *client_conn;
	struct rspamd_http_connection *backend_conn;
	struct rspamd_dns_resolver *resolver;
	gboolean replied;
};

static GQuark
http_proxy_quark (void)
{
	return g_quark_from_static_string ("http-proxy");
}

static gboolean
http_proxy_parse_upstream (rspamd_mempool_t *pool,
	const ucl_object_t *obj,
	gpointer ud,
	struct rspamd_rcl_section *section,
	GError **err)
{
	const ucl_object_t *elt;
	struct rspamd_http_upstream *up = NULL;
	struct http_proxy_ctx *ctx = ud;

	if (ucl_object_type (obj) != UCL_OBJECT) {
		g_set_error (err, http_proxy_quark (), 100,
				"upstream option must be an object");

		return FALSE;
	}

	elt = ucl_object_find_key (obj, "name");
	if (elt == NULL) {
		g_set_error (err, http_proxy_quark (), 100,
				"upstream option must have some name definition");

		return FALSE;
	}

	up = g_slice_alloc0 (sizeof (*up));
	up->name = g_strdup (ucl_object_tostring (elt));

	elt = ucl_object_find_key (obj, "key");
	if (elt != NULL) {
		up->key = rspamd_http_connection_make_peer_key (ucl_object_tostring (elt));

		if (up->key == NULL) {
			g_set_error (err, http_proxy_quark (), 100,
					"cannot read upstream key");

			goto err;
		}
	}

	elt = ucl_object_find_key (obj, "hosts");

	if (elt == NULL) {
		g_set_error (err, http_proxy_quark (), 100,
				"upstream option must have some hosts definition");

		goto err;
	}

	up->u = rspamd_upstreams_create ();
	if (!rspamd_upstreams_from_ucl (up->u, elt, 11333, NULL)) {
		g_set_error (err, http_proxy_quark (), 100,
				"upstream has bad hosts definition");

		goto err;
	}

	elt = ucl_object_find_key (obj, "default");
	if (elt && ucl_object_toboolean (elt)) {
		ctx->default_upstream = up;
	}

	g_hash_table_insert (ctx->upstreams, up->name, up);

err:

	if (up) {
		g_free (up->name);
		rspamd_upstreams_destroy (up->u);

		if (up->key) {
			rspamd_http_connection_key_unref (up->key);
		}

		g_slice_free1 (sizeof (*up), up);
	}

	return FALSE;
}

gpointer
init_http_proxy (struct rspamd_config *cfg)
{
	struct http_proxy_ctx *ctx;
	GQuark type;

	type = g_quark_try_string ("http-proxy");

	ctx = g_malloc0 (sizeof (struct http_proxy_ctx));
	ctx->timeout = 5.0;
	ctx->upstreams = g_hash_table_new (rspamd_strcase_hash, rspamd_strcase_equal);

	rspamd_rcl_register_worker_option (cfg, type, "timeout",
		rspamd_rcl_parse_struct_time, ctx,
		G_STRUCT_OFFSET (struct http_proxy_ctx,
		timeout), RSPAMD_CL_FLAG_TIME_FLOAT);
	rspamd_rcl_register_worker_option (cfg, type, "keypair",
		rspamd_rcl_parse_struct_keypair, ctx,
		G_STRUCT_OFFSET (struct http_proxy_ctx,
		key), 0);
	rspamd_rcl_register_worker_option (cfg, type, "upstream",
		http_proxy_parse_upstream, ctx, 0, 0);

	return ctx;
}

static void
proxy_session_cleanup (struct http_proxy_session *session)
{
	rspamd_inet_address_destroy (session->client_addr);

	if (session->backend_conn) {
		rspamd_http_connection_unref (session->backend_conn);
	}
	if (session->client_conn) {
		rspamd_http_connection_unref (session->backend_conn);
	}

	close (session->backend_sock);
	close (session->client_sock);

	g_slice_free1 (sizeof (*session), session);
}

static void
proxy_client_write_error (struct http_proxy_session *session, gint code)
{
	struct rspamd_http_message *reply;

	reply = rspamd_http_new_message (HTTP_RESPONSE);
	reply->code = code;
	rspamd_http_connection_write_message (session->client_conn,
			reply, NULL, NULL, session, session->client_sock,
			&session->ctx->io_tv, session->ev_base);
}

static void
proxy_backend_error_handler (struct rspamd_http_connection *conn, GError *err)
{
	struct http_proxy_session *session = conn->ud;

	msg_info ("abnormally closing connection from backend: %s, error: %s",
		rspamd_inet_address_to_string (rspamd_upstream_addr (session->up)),
		err->message);
	/* Terminate session immediately */
	proxy_client_write_error (session, err->code);
}

static gint
proxy_backend_finish_handler (struct rspamd_http_connection *conn,
	struct rspamd_http_message *msg)
{
	struct http_proxy_session *session = conn->ud;

	rspamd_http_connection_write_message (session->client_conn,
		msg, NULL, NULL, session, session->client_sock,
		&session->ctx->io_tv, session->ev_base);

	return 0;
}

static void
proxy_client_error_handler (struct rspamd_http_connection *conn, GError *err)
{
	struct http_proxy_session *session = conn->ud;

	msg_info ("abnormally closing connection from: %s, error: %s",
		rspamd_inet_address_to_string (session->client_addr), err->message);
	/* Terminate session immediately */
	proxy_session_cleanup (session);
}

static gint
proxy_client_finish_handler (struct rspamd_http_connection *conn,
	struct rspamd_http_message *msg)
{
	struct http_proxy_session *session = conn->ud;
	struct rspamd_http_upstream *backend = NULL;
	const gchar *host;

	if (!session->replied) {
		host = rspamd_http_message_find_header (msg, "Host");

		if (host == NULL) {
			backend = session->ctx->default_upstream;
		}
		else {
			backend = g_hash_table_lookup (session->ctx->upstreams, host);
		}

		if (backend == NULL) {
			/* No backend */
			msg_err ("cannot find upstream for %s", host ? host : "default");
			goto err;
		}
		else {
			session->up = rspamd_upstream_get (backend->u, RSPAMD_UPSTREAM_ROUND_ROBIN);

			if (session->up == NULL) {
				msg_err ("cannot select upstream for %s", host ? host : "default");
				goto err;
			}

			session->backend_sock = rspamd_inet_address_connect (
					rspamd_upstream_addr (session->up), SOCK_STREAM, TRUE);

			if (session->backend_sock == -1) {
				msg_err ("cannot connect upstream for %s", host ? host : "default");
				rspamd_upstream_fail (session->up);
				goto err;
			}

			session->backend_conn = rspamd_http_connection_new (
					NULL,
					proxy_backend_error_handler,
					proxy_backend_finish_handler,
					RSPAMD_HTTP_CLIENT_SIMPLE,
					RSPAMD_HTTP_CLIENT,
					session->ctx->keys_cache);

			rspamd_http_connection_set_key (session->backend_conn,
					session->ctx->local_key);
			msg->peer_key = rspamd_http_connection_key_ref (backend->key);
			session->replied = TRUE;

			rspamd_http_connection_write_message (session->backend_conn,
				msg, NULL, NULL, session, session->backend_sock,
				&session->ctx->io_tv, session->ev_base);
		}
	}
	else {
		proxy_session_cleanup (session);
	}

	return 0;

err:
	session->replied = TRUE;
	proxy_client_write_error (session, 404);

	return 0;
}

static void
proxy_accept_socket (gint fd, short what, void *arg)
{
	struct rspamd_worker *worker = (struct rspamd_worker *) arg;
	struct http_proxy_ctx *ctx;
	rspamd_inet_addr_t *addr;
	struct http_proxy_session *session;
	gint nfd;

	ctx = worker->ctx;

	if ((nfd =
		rspamd_accept_from_socket (fd, &addr)) == -1) {
		msg_warn ("accept failed: %s", strerror (errno));
		return;
	}
	/* Check for EAGAIN */
	if (nfd == 0) {
		return;
	}

	msg_info ("accepted connection from %s port %d",
		rspamd_inet_address_to_string (addr),
		rspamd_inet_address_get_port (addr));

	session = g_slice_alloc0 (sizeof (*session));
	session->client_sock = nfd;
	session->client_addr = addr;

	session->resolver = ctx->resolver;

	session->client_conn = rspamd_http_connection_new (
		NULL,
		proxy_client_error_handler,
		proxy_client_finish_handler,
		0,
		RSPAMD_HTTP_SERVER,
		ctx->keys_cache);
	session->ev_base = ctx->ev_base;
	session->ctx = ctx;

	if (ctx->key) {
		rspamd_http_connection_set_key (session->client_conn, ctx->key);
	}

	rspamd_http_connection_read_message (session->client_conn,
		session,
		nfd,
		&ctx->io_tv,
		ctx->ev_base);
}

void
start_http_proxy (struct rspamd_worker *worker)
{
	struct http_proxy_ctx *ctx = worker->ctx;
	GError *err = NULL;

	ctx->ev_base = rspamd_prepare_worker (worker, "http_proxy",
			proxy_accept_socket);

	rspamd_map_watch (worker->srv->cfg, ctx->ev_base);


	ctx->resolver = dns_resolver_init (worker->srv->logger,
			ctx->ev_base,
			worker->srv->cfg);
	double_to_tv (ctx->timeout, &ctx->io_tv);

	rspamd_upstreams_library_init (ctx->resolver->r, ctx->ev_base);
	rspamd_upstreams_library_config (worker->srv->cfg);

	/* XXX: stupid default */
	ctx->keys_cache = rspamd_keypair_cache_new (256);

	event_base_loop (ctx->ev_base, 0);

	g_mime_shutdown ();
	rspamd_log_close (rspamd_main->logger);

	if (ctx->key) {
		rspamd_http_connection_key_unref (ctx->key);
	}

	rspamd_keypair_cache_destroy (ctx->keys_cache);

	exit (EXIT_SUCCESS);
}

