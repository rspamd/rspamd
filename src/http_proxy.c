/*-
 * Copyright 2016 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
#include "rspamd.h"
#include "libserver/worker_util.h"
#include "keypairs_cache.h"
#include "ottery.h"
#include "unix-std.h"

/* Rotate keys each minute by default */
#define DEFAULT_ROTATION_TIME 60.0

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
	SOCK_STREAM,                /* TCP socket */
	RSPAMD_WORKER_VER
};

struct rspamd_http_upstream {
	gchar *name;
	struct upstream_list *u;
	struct rspamd_cryptobox_pubkey *key;
};

struct http_proxy_ctx {
	gdouble timeout;
	struct timeval io_tv;
	struct rspamd_config *cfg;
	/* DNS resolver */
	struct rspamd_dns_resolver *resolver;
	/* Events base */
	struct event_base *ev_base;
	/* Encryption key for clients */
	struct rspamd_cryptobox_keypair *key;
	/* Keys cache */
	struct rspamd_keypair_cache *keys_cache;
	/* Upstreams to use */
	GHashTable *upstreams;
	/* Default upstream */
	struct rspamd_http_upstream *default_upstream;
	/* Local rotating keypair for upstreams */
	struct rspamd_cryptobox_keypair *local_key;
	struct event rotate_ev;
	gdouble rotate_tm;
};

struct http_proxy_session {
	struct http_proxy_ctx *ctx;
	struct event_base *ev_base;
	struct rspamd_cryptobox_keypair *local_key;
	struct rspamd_cryptobox_pubkey *remote_key;
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
	struct http_proxy_ctx *ctx;
	struct rspamd_rcl_struct_parser *pd = ud;

	ctx = pd->user_struct;

	if (ucl_object_type (obj) != UCL_OBJECT) {
		g_set_error (err, http_proxy_quark (), 100,
				"upstream option must be an object");

		return FALSE;
	}

	elt = ucl_object_lookup (obj, "name");
	if (elt == NULL) {
		g_set_error (err, http_proxy_quark (), 100,
				"upstream option must have some name definition");

		return FALSE;
	}

	up = g_slice_alloc0 (sizeof (*up));
	up->name = g_strdup (ucl_object_tostring (elt));

	elt = ucl_object_lookup (obj, "key");
	if (elt != NULL) {
		up->key = rspamd_pubkey_from_base32 (ucl_object_tostring (elt), 0,
				RSPAMD_KEYPAIR_KEX, RSPAMD_CRYPTOBOX_MODE_25519);

		if (up->key == NULL) {
			g_set_error (err, http_proxy_quark (), 100,
					"cannot read upstream key");

			goto err;
		}
	}

	elt = ucl_object_lookup (obj, "hosts");

	if (elt == NULL) {
		g_set_error (err, http_proxy_quark (), 100,
				"upstream option must have some hosts definition");

		goto err;
	}

	up->u = rspamd_upstreams_create (ctx->cfg->ups_ctx);
	if (!rspamd_upstreams_from_ucl (up->u, elt, 11333, NULL)) {
		g_set_error (err, http_proxy_quark (), 100,
				"upstream has bad hosts definition");

		goto err;
	}

	elt = ucl_object_lookup (obj, "default");
	if (elt && ucl_object_toboolean (elt)) {
		ctx->default_upstream = up;
	}

	g_hash_table_insert (ctx->upstreams, up->name, up);

	return TRUE;

err:

	if (up) {
		g_free (up->name);
		rspamd_upstreams_destroy (up->u);

		if (up->key) {
			rspamd_pubkey_unref (up->key);
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

	type = g_quark_try_string ("http_proxy");

	ctx = g_malloc0 (sizeof (struct http_proxy_ctx));
	ctx->timeout = 5.0;
	ctx->upstreams = g_hash_table_new (rspamd_strcase_hash, rspamd_strcase_equal);
	ctx->rotate_tm = DEFAULT_ROTATION_TIME;
	ctx->cfg = cfg;

	rspamd_rcl_register_worker_option (cfg,
			type,
			"timeout",
			rspamd_rcl_parse_struct_time,
			ctx,
			G_STRUCT_OFFSET (struct http_proxy_ctx,
					timeout),
			RSPAMD_CL_FLAG_TIME_FLOAT,
			"IO timeout");
	rspamd_rcl_register_worker_option (cfg,
			type,
			"rotate",
			rspamd_rcl_parse_struct_time,
			ctx,
			G_STRUCT_OFFSET (struct http_proxy_ctx,
					rotate_tm),
			RSPAMD_CL_FLAG_TIME_FLOAT,
			"Rotation keys time, default: "
			G_STRINGIFY (DEFAULT_ROTATION_TIME) " seconds");
	rspamd_rcl_register_worker_option (cfg,
			type,
			"keypair",
			rspamd_rcl_parse_struct_keypair,
			ctx,
			G_STRUCT_OFFSET (struct http_proxy_ctx,
					key),
			0,
			"Server's keypair");
	rspamd_rcl_register_worker_option (cfg,
			type,
			"upstream",
			http_proxy_parse_upstream,
			ctx,
			0,
			0,
			"List of upstreams");

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
		rspamd_http_connection_unref (session->client_conn);
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
	rspamd_http_connection_reset (session->backend_conn);
	/* Terminate session immediately */
	proxy_client_write_error (session, err->code);
}

static gint
proxy_backend_finish_handler (struct rspamd_http_connection *conn,
	struct rspamd_http_message *msg)
{
	struct http_proxy_session *session = conn->ud;

	rspamd_http_connection_steal_msg (session->backend_conn);
	rspamd_http_message_remove_header (msg, "Content-Length");
	rspamd_http_message_remove_header (msg, "Key");
	rspamd_http_connection_reset (session->backend_conn);
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
	const rspamd_ftok_t *host;
	gchar hostbuf[512];

	if (!session->replied) {
		host = rspamd_http_message_find_header (msg, "Host");

		if (host == NULL) {
			backend = session->ctx->default_upstream;
		}
		else {
			rspamd_strlcpy (hostbuf, host->begin, MIN(host->len + 1, sizeof (hostbuf)));
			backend = g_hash_table_lookup (session->ctx->upstreams, hostbuf);

			if (backend == NULL) {
				backend = session->ctx->default_upstream;
			}
		}

		if (backend == NULL) {
			/* No backend */
			msg_err ("cannot find upstream for %s", host ? hostbuf : "default");
			goto err;
		}
		else {
			session->up = rspamd_upstream_get (backend->u,
					RSPAMD_UPSTREAM_ROUND_ROBIN, NULL, 0);

			if (session->up == NULL) {
				msg_err ("cannot select upstream for %s", host ? hostbuf : "default");
				goto err;
			}

			session->backend_sock = rspamd_inet_address_connect (
					rspamd_upstream_addr (session->up), SOCK_STREAM, TRUE);

			if (session->backend_sock == -1) {
				msg_err ("cannot connect upstream for %s", host ? hostbuf : "default");
				rspamd_upstream_fail (session->up);
				goto err;
			}

			rspamd_http_connection_steal_msg (session->client_conn);
			rspamd_http_message_remove_header (msg, "Content-Length");
			rspamd_http_message_remove_header (msg, "Key");
			rspamd_http_connection_reset (session->client_conn);
			session->backend_conn = rspamd_http_connection_new (
					NULL,
					proxy_backend_error_handler,
					proxy_backend_finish_handler,
					RSPAMD_HTTP_CLIENT_SIMPLE,
					RSPAMD_HTTP_CLIENT,
					session->ctx->keys_cache);

			rspamd_http_connection_set_key (session->backend_conn,
					session->ctx->local_key);
			msg->peer_key = rspamd_pubkey_ref (backend->key);
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

static void
proxy_rotate_key (gint fd, short what, void *arg)
{
	struct timeval rot_tv;
	struct http_proxy_ctx *ctx = arg;
	gpointer kp;

	double_to_tv (ctx->rotate_tm, &rot_tv);
	rot_tv.tv_sec += ottery_rand_range (rot_tv.tv_sec);
	event_del (&ctx->rotate_ev);
	event_add (&ctx->rotate_ev, &rot_tv);

	kp = ctx->local_key;
	ctx->local_key = rspamd_keypair_new (RSPAMD_KEYPAIR_KEX,
			RSPAMD_CRYPTOBOX_MODE_25519);
	rspamd_keypair_unref (kp);
}

void
start_http_proxy (struct rspamd_worker *worker)
{
	struct http_proxy_ctx *ctx = worker->ctx;
	struct timeval rot_tv;

	ctx->ev_base = rspamd_prepare_worker (worker, "http_proxy",
			proxy_accept_socket);

	rspamd_map_watch (worker->srv->cfg, ctx->ev_base);


	ctx->resolver = dns_resolver_init (worker->srv->logger,
			ctx->ev_base,
			worker->srv->cfg);
	double_to_tv (ctx->timeout, &ctx->io_tv);

	rspamd_upstreams_library_config (worker->srv->cfg, ctx->cfg->ups_ctx,
			ctx->ev_base, ctx->resolver->r);

	/* XXX: stupid default */
	ctx->keys_cache = rspamd_keypair_cache_new (256);
	ctx->local_key = rspamd_keypair_new (RSPAMD_KEYPAIR_KEX,
			RSPAMD_CRYPTOBOX_MODE_25519);

	double_to_tv (ctx->rotate_tm, &rot_tv);
	rot_tv.tv_sec += ottery_rand_range (rot_tv.tv_sec);
	event_set (&ctx->rotate_ev, -1, EV_TIMEOUT, proxy_rotate_key, ctx);
	event_base_set (ctx->ev_base, &ctx->rotate_ev);
	event_add (&ctx->rotate_ev, &rot_tv);

	event_base_loop (ctx->ev_base, 0);
	rspamd_worker_block_signals ();

	g_mime_shutdown ();
	rspamd_log_close (worker->srv->logger);

	if (ctx->key) {
		rspamd_keypair_unref (ctx->key);
	}

	rspamd_keypair_cache_destroy (ctx->keys_cache);

	exit (EXIT_SUCCESS);
}

