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
#include "rspamd.h"
#include "util.h"
#include "libutil/fstring.h"
#include "libutil/http.h"
#include "libutil/http_private.h"
#include "ottery.h"
#include "cryptobox.h"
#include "keypair.h"
#include "unix-std.h"
#include <math.h>

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

static guint port = 43000;
static guint cache_size = 10;
static guint nworkers = 1;
static gboolean openssl_mode = FALSE;
static GHashTable *maps = NULL;
static gchar *key = NULL;
static struct rspamd_keypair_cache *c;
static struct rspamd_cryptobox_keypair *server_key;
static struct timeval io_tv = {
		.tv_sec = 20,
		.tv_usec = 0
};

static GOptionEntry entries[] = {
		{"port",       'p', 0, G_OPTION_ARG_INT,     &port,
				"Port number (default: 43000)",                  NULL},
		{"cache", 'c', 0, G_OPTION_ARG_INT, &cache_size,
				"Keys cache size (default: 10)", NULL},
		{"workers", 'n', 0, G_OPTION_ARG_INT, &nworkers,
				"Number of workers to start (default: 1)", NULL},
		{"openssl", 'o', 0, G_OPTION_ARG_NONE, &openssl_mode,
				"Use openssl crypto", NULL},
		{"key", 'k', 0, G_OPTION_ARG_STRING, &key,
				"Use static keypair instead of new one (base32 encoded sk || pk)", NULL},
		{NULL,            0,   0, G_OPTION_ARG_NONE, NULL, NULL, NULL}
};

struct rspamd_http_server_session {
	struct rspamd_http_connection *conn;
	struct ev_loop *ev_base;
	guint req_size;
	gboolean reply;
	gint fd;
};

static void
rspamd_server_error (struct rspamd_http_connection *conn,
		GError *err)
{
	struct rspamd_http_server_session *session = conn->ud;

	rspamd_fprintf (stderr, "http error occurred: %s\n", err->message);
	rspamd_http_connection_unref (conn);
	close (session->fd);
	g_slice_free1 (sizeof (*session), session);
}

static int
rspamd_server_finish (struct rspamd_http_connection *conn,
		struct rspamd_http_message *msg)
{
	struct rspamd_http_server_session *session = conn->ud;
	struct rspamd_http_message *reply;
	gulong size;
	const gchar *url_str;
	guint url_len;
	rspamd_fstring_t *body;

	if (!session->reply) {
		session->reply = TRUE;
		reply = rspamd_http_new_message (HTTP_RESPONSE);
		url_str = msg->url->str;
		url_len = msg->url->len;

		if (url_str[0] == '/') {
			url_str ++;
			url_len --;
		}

		if (rspamd_strtoul (url_str, url_len, &size)) {
			session->req_size = size;

			reply->code = 200;
			reply->status = rspamd_fstring_new_init ("OK", 2);
			body = rspamd_fstring_sized_new (size);
			body->len = size;
			memset (body->str, 0, size);
			rspamd_http_message_set_body_from_fstring_steal (msg, body);

		}
		else {
			reply->code = 404;
			reply->status = rspamd_fstring_new_init ("Not found", 9);
		}

		rspamd_http_connection_reset (conn);
		rspamd_http_connection_write_message (conn, reply, NULL,
				"application/octet-stream", session, session->fd,
				&io_tv, session->ev_base);
	}
	else {
		/* Destroy session */
		rspamd_http_connection_unref (conn);
		close (session->fd);
		g_slice_free1 (sizeof (*session), session);
	}

	return 0;
}

static void
rspamd_server_accept (gint fd, short what, void *arg)
{
	struct ev_loop *ev_base = arg;
	struct rspamd_http_server_session *session;
	rspamd_inet_addr_t *addr;
	gint nfd;

	do {
		if ((nfd =
					 rspamd_accept_from_socket (fd, &addr, NULL)) == -1) {
			rspamd_fprintf (stderr, "accept failed: %s", strerror (errno));
			return;
		}
		/* Check for EAGAIN */
		if (nfd == 0) {
			rspamd_inet_address_free (addr);
			return;
		}

		rspamd_inet_address_free (addr);
		session = g_slice_alloc (sizeof (*session));
		session->conn = rspamd_http_connection_new (NULL,
				rspamd_server_error,
				rspamd_server_finish,
				0,
				RSPAMD_HTTP_SERVER,
				c,
				NULL);
		rspamd_http_connection_set_key (session->conn, server_key);
		rspamd_http_connection_read_message (session->conn,
				session,
				nfd,
				&io_tv,
				ev_base);
		session->reply = FALSE;
		session->fd = nfd;
		session->ev_base = ev_base;
	} while (nfd > 0);
}

static void
rspamd_http_term_handler (gint fd, short what, void *arg)
{
	struct ev_loop *ev_base = arg;
	struct timeval tv = {0, 0};

	event_base_loopexit (ev_base, &tv);
}

static void
rspamd_http_server_func (gint fd, rspamd_inet_addr_t *addr)
{
	struct ev_loop *ev_base = event_init ();
	struct event accept_ev, term_ev;

	event_set (&accept_ev, fd, EV_READ | EV_PERSIST, rspamd_server_accept, ev_base);
	event_base_set (ev_base, &accept_ev);
	event_add (&accept_ev, NULL);

	evsignal_set (&term_ev, SIGTERM, rspamd_http_term_handler, ev_base);
	event_base_set (ev_base, &term_ev);
	event_add (&term_ev, NULL);

	event_base_loop (ev_base, 0);
}

static void
rspamd_http_start_servers (pid_t *sfd, rspamd_inet_addr_t *addr)
{
	guint i;
	gint fd;

	fd = rspamd_inet_address_listen (addr, SOCK_STREAM, TRUE);
	g_assert (fd != -1);

	for (i = 0; i < nworkers; i++) {
		sfd[i] = fork ();
		g_assert (sfd[i] != -1);

		if (sfd[i] == 0) {
			rspamd_http_server_func (fd, addr);
			exit (EXIT_SUCCESS);
		}
	}

	close (fd);
}

static void
rspamd_http_stop_servers (pid_t *sfd)
{
	guint i;
	gint res;

	for (i = 0; i < nworkers; i++) {
		kill (sfd[i], SIGTERM);
		wait (&res);
	}
}

static void
rspamd_http_server_term (int fd, short what, void *arg)
{
	pid_t *sfd = arg;

	rspamd_http_stop_servers (sfd);
	event_loopexit (NULL);
}

int
main (int argc, gchar **argv)
{
	GOptionContext *context;
	GError *error = NULL;
	struct ev_loop *ev_base;
	GString *b32_key;
	pid_t *sfd;
	rspamd_inet_addr_t *addr;
	struct event term_ev, int_ev;
	struct in_addr ina = {INADDR_ANY};

	rspamd_init_libs ();

	context = g_option_context_new (
			"rspamd-http-server - test server for benchmarks");
	g_option_context_set_summary (context,
			"Summary:\n  Rspamd test HTTP server "
					RVERSION
					"\n  Release id: "
					RID);
	g_option_context_add_main_entries (context, entries, NULL);

	if (!g_option_context_parse (context, &argc, &argv, &error)) {
		rspamd_fprintf (stderr, "option parsing failed: %s\n", error->message);
		g_error_free (error);
		exit (EXIT_FAILURE);
	}

	maps = g_hash_table_new (g_int_hash, g_int_equal);

	if (key == NULL) {
		server_key = rspamd_keypair_new (RSPAMD_KEYPAIR_KEX,
				openssl_mode ? RSPAMD_CRYPTOBOX_MODE_NIST : RSPAMD_CRYPTOBOX_MODE_25519);
		b32_key = rspamd_keypair_print (server_key,
				RSPAMD_KEYPAIR_PUBKEY | RSPAMD_KEYPAIR_BASE32);
		rspamd_printf ("key: %v\n", b32_key);
	}
	else {
		/* TODO: add key loading */
	}

	if (cache_size > 0) {
		c = rspamd_keypair_cache_new (cache_size);
	}

	sfd = g_alloca (sizeof (*sfd) * nworkers);
	addr = rspamd_inet_address_new (AF_INET, &ina);
	rspamd_inet_address_set_port (addr, port);
	rspamd_http_start_servers (sfd, addr);

	/* Just wait for workers */
	ev_base = event_init ();

	event_set (&term_ev, SIGTERM, EV_SIGNAL, rspamd_http_server_term, sfd);
	event_base_set (ev_base, &term_ev);
	event_add (&term_ev, NULL);
	event_set (&int_ev, SIGINT, EV_SIGNAL, rspamd_http_server_term, sfd);
	event_base_set (ev_base, &int_ev);
	event_add (&int_ev, NULL);

	event_base_loop (ev_base, 0);

	return 0;
}
