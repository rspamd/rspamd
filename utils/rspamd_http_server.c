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
#include "rspamd.h"
#include "util.h"
#include "http.h"
#include "ottery.h"
#include "cryptobox.h"
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
static struct rspamd_keypair_cache *c;
static gpointer server_key;
static struct timeval io_tv = {
		.tv_sec = 5,
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
		{NULL,            0,   0, G_OPTION_ARG_NONE, NULL, NULL, NULL}
};

struct rspamd_http_server_session {
	struct rspamd_http_connection *conn;
	struct event_base *ev_base;
	guint req_size;
	gboolean reply;
	gint fd;
};

static void
rspamd_server_error (struct rspamd_http_connection *conn,
		GError *err)
{
	msg_err ("http error occurred: %s", err->message);
	g_assert (0);
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
			reply->body = rspamd_fstring_sized_new (size);
			memset (reply->body->str, 0, size);
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
	struct event_base *ev_base = arg;
	struct rspamd_http_server_session *session;
	rspamd_inet_addr_t *addr;
	gint nfd;

	if ((nfd =
				 rspamd_accept_from_socket (fd, &addr)) == -1) {
		msg_warn ("accept failed: %s", strerror (errno));
		return;
	}
	/* Check for EAGAIN */
	if (nfd == 0) {
		return;
	}

	rspamd_inet_address_destroy (addr);
	session = g_slice_alloc (sizeof (*session));
	session->conn = rspamd_http_connection_new (NULL, rspamd_server_error,
			rspamd_server_finish, 0, RSPAMD_HTTP_SERVER, c);
	rspamd_http_connection_set_key (session->conn, server_key);
	rspamd_http_connection_read_message (session->conn, session, nfd, &io_tv,
			ev_base);
	session->reply = FALSE;
	session->fd = nfd;
	session->ev_base = ev_base;
}

static void
rspamd_http_term_handler (gint fd, short what, void *arg)
{
	struct event_base *ev_base = arg;
	struct timeval tv = {0, 0};

	event_base_loopexit (ev_base, &tv);
}

static void
rspamd_http_server_func (gint fd, rspamd_inet_addr_t *addr)
{
	struct event_base *ev_base = event_init ();
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

	g_assert (
			(fd = rspamd_inet_address_listen (addr, SOCK_STREAM, TRUE)) != -1);

	for (i = 0; i < nworkers; i++) {
		sfd[i] = fork ();
		g_assert (sfd[i] != -1);

		if (sfd[i] == 0) {
			gperf_profiler_init (NULL, "http-server");
			rspamd_http_server_func (fd, addr);
			gperf_profiler_stop ();
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
}

int
main (int argc, gchar **argv)
{
	GOptionContext *context;
	GError *error = NULL;
	struct event_base *ev_base;
	GString *b32_key;
	pid_t *sfd;
	rspamd_inet_addr_t *addr;
	struct event term_ev, int_ev;
	struct in_addr ina = {INADDR_ANY};

	rspamd_init_libs ();

	context = g_option_context_new (
			"rspamd_http_server - test server for benchmarks");
	g_option_context_set_summary (context,
			"Summary:\n  Rspamd test HTTP server "
					RVERSION
					"\n  Release id: "
					RID);
	g_option_context_add_main_entries (context, entries, NULL);

	if (!g_option_context_parse (context, &argc, &argv, &error)) {
		rspamd_fprintf (stderr, "option parsing failed: %s\n", error->message);
		g_error_free (error);
		exit (1);
	}

	maps = g_hash_table_new (g_int_hash, g_int_equal);

	if (openssl_mode) {
		g_assert (rspamd_cryptobox_openssl_mode (TRUE));
	}

	server_key = rspamd_http_connection_gen_key ();
	b32_key = rspamd_http_connection_print_key (server_key,
			RSPAMD_KEYPAIR_PUBKEY | RSPAMD_KEYPAIR_BASE32);
	rspamd_printf ("key: %v\n", b32_key);

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
