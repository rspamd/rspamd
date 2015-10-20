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
static gchar *host = "127.0.0.1";
static gchar *server_key = NULL;
static guint cache_size = 10;
static guint nworkers = 1;
static gboolean openssl_mode = FALSE;
static struct rspamd_keypair_cache *c;
static gpointer client_key;
static gpointer peer_key;
static struct timeval io_tv = {
		.tv_sec = 20,
		.tv_usec = 0
};
double diff, total_diff = 0.0, *latency, mean, std;
static guint file_size = 500;
static guint pconns = 100;
static guint ntests = 3000;
static rspamd_inet_addr_t *addr;
static rspamd_mutex_t *mtx_event;

static GOptionEntry entries[] = {
		{"port",    'p', 0, G_OPTION_ARG_INT,  &port,
				"Port number (default: 43000)",            NULL},
		{"cache", 'c', 0, G_OPTION_ARG_INT,  &cache_size,
				"Keys cache size (default: 10)",           NULL},
		{"workers", 'n', 0, G_OPTION_ARG_INT,  &nworkers,
				"Number of workers to start (default: 1)", NULL},
		{"size", 's', 0, G_OPTION_ARG_INT, &file_size,
				"Size of payload to transfer (default: 500)", NULL},
		{"conns", 'C', 0, G_OPTION_ARG_INT, &pconns,
				"Number of parallel connections (default: 100)", NULL},
		{"tests", 't', 0, G_OPTION_ARG_INT, &pconns,
				"Number of tests to execute (default: 3000)", NULL},
		{"openssl", 'o', 0, G_OPTION_ARG_NONE, &openssl_mode,
				"Use openssl crypto",                      NULL},
		{"host", 'h', 0, G_OPTION_ARG_STRING, &host,
				"Connect to the specified host (default: localhost)", NULL},
		{"key", 'k', 0, G_OPTION_ARG_STRING, &server_key,
				"Use the specified key (base32 encoded)", NULL},
		{NULL,      0,   0, G_OPTION_ARG_NONE, NULL, NULL, NULL}
};

static gint
rspamd_client_body (struct rspamd_http_connection *conn,
		struct rspamd_http_message *msg,
		const gchar *chunk, gsize len)
{
	g_assert (chunk[0] == '\0');

	return 0;
}

struct client_cbdata {
	double *lat;
	gdouble ts;
};

static void
rspamd_client_err (struct rspamd_http_connection *conn, GError *err)
{
	msg_info ("abnormally closing connection from: error: %s",
			err->message);

	g_assert (0);
	close (conn->fd);
	rspamd_http_connection_unref (conn);
}

static gint
rspamd_client_finish (struct rspamd_http_connection *conn,
		struct rspamd_http_message *msg)
{
	struct client_cbdata *cb = conn->ud;

	*(cb->lat) = rspamd_get_ticks () - cb->ts;
	close (conn->fd);
	rspamd_http_connection_unref (conn);
	g_free (cb);

	return 0;
}

static void
rspamd_http_client_func (struct event_base *ev_base, double *latency)
{
	struct rspamd_http_message *msg;
	struct rspamd_http_connection *conn;
	gchar urlbuf[PATH_MAX];
	struct client_cbdata *cb;
	gint fd;

	g_assert (
			(fd = rspamd_inet_address_connect (addr, SOCK_STREAM, TRUE)) != -1);
	conn = rspamd_http_connection_new (rspamd_client_body, rspamd_client_err,
			rspamd_client_finish, RSPAMD_HTTP_CLIENT_SIMPLE,
			RSPAMD_HTTP_CLIENT, c);
	rspamd_snprintf (urlbuf, sizeof (urlbuf), "http://%s/%d", host, file_size);
	msg = rspamd_http_message_from_url (urlbuf);

	g_assert (conn != NULL && msg != NULL);

	if (peer_key != NULL) {
		g_assert (client_key != NULL);
		rspamd_http_connection_set_key (conn, client_key);
		msg->peer_key = rspamd_http_connection_key_ref (peer_key);
	}

	cb = g_malloc (sizeof (*cb));
	cb->ts = rspamd_get_ticks ();
	cb->lat = latency;
	rspamd_http_connection_write_message (conn, msg, NULL, NULL, cb,
			fd, &io_tv, ev_base);
}

static void *
rspamd_bench_thread_func (gpointer d)
{
	guint i, j;
	struct event_base *ev_base;
	gint *nt = d;

	rspamd_mutex_lock (mtx_event);
	ev_base = event_init ();
	rspamd_mutex_unlock (mtx_event);

	for (i = 0; i < ntests; i++) {
		for (j = 0; j < pconns; j++) {
			rspamd_http_client_func (ev_base, &latency[(*nt) * pconns * ntests
					+ i * pconns + j]);
		}
		event_base_loop (ev_base, 0);
	}

	return NULL;
}

static int
cmpd (const void *p1, const void *p2)
{
	const double *d1 = p1, *d2 = p2;

	return (*d1) - (*d2);
}

double
rspamd_http_calculate_mean (double *lats, double *std)
{
	guint i;
	gdouble mean = 0., dev = 0.;

	qsort (lats, ntests * pconns, sizeof (double), cmpd);

	for (i = 0; i < ntests * pconns; i++) {
		mean += lats[i];
	}

	mean /= ntests * pconns;

	for (i = 0; i < ntests * pconns; i++) {
		dev += (lats[i] - mean) * (lats[i] - mean);
	}

	dev /= ntests * pconns;

	*std = sqrt (dev);
	return mean;
}

int
main (int argc, char **argv)
{
	GOptionContext *context;
	GError *error = NULL;
	GThread **workers;
	guint i;
	gdouble ts1, ts2;

	rspamd_init_libs ();

	context = g_option_context_new (
			"rspamd-http-bench - test server for benchmarks");
	g_option_context_set_summary (context,
			"Summary:\n  Rspamd test HTTP benchmark "
					RVERSION
					"\n  Release id: "
					RID);
	g_option_context_add_main_entries (context, entries, NULL);

	if (!g_option_context_parse (context, &argc, &argv, &error)) {
		rspamd_fprintf (stderr, "option parsing failed: %s\n", error->message);
		g_error_free (error);
		exit (1);
	}

	if (openssl_mode) {
		g_assert (rspamd_cryptobox_openssl_mode (TRUE));
	}

	if (server_key) {
		peer_key = rspamd_http_connection_make_peer_key (server_key);
		g_assert (peer_key != NULL);
		client_key = rspamd_http_connection_gen_key ();

		if (cache_size > 0) {
			c = rspamd_keypair_cache_new (cache_size);
		}
	}

	mtx_event = rspamd_mutex_new ();
	rspamd_parse_inet_address (&addr, host, 0);
	g_assert (addr != NULL);
	rspamd_inet_address_set_port (addr, port);

	latency = g_malloc0 (nworkers * pconns * ntests * sizeof (gdouble));
	workers = g_malloc (sizeof (*workers) * nworkers);

	gperf_profiler_init (NULL, "http-bench");

	rspamd_mutex_lock (mtx_event);
	for (i = 0; i < nworkers; i ++) {
		gint *nt = g_malloc (sizeof (gint));
		*nt = i;
		workers[i] = rspamd_create_thread ("bench-worker",
				rspamd_bench_thread_func,
				nt,
				NULL);
	}
	rspamd_mutex_unlock (mtx_event);

	ts1 = rspamd_get_ticks ();

	for (i = 0; i < nworkers; i++) {
		g_thread_join (workers[i]);
	}

	ts2 = rspamd_get_ticks ();

	gperf_profiler_stop ();

	total_diff = ts2 - ts1;

	rspamd_printf ("Made %d connections of size %d in %.6fs, %.6f cps, %.6f MB/sec\n",
			nworkers * ntests * pconns,
			file_size,
			total_diff,
			nworkers * ntests * pconns / total_diff,
			nworkers * ntests * pconns * file_size / total_diff / (1024.0 * 1024.0));
	mean = rspamd_http_calculate_mean (latency, &std);
	rspamd_printf ("Latency: %.6f ms mean, %.6f dev\n",
			mean * 1000.0, std * 1000.0);

	return 0;
}
