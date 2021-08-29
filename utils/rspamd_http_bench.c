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
#include "libutil/http.h"
#include "libutil/http_private.h"
#include "ottery.h"
#include "cryptobox.h"
#include "unix-std.h"
#include <math.h>
#include <netinet/tcp.h>

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

static guint port = 43000;
static gchar *host = "127.0.0.1";
static gchar *server_key = NULL;
static guint cache_size = 10;
static guint nworkers = 1;
static gboolean openssl_mode = FALSE;
static guint file_size = 500;
static guint pconns = 100;
static gdouble test_time = 10.0;
static gchar *latencies_file = NULL;
static gboolean csv_output = FALSE;

/* Dynamic vars */
static rspamd_inet_addr_t *addr;
static guint32 workers_left = 0;
static guint32 *conns_done = NULL;
static const guint store_latencies = 1000;
static guint32 conns_pending = 0;

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
		{"time", 't', 0, G_OPTION_ARG_DOUBLE, &test_time,
				"Time to run tests (default: 10.0 sec)", NULL},
		{"openssl", 'o', 0, G_OPTION_ARG_NONE, &openssl_mode,
				"Use openssl crypto",                      NULL},
		{"host", 'h', 0, G_OPTION_ARG_STRING, &host,
				"Connect to the specified host (default: localhost)", NULL},
		{"key", 'k', 0, G_OPTION_ARG_STRING, &server_key,
				"Use the specified key (base32 encoded)", NULL},
		{"latency", 'l', 0, G_OPTION_ARG_FILENAME, &latencies_file,
				"Write latencies to the specified file", NULL},
		{"csv", 0, 0, G_OPTION_ARG_NONE, &csv_output,
				"Output CSV", NULL},
		{NULL,      0,   0, G_OPTION_ARG_NONE, NULL, NULL, NULL}
};

struct lat_elt {
	gdouble lat;
	guchar checked;
};

static struct lat_elt *latencies;

static gint
rspamd_client_body (struct rspamd_http_connection *conn,
		struct rspamd_http_message *msg,
		const gchar *chunk, gsize len)
{
	g_assert (chunk[0] == '\0');

	return 0;
}

struct client_cbdata {
	struct lat_elt *lat;
	guint32 *wconns;
	gdouble ts;
	struct ev_loop *ev_base;
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

	cb->lat->lat = rspamd_get_ticks () - cb->ts;
	cb->lat->checked = TRUE;
	(*cb->wconns) ++;
	conns_pending --;
	close (conn->fd);
	rspamd_http_connection_unref (conn);
	g_free (cb);

	if (conns_pending == 0) {
		event_base_loopexit (cb->ev_base, NULL);
	}

	return 0;
}

static void
rspamd_http_client_func (struct ev_loop *ev_base, struct lat_elt *latency,
		guint32 *wconns,
		struct rspamd_cryptobox_pubkey *peer_key,
		struct rspamd_cryptobox_keypair* client_key,
		struct rspamd_keypair_cache *c)
{
	struct rspamd_http_message *msg;
	struct rspamd_http_connection *conn;
	gchar urlbuf[PATH_MAX];
	struct client_cbdata *cb;
	gint fd, flags;

	fd = rspamd_inet_address_connect (addr, SOCK_STREAM, TRUE);
	g_assert (fd != -1);
	flags = 1;
	(void)setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, &flags, sizeof (flags));
	conn = rspamd_http_connection_new (rspamd_client_body,
			rspamd_client_err,
			rspamd_client_finish,
			RSPAMD_HTTP_CLIENT_SIMPLE,
			RSPAMD_HTTP_CLIENT,
			c,
			NULL);
	rspamd_snprintf (urlbuf, sizeof (urlbuf), "http://%s/%d", host, file_size);
	msg = rspamd_http_message_from_url (urlbuf);

	g_assert (conn != NULL && msg != NULL);

	if (peer_key != NULL) {
		g_assert (client_key != NULL);
		rspamd_http_connection_set_key (conn, client_key);
		msg->peer_key = rspamd_pubkey_ref (peer_key);
	}

	cb = g_malloc (sizeof (*cb));
	cb->ts = rspamd_get_ticks ();
	cb->lat = latency;
	cb->ev_base = ev_base;
	cb->wconns = wconns;
	latency->checked = FALSE;
	rspamd_http_connection_write_message (conn, msg, NULL, NULL, cb,
			fd, NULL, ev_base);
}

static void
rspamd_worker_func (struct lat_elt *plat, guint32 *wconns)
{
	guint i, j;
	struct ev_loop *ev_base;
	struct itimerval itv;
	struct rspamd_keypair_cache *c = NULL;
	struct rspamd_cryptobox_keypair *client_key = NULL;
	struct rspamd_cryptobox_pubkey *peer_key = NULL;

	if (server_key) {
		peer_key = rspamd_pubkey_from_base32 (server_key, 0, RSPAMD_KEYPAIR_KEX,
				openssl_mode ? RSPAMD_CRYPTOBOX_MODE_NIST : RSPAMD_CRYPTOBOX_MODE_25519);
		g_assert (peer_key != NULL);
		client_key = rspamd_keypair_new (RSPAMD_KEYPAIR_KEX,
				openssl_mode ? RSPAMD_CRYPTOBOX_MODE_NIST : RSPAMD_CRYPTOBOX_MODE_25519);

		if (cache_size > 0) {
			c = rspamd_keypair_cache_new (cache_size);
		}
	}

	memset (&itv, 0, sizeof (itv));
	double_to_tv (test_time, &itv.it_value);

	ev_base = event_init ();
	g_assert (setitimer (ITIMER_REAL, &itv, NULL) != -1);

	for (i = 0; ; i = (i + 1) % store_latencies) {
		for (j = 0; j < pconns; j++) {
			rspamd_http_client_func (ev_base, &plat[i * pconns + j],
					wconns, peer_key, client_key, c);
		}

		conns_pending = pconns;

		event_base_loop (ev_base, 0);
	}
}

static int
cmpd (const void *p1, const void *p2)
{
	const struct lat_elt *d1 = p1, *d2 = p2;

	return (d1->lat) - (d2->lat);
}

double
rspamd_http_calculate_mean (struct lat_elt *lats, double *std)
{
	guint i, cnt, checked = 0;
	gdouble mean = 0., dev = 0.;

	cnt = store_latencies * pconns;
	qsort (lats, cnt, sizeof (*lats), cmpd);

	for (i = 0; i < cnt; i++) {
		if (lats[i].checked) {
			mean += lats[i].lat;
			checked ++;
		}
	}

	g_assert (checked > 0);
	mean /= checked;

	for (i = 0; i < cnt; i++) {
		if (lats[i].checked) {
			dev += pow ((lats[i].lat - mean), 2);
		}
	}

	dev /= checked;

	*std = sqrt (dev);
	return mean;
}

static void
rspamd_http_start_workers (pid_t *sfd)
{
	guint i;
	for (i = 0; i < nworkers; i++) {
		sfd[i] = fork ();
		g_assert (sfd[i] != -1);

		if (sfd[i] == 0) {
			gperf_profiler_init (NULL, "http-bench");
			rspamd_worker_func (&latencies[i * pconns * store_latencies],
					&conns_done[i]);
			gperf_profiler_stop ();
			exit (EXIT_SUCCESS);
		}

		workers_left ++;
	}
}

static void
rspamd_http_stop_workers (pid_t *sfd)
{
	guint i;
	gint res;

	for (i = 0; i < nworkers; i++) {
		kill (sfd[i], SIGTERM);
		wait (&res);
	}
}

static void
rspamd_http_bench_term (int fd, short what, void *arg)
{
	pid_t *sfd = arg;

	rspamd_http_stop_workers (sfd);
	event_loopexit (NULL);
}

static void
rspamd_http_bench_cld (int fd, short what, void *arg)
{
	gint res;

	while (waitpid (-1, &res, WNOHANG) > 0) {
		if (--workers_left == 0) {
			event_loopexit (NULL);
		}
	}
}


int
main (int argc, char **argv)
{
	GOptionContext *context;
	GError *error = NULL;
	pid_t *sfd;
	struct ev_loop *ev_base;
	rspamd_mempool_t *pool = rspamd_mempool_new (8192, "http-bench");
	struct event term_ev, int_ev, cld_ev;
	guint64 total_done;
	FILE *lat_file;
	gdouble mean, std;
	guint i;

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
		exit (EXIT_FAILURE);
	}

	rspamd_parse_inet_address (&addr, host, 0);
	g_assert (addr != NULL);
	rspamd_inet_address_set_port (addr, port);

	latencies = rspamd_mempool_alloc_shared (pool,
			nworkers * pconns * store_latencies * sizeof (*latencies));
	sfd  = g_malloc (sizeof (*sfd) * nworkers);
	conns_done = rspamd_mempool_alloc_shared (pool, sizeof (guint32) * nworkers);
	memset (conns_done, 0, sizeof (guint32) * nworkers);

	rspamd_http_start_workers (sfd);

	ev_base = event_init ();

	event_set (&term_ev, SIGTERM, EV_SIGNAL, rspamd_http_bench_term, sfd);
	event_base_set (ev_base, &term_ev);
	event_add (&term_ev, NULL);
	event_set (&int_ev, SIGINT, EV_SIGNAL, rspamd_http_bench_term, sfd);
	event_base_set (ev_base, &int_ev);
	event_add (&int_ev, NULL);
	event_set (&cld_ev, SIGCHLD, EV_SIGNAL|EV_PERSIST,
			rspamd_http_bench_cld, NULL);
	event_base_set (ev_base, &cld_ev);
	event_add (&cld_ev, NULL);

	event_base_loop (ev_base, 0);

	total_done = 0;
	for (i = 0; i < nworkers; i ++) {
		total_done += conns_done[i];
	}

	mean = rspamd_http_calculate_mean (latencies, &std);

	if (!csv_output) {
		rspamd_printf (
				"Made %L connections of size %d in %.6fs, %.6f cps, %.6f MB/sec\n",
				total_done,
				file_size,
				test_time,
				total_done / test_time,
				total_done * file_size / test_time / (1024.0 * 1024.0));
		rspamd_printf ("Latency: %.6f ms mean, %.6f dev\n",
				mean * 1000.0, std * 1000.0);
	}
	else {
		/* size,connections,time,mean,stddev,conns,workers */
		rspamd_printf ("%ud,%L,%.1f,%.6f,%.6f,%ud,%ud\n",
				file_size,
				total_done,
				test_time,
				mean*1000.0,
				std*1000.0,
				pconns,
				nworkers);
	}

	if (latencies_file) {
		lat_file = fopen (latencies_file, "w");

		if (lat_file) {
			for (i = 0; i < store_latencies * pconns; i ++) {
				if (latencies[i].checked) {
					rspamd_fprintf (lat_file, "%.6f\n", latencies[i].lat);
				}
			}

			fclose (lat_file);
		}
	}

	rspamd_mempool_delete (pool);

	return 0;
}
