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
#include "libutil/http_connection.h"
#include "libutil/http_router.h"
#include "libutil/http_private.h"
#include "tests.h"
#include "ottery.h"
#include "cryptobox.h"
#include "keypair.h"
#include "unix-std.h"
#include <math.h>

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

static guint file_size = 500;
static guint pconns = 100;
static guint ntests = 3000;
static guint nservers = 1;

static void
rspamd_server_error (struct rspamd_http_connection_entry *conn_ent,
	GError *err)
{
	msg_err ("http error occurred: %s", err->message);
	g_assert (0);
}

static void
rspamd_server_finish (struct rspamd_http_connection_entry *conn_ent)
{
	/* Do nothing here */
}

static void
rspamd_server_accept (gint fd, short what, void *arg)
{
	struct rspamd_http_connection_router *rt = arg;
	rspamd_inet_addr_t *addr = NULL;
	gint nfd;

	if ((nfd =
			rspamd_accept_from_socket (fd, &addr, NULL)) == -1) {
		msg_warn ("accept failed: %s", strerror (errno));
		return;
	}
	/* Check for EAGAIN */
	if (nfd == 0) {
		rspamd_inet_address_free (addr);
		return;
	}

	rspamd_inet_address_free (addr);
	rspamd_http_router_handle_socket (rt, nfd, NULL);
}

static void
rspamd_http_term_handler (gint fd, short what, void *arg)
{
	struct ev_loop *ev_base = arg;
	struct timeval tv = {0, 0};

	event_base_loopexit (ev_base, &tv);
}

static void
rspamd_http_server_func (gint fd, const gchar *path, rspamd_inet_addr_t *addr,
		struct rspamd_cryptobox_keypair *kp, struct rspamd_keypair_cache *c)
{
	struct rspamd_http_connection_router *rt;
	struct ev_loop *ev_base = event_init ();
	struct event accept_ev, term_ev;

	rt = rspamd_http_router_new (rspamd_server_error, rspamd_server_finish,
			NULL, ev_base, path, c);
	g_assert (rt != NULL);

	rspamd_http_router_set_key (rt, kp);
	event_set (&accept_ev, fd, EV_READ | EV_PERSIST, rspamd_server_accept, rt);
	event_base_set (ev_base, &accept_ev);
	event_add (&accept_ev, NULL);

	evsignal_set (&term_ev, SIGTERM, rspamd_http_term_handler, ev_base);
	event_base_set (ev_base, &term_ev);
	event_add (&term_ev, NULL);

	event_base_loop (ev_base, 0);
}

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

	*(cb->lat) = rspamd_get_ticks (FALSE) * 1000. - cb->ts;
	close (conn->fd);
	rspamd_http_connection_unref (conn);
	g_free (cb);

	return 0;
}

static void
rspamd_http_client_func (const gchar *path, rspamd_inet_addr_t *addr,
		struct rspamd_cryptobox_keypair *kp,
		struct rspamd_cryptobox_pubkey *peer_kp,
		struct rspamd_keypair_cache *c,
		struct ev_loop *ev_base, double *latency)
{
	struct rspamd_http_message *msg;
	struct rspamd_http_connection *conn;
	gchar urlbuf[PATH_MAX];
	struct client_cbdata *cb;
	gint fd;

	g_assert ((fd = rspamd_inet_address_connect (addr, SOCK_STREAM, TRUE)) != -1);
	conn = rspamd_http_connection_new (rspamd_client_body,
			rspamd_client_err,
			rspamd_client_finish,
			RSPAMD_HTTP_CLIENT_SIMPLE,
			RSPAMD_HTTP_CLIENT,
			c,
			NULL);
	rspamd_snprintf (urlbuf, sizeof (urlbuf), "http://127.0.0.1/%s", path);
	msg = rspamd_http_message_from_url (urlbuf);

	g_assert (conn != NULL && msg != NULL);

	if (kp != NULL) {
		g_assert (peer_kp != NULL);
		rspamd_http_connection_set_key (conn, kp);
		msg->peer_key = rspamd_pubkey_ref (peer_kp);
	}

	cb = g_malloc (sizeof (*cb));
	cb->ts = rspamd_get_ticks (FALSE) * 1000.;
	cb->lat = latency;
	rspamd_http_connection_write_message (conn, msg, NULL, NULL, cb,
			fd, NULL, ev_base);
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

	for (i = 0; i < ntests * pconns; i ++) {
		mean += lats[i];
	}

	mean /= ntests * pconns;

	for (i = 0; i < ntests * pconns; i ++) {
		dev += (lats[i] - mean) * (lats[i] - mean);
	}

	dev /= ntests * pconns;

	*std = sqrt (dev);
	return mean;
}

static void
rspamd_http_start_servers (pid_t *sfd, rspamd_inet_addr_t *addr,
		struct rspamd_cryptobox_keypair *serv_key,
		struct rspamd_keypair_cache *c)
{
	guint i;
	gint fd;

	g_assert ((fd = rspamd_inet_address_listen (addr, SOCK_STREAM, TRUE)) != -1);

	for (i = 0; i < nservers; i ++) {
		sfd[i] = fork ();
		g_assert (sfd[i] != -1);

		if (sfd[i] == 0) {
			rspamd_http_server_func (fd, "/tmp/", addr, serv_key, c);
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

	for (i = 0; i < nservers; i++) {
		kill (sfd[i], SIGTERM);
		wait (&res);
	}
}

void
rspamd_http_test_func (void)
{
	struct ev_loop *ev_base = event_init ();
	rspamd_mempool_t *pool = rspamd_mempool_new (rspamd_mempool_suggest_size (), NULL);
	struct rspamd_cryptobox_keypair *serv_key, *client_key;
	struct rspamd_cryptobox_pubkey *peer_key;
	struct rspamd_keypair_cache *c;
	rspamd_mempool_mutex_t *mtx;
	rspamd_inet_addr_t *addr;
	gdouble ts1, ts2;
	gchar filepath[PATH_MAX], *buf;
	gchar *env;
	gint fd;
	guint i, j;
	pid_t *sfd;
	GString *b32_key;
	double diff, total_diff = 0.0, *latency, mean, std;

	/* Read environment */
	if ((env = getenv ("RSPAMD_HTTP_CONNS")) != NULL) {
		pconns = strtoul (env, NULL, 10);
	}
	else {
		return;
	}

	if ((env = getenv ("RSPAMD_HTTP_TESTS")) != NULL) {
		ntests = strtoul (env, NULL, 10);
	}
	if ((env = getenv ("RSPAMD_HTTP_SIZE")) != NULL) {
		file_size = strtoul (env, NULL, 10);
	}
	if ((env = getenv ("RSPAMD_HTTP_SERVERS")) != NULL) {
		nservers = strtoul (env, NULL, 10);
	}

	rspamd_cryptobox_init ();
	rspamd_snprintf (filepath, sizeof (filepath), "/tmp/http-test-XXXXXX");
	g_assert ((fd = mkstemp (filepath)) != -1);

	sfd = g_alloca (sizeof (*sfd) * nservers);
	latency = g_malloc0 (pconns * ntests * sizeof (gdouble));

	buf = g_malloc (file_size);
	memset (buf, 0, file_size);
	g_assert (write (fd, buf, file_size) == file_size);
	g_free (buf);

	mtx = rspamd_mempool_get_mutex (pool);

	rspamd_parse_inet_address (&addr, "127.0.0.1", 0);
	rspamd_inet_address_set_port (addr, 43898);
	serv_key = rspamd_keypair_new (RSPAMD_KEYPAIR_KEX,
			RSPAMD_CRYPTOBOX_MODE_25519);
	client_key = rspamd_keypair_new (RSPAMD_KEYPAIR_KEX,
			RSPAMD_CRYPTOBOX_MODE_25519);
	c = rspamd_keypair_cache_new (16);

	rspamd_http_start_servers (sfd, addr, serv_key, NULL);
	usleep (100000);

	/* Do client stuff */
	gperf_profiler_init (NULL, "plain-http-client");
	for (i = 0; i < ntests; i ++) {
		for (j = 0; j < pconns; j ++) {
			rspamd_http_client_func (filepath + sizeof ("/tmp") - 1, addr,
					NULL, NULL, c, ev_base, &latency[i * pconns + j]);
		}
		ts1 = rspamd_get_ticks (FALSE);
		event_base_loop (ev_base, 0);
		ts2 = rspamd_get_ticks (FALSE);
		diff = (ts2 - ts1) * 1000.0;
		total_diff += diff;
	}
	gperf_profiler_stop ();

	msg_info ("Made %d connections of size %d in %.6f ms, %.6f cps",
			ntests * pconns,
			file_size,
			total_diff, ntests * pconns / total_diff * 1000.);
	mean = rspamd_http_calculate_mean (latency, &std);
	msg_info ("Latency: %.6f ms mean, %.6f dev",
			mean, std);

	rspamd_http_stop_servers (sfd);

	rspamd_http_start_servers (sfd, addr, serv_key, c);

	//rspamd_mempool_lock_mutex (mtx);
	usleep (100000);
	b32_key = rspamd_keypair_print (serv_key,
			RSPAMD_KEYPAIR_PUBKEY|RSPAMD_KEYPAIR_BASE32);
	g_assert (b32_key != NULL);
	peer_key = rspamd_pubkey_from_base32 (b32_key->str, b32_key->len,
			RSPAMD_KEYPAIR_KEX, RSPAMD_CRYPTOBOX_MODE_25519);
	g_assert (peer_key != NULL);
	total_diff = 0.0;

	gperf_profiler_init (NULL, "cached-http-client");
	for (i = 0; i < ntests; i ++) {
		for (j = 0; j < pconns; j ++) {
			rspamd_http_client_func (filepath + sizeof ("/tmp") - 1, addr,
					client_key, peer_key, c, ev_base, &latency[i * pconns + j]);
		}
		ts1 = rspamd_get_ticks (FALSE);
		event_base_loop (ev_base, 0);
		ts2 = rspamd_get_ticks (FALSE);
		diff = (ts2 - ts1) * 1000.0;
		total_diff += diff;
	}
	gperf_profiler_stop ();

	msg_info ("Made %d encrypted connections of size %d in %.6f ms, %.6f cps",
			ntests * pconns,
			file_size,
			total_diff, ntests * pconns / total_diff * 1000.);
	mean = rspamd_http_calculate_mean (latency, &std);
	msg_info ("Latency: %.6f ms mean, %.6f dev",
			mean, std);

	/* Restart server */
	rspamd_http_stop_servers (sfd);
	/* No keypairs cache */
	rspamd_http_start_servers (sfd, addr, serv_key, NULL);

	usleep (100000);
	total_diff = 0.0;

	gperf_profiler_init (NULL, "fair-http-client");
	for (i = 0; i < ntests; i ++) {
		for (j = 0; j < pconns; j ++) {
			rspamd_http_client_func (filepath + sizeof ("/tmp") - 1, addr,
					client_key, peer_key, c, ev_base, &latency[i * pconns + j]);
		}
		ts1 = rspamd_get_ticks (FALSE);
		event_base_loop (ev_base, 0);
		ts2 = rspamd_get_ticks (FALSE);
		diff = (ts2 - ts1) * 1000.0;
		total_diff += diff;
	}
	gperf_profiler_stop ();

	msg_info ("Made %d uncached encrypted connections of size %d in %.6f ms, %.6f cps",
			ntests * pconns,
			file_size,
			total_diff, ntests * pconns / total_diff * 1000.);
	mean = rspamd_http_calculate_mean (latency, &std);
	msg_info ("Latency: %.6f ms mean, %.6f dev",
			mean, std);

	/* AES mode */
	serv_key = rspamd_keypair_new (RSPAMD_KEYPAIR_KEX,
			RSPAMD_CRYPTOBOX_MODE_NIST);
	client_key = rspamd_keypair_new (RSPAMD_KEYPAIR_KEX,
			RSPAMD_CRYPTOBOX_MODE_NIST);
	c = rspamd_keypair_cache_new (16);

	/* Restart server */
	rspamd_http_stop_servers (sfd);
	/* No keypairs cache */
	rspamd_http_start_servers (sfd, addr, serv_key, c);

	//rspamd_mempool_lock_mutex (mtx);
	usleep (100000);
	b32_key = rspamd_keypair_print (serv_key,
			RSPAMD_KEYPAIR_PUBKEY | RSPAMD_KEYPAIR_BASE32);
	g_assert (b32_key != NULL);
	peer_key = rspamd_pubkey_from_base32 (b32_key->str, b32_key->len,
			RSPAMD_KEYPAIR_KEX, RSPAMD_CRYPTOBOX_MODE_NIST);
	g_assert (peer_key != NULL);
	total_diff = 0.0;

	gperf_profiler_init (NULL, "cached-http-client-aes");
	for (i = 0; i < ntests; i++) {
		for (j = 0; j < pconns; j++) {
			rspamd_http_client_func (filepath + sizeof ("/tmp") - 1,
					addr,
					client_key,
					peer_key,
					NULL,
					ev_base,
					&latency[i * pconns + j]);
		}
		ts1 = rspamd_get_ticks (FALSE);
		event_base_loop (ev_base, 0);
		ts2 = rspamd_get_ticks (FALSE);
		diff = (ts2 - ts1) * 1000.0;
		total_diff += diff;
	}
	gperf_profiler_stop ();

	msg_info (
			"Made %d aes encrypted connections of size %d in %.6f ms, %.6f cps",
			ntests * pconns,
			file_size,
			total_diff,
			ntests * pconns / total_diff * 1000.);
	mean = rspamd_http_calculate_mean (latency, &std);
	msg_info ("Latency: %.6f ms mean, %.6f dev",
			mean, std);

	/* Restart server */
	rspamd_http_stop_servers (sfd);
	/* No keypairs cache */
	rspamd_http_start_servers (sfd, addr, serv_key, NULL);

	//rspamd_mempool_lock_mutex (mtx);
	usleep (100000);
	total_diff = 0.0;

	gperf_profiler_init (NULL, "fair-http-client-aes");
	for (i = 0; i < ntests; i++) {
		for (j = 0; j < pconns; j++) {
			rspamd_http_client_func (filepath + sizeof ("/tmp") - 1,
					addr,
					client_key,
					peer_key,
					c,
					ev_base,
					&latency[i * pconns + j]);
		}
		ts1 = rspamd_get_ticks (FALSE);
		event_base_loop (ev_base, 0);
		ts2 = rspamd_get_ticks (FALSE);
		diff = (ts2 - ts1) * 1000.0;
		total_diff += diff;
	}
	gperf_profiler_stop ();

	msg_info (
			"Made %d uncached aes encrypted connections of size %d in %.6f ms, %.6f cps",
			ntests * pconns,
			file_size,
			total_diff,
			ntests * pconns / total_diff * 1000.);
	mean = rspamd_http_calculate_mean (latency, &std);
	msg_info ("Latency: %.6f ms mean, %.6f dev",
			mean, std);

	close (fd);
	unlink (filepath);
	rspamd_http_stop_servers (sfd);
}
