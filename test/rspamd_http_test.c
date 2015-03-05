/* Copyright (c) 2015, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
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
#include "main.h"
#include "util.h"
#include "http.h"
#include "tests.h"
#include "ottery.h"
#include "cryptobox.h"

static const int file_blocks = 8;
static const int pconns = 10;
static const int ntests = 3000;

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
	rspamd_inet_addr_t addr;
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

	rspamd_http_router_handle_socket (rt, nfd, NULL);
}

static void
rspamd_http_server_func (const gchar *path, rspamd_inet_addr_t *addr,
		rspamd_mempool_mutex_t *mtx, gpointer kp, struct rspamd_keypair_cache *c)
{
	struct rspamd_http_connection_router *rt;
	struct event_base *ev_base = event_init ();
	struct event accept_ev;
	gint fd;

	rt = rspamd_http_router_new (rspamd_server_error, rspamd_server_finish,
			NULL, ev_base, path, c);
	g_assert (rt != NULL);

	rspamd_http_router_set_key (rt, kp);

	g_assert ((fd = rspamd_inet_address_listen (addr, SOCK_STREAM, TRUE)) != -1);
	event_set (&accept_ev, fd, EV_READ | EV_PERSIST, rspamd_server_accept, rt);
	event_base_set (ev_base, &accept_ev);
	event_add (&accept_ev, NULL);


	rspamd_mempool_unlock_mutex (mtx);
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
	struct timespec ts;

	*(cb->lat) = rspamd_get_ticks () * 1000.;
	close (conn->fd);
	rspamd_http_connection_unref (conn);
	g_free (cb);

	return 0;
}

static void
rspamd_http_client_func (const gchar *path, rspamd_inet_addr_t *addr,
		gpointer kp, gpointer peer_kp, struct rspamd_keypair_cache *c,
		struct event_base *ev_base, double *latency)
{
	struct rspamd_http_message *msg;
	struct rspamd_http_connection *conn;
	gchar urlbuf[PATH_MAX];
	struct client_cbdata *cb;
	gint fd;

	g_assert ((fd = rspamd_inet_address_connect (addr, SOCK_STREAM, TRUE)) != -1);
	conn = rspamd_http_connection_new (rspamd_client_body, rspamd_client_err,
			rspamd_client_finish, RSPAMD_HTTP_CLIENT_SIMPLE,
			RSPAMD_HTTP_CLIENT, c);
	rspamd_snprintf (urlbuf, sizeof (urlbuf), "http://127.0.0.1/%s", path);
	msg = rspamd_http_message_from_url (urlbuf);

	g_assert (conn != NULL && msg != NULL);

	if (kp != NULL) {
		g_assert (peer_kp != NULL);
		rspamd_http_connection_set_key (conn, kp);
		msg->peer_key = rspamd_http_connection_key_ref (peer_kp);
	}

	cb = g_malloc (sizeof (*cb));
	cb->ts = rspamd_get_ticks ();
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
	gint i;
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

void
rspamd_http_test_func (void)
{
	struct event_base *ev_base = event_init ();
	rspamd_mempool_t *pool = rspamd_mempool_new (rspamd_mempool_suggest_size ());
	gpointer serv_key, client_key, peer_key;
	struct rspamd_keypair_cache *c;
	rspamd_mempool_mutex_t *mtx;
	rspamd_inet_addr_t addr;
	gdouble ts1, ts2;
	gchar filepath[PATH_MAX], buf[512];
	gint fd, i, j;
	pid_t sfd;
	GString *b32_key;
	double diff, total_diff = 0.0, latency[pconns * ntests], mean, std;

	rspamd_cryptobox_init ();
	rspamd_snprintf (filepath, sizeof (filepath), "/tmp/http-test-XXXXXX");
	g_assert ((fd = mkstemp (filepath)) != -1);

	for (i = 0; i < file_blocks; i ++) {
		memset (buf, 0, sizeof (buf));
		g_assert (write (fd, buf, sizeof (buf)) == sizeof (buf));
	}

	mtx = rspamd_mempool_get_mutex (pool);

	rspamd_parse_inet_address (&addr, "127.0.0.1");
	rspamd_inet_address_set_port (&addr, ottery_rand_range (30000) + 32768);
	serv_key = rspamd_http_connection_gen_key ();
	client_key = rspamd_http_connection_gen_key ();
	c = rspamd_keypair_cache_new (16);

	rspamd_mempool_lock_mutex (mtx);
	sfd = fork ();
	g_assert (sfd != -1);

	if (sfd == 0) {
		rspamd_http_server_func ("/tmp/", &addr, mtx, serv_key, c);
		exit (EXIT_SUCCESS);
	}

	rspamd_mempool_lock_mutex (mtx);

	/* Do client stuff */
	for (i = 0; i < ntests; i ++) {
		for (j = 0; j < pconns; j ++) {
			rspamd_http_client_func (filepath + sizeof ("/tmp") - 1, &addr,
					NULL, NULL, c, ev_base, &latency[i * pconns + j]);
		}
		ts1 = rspamd_get_ticks ();
		event_base_loop (ev_base, 0);
		ts2 = rspamd_get_ticks ();
		diff = (ts2 - ts1) * 1000.0;
		total_diff += diff;
	}

	msg_info ("Made %d connections of size %d in %.6f ms, %.6f cps",
			ntests * pconns,
			sizeof (buf) * file_blocks,
			total_diff, ntests * pconns / total_diff * 1000.);
	mean = rspamd_http_calculate_mean (latency, &std);
	msg_info ("Latency: %.6f ms mean, %.6f dev",
			mean, std);

	/* Now test encrypted */
	b32_key = rspamd_http_connection_print_key (serv_key,
			RSPAMD_KEYPAIR_PUBKEY|RSPAMD_KEYPAIR_BASE32);
	g_assert (b32_key != NULL);
	peer_key = rspamd_http_connection_make_peer_key (b32_key->str);
	g_assert (peer_key != NULL);
	total_diff = 0.0;

	for (i = 0; i < ntests; i ++) {
		for (j = 0; j < pconns; j ++) {
			rspamd_http_client_func (filepath + sizeof ("/tmp") - 1, &addr,
					client_key, peer_key, c, ev_base, &latency[i * pconns + j]);
		}
		ts1 = rspamd_get_ticks ();
		event_base_loop (ev_base, 0);
		ts2 = rspamd_get_ticks ();
		diff = (ts2 - ts1) * 1000.0;
		total_diff += diff;
	}

	msg_info ("Made %d encrypted connections of size %d in %.6f ms, %.6f cps",
			ntests * pconns,
			sizeof (buf) * file_blocks,
			total_diff, ntests * pconns / total_diff * 1000.);
	mean = rspamd_http_calculate_mean (latency, &std);
	msg_info ("Latency: %.6f ms mean, %.6f dev",
			mean, std);

	/* Restart server */
	kill (sfd, SIGTERM);
	wait (&i);
	sfd = fork ();
	g_assert (sfd != -1);

	if (sfd == 0) {
		rspamd_http_server_func ("/tmp/", &addr, mtx, serv_key, NULL);
		exit (EXIT_SUCCESS);
	}

	rspamd_mempool_lock_mutex (mtx);
	total_diff = 0.0;

	for (i = 0; i < ntests; i ++) {
		for (j = 0; j < pconns; j ++) {
			rspamd_http_client_func (filepath + sizeof ("/tmp") - 1, &addr,
					client_key, peer_key, c, ev_base, &latency[i * pconns + j]);
		}
		ts1 = rspamd_get_ticks ();
		event_base_loop (ev_base, 0);
		ts2 = rspamd_get_ticks ();
		diff = (ts2 - ts1) * 1000.0;
		total_diff += diff;
	}

	msg_info ("Made %d uncached encrypted connections of size %d in %.6f ms, %.6f cps",
			ntests * pconns,
			sizeof (buf) * file_blocks,
			total_diff, ntests * pconns / total_diff * 1000.);
	mean = rspamd_http_calculate_mean (latency, &std);
	msg_info ("Latency: %.6f ms mean, %.6f dev",
			mean, std);

	close (fd);
	unlink (filepath);
	kill (sfd, SIGTERM);
}
