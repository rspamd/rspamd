/* Copyright (c) 2010-2012, Vsevolod Stakhov
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
#include "cfg_file.h"
#include "cfg_xml.h"
#include "util.h"
#include "smtp_proto.h"
#include "map.h"
#include "message.h"
#include "settings.h"
#include "dns.h"
#include "upstream.h"
#include "proxy.h"

/*
 * SMTP proxy is a simple smtp proxy worker for dns resolving and
 * load balancing. It uses XCLIENT command and is designed for MTA
 * that supports that (postfix and exim).
 */

/* Upstream timeouts */
#define DEFAULT_UPSTREAM_ERROR_TIME 10
#define DEFAULT_UPSTREAM_DEAD_TIME 300
#define DEFAULT_UPSTREAM_MAXERRORS 10

#define DEFAULT_PROXY_BUF_LEN 100 * 1024

static sig_atomic_t                    wanna_die = 0;

/* Init functions */
gpointer init_smtp_proxy ();
void start_smtp_proxy (struct rspamd_worker *worker);

worker_t smtp_proxy_worker = {
	"smtp_proxy",				/* Name */
	init_smtp_proxy,			/* Init function */
	start_smtp_proxy,			/* Start function */
	TRUE,						/* Has socket */
	FALSE,						/* Non unique */
	FALSE,						/* Non threaded */
	TRUE						/* Killable */
};

struct smtp_proxy_ctx {
	struct smtp_upstream upstreams[MAX_SMTP_UPSTREAMS];
	size_t upstream_num;
	gchar *upstreams_str;

	memory_pool_t *pool;
	guint32 smtp_delay;
	guint32 delay_jitter;
	guint32 smtp_timeout_raw;
	struct timeval smtp_timeout;

	gboolean use_xclient;

	gsize proxy_buf_len;

	struct rspamd_dns_resolver *resolver;
	struct event_base *ev_base;
};

enum rspamd_smtp_proxy_state {
	SMTP_PROXY_STATE_RESOLVE_REVERSE = 0,
	SMTP_PROXY_STATE_RESOLVE_NORMAL,
	SMTP_PROXY_STATE_DELAY
};

struct smtp_proxy_session {
	struct smtp_proxy_ctx *ctx;
	memory_pool_t *pool;

	enum rspamd_smtp_proxy_state state;
	struct rspamd_worker *worker;
	struct in_addr client_addr;
	gchar *hostname;
	gchar *error;
	gchar *temp_name;
	gint sock;
	gint upstream_sock;

	struct rspamd_async_session *s;
	rspamd_io_dispatcher_t *dispatcher;

	rspamd_proxy_t *proxy;

	struct smtp_upstream *upstream;

	struct event *delay_timer;

	gboolean resolved;
	struct rspamd_dns_resolver *resolver;
	struct event_base *ev_base;
};

#ifndef HAVE_SA_SIGINFO
static void
sig_handler (gint signo)
#else
static void
sig_handler (gint signo, siginfo_t *info, void *unused)
#endif
{
	struct timeval                  tv;

	switch (signo) {
	case SIGINT:
	case SIGTERM:
		if (!wanna_die) {
			wanna_die = 1;
			tv.tv_sec = 0;
			tv.tv_usec = 0;
			event_loopexit (&tv);

#ifdef WITH_GPERF_TOOLS
			ProfilerStop ();
#endif
		}
		break;
	}
}

/*
 * Config reload is designed by sending sigusr to active workers and pending shutdown of them
 */
static void
sigusr2_handler (gint fd, short what, void *arg)
{
	struct rspamd_worker           *worker = (struct rspamd_worker *)arg;
	/* Do not accept new connections, preparing to end worker's process */
	struct timeval                  tv;
	if (! wanna_die) {
		tv.tv_sec = SOFT_SHUTDOWN_TIME;
		tv.tv_usec = 0;
		event_del (&worker->sig_ev_usr1);
		event_del (&worker->sig_ev_usr2);
		event_del (&worker->bind_ev);
		msg_info ("worker's shutdown is pending in %d sec", SOFT_SHUTDOWN_TIME);
		event_loopexit (&tv);
	}
	return;
}

/*
 * Reopen log is designed by sending sigusr1 to active workers and pending shutdown of them
 */
static void
sigusr1_handler (gint fd, short what, void *arg)
{
	struct rspamd_worker           *worker = (struct rspamd_worker *) arg;

	reopen_log (worker->srv->logger);

	return;
}

static void
free_smtp_proxy_session (gpointer arg)
{
	struct smtp_proxy_session            *session = arg;

	if (session) {
		if (session->dispatcher) {
			rspamd_remove_dispatcher (session->dispatcher);
		}

		close (session->sock);
		memory_pool_delete (session->pool);
		g_slice_free1 (sizeof (struct smtp_proxy_session), session);
	}
}

static void
smtp_proxy_err_proxy (GError * err, void *arg)
{
	struct smtp_proxy_session            *session = arg;

	if (err) {
		g_error_free (err);
		msg_info ("abnormally closing connection, error: %s", err->message);
	}
	/* Free buffers */
	destroy_session (session->s);
}

static gboolean
create_smtp_proxy_upstream_connection (struct smtp_proxy_session *session)
{
	struct smtp_upstream              *selected;
	struct sockaddr_un                *un;

	/* Try to select upstream */
	selected = (struct smtp_upstream *)get_upstream_round_robin (session->ctx->upstreams,
			session->ctx->upstream_num, sizeof (struct smtp_upstream),
			time (NULL), DEFAULT_UPSTREAM_ERROR_TIME, DEFAULT_UPSTREAM_DEAD_TIME, DEFAULT_UPSTREAM_MAXERRORS);
	if (selected == NULL) {
		msg_err ("no upstreams suitable found");
		return FALSE;
	}

	session->upstream = selected;

	/* Now try to create socket */
	if (selected->is_unix) {
		un = alloca (sizeof (struct sockaddr_un));
		session->upstream_sock = make_unix_socket (selected->name, un, FALSE, TRUE);
	}
	else {
		session->upstream_sock = make_tcp_socket (&selected->addr, selected->port, FALSE, TRUE);
	}
	if (session->upstream_sock == -1) {
		msg_err ("cannot make a connection to %s", selected->name);
		upstream_fail (&selected->up, time (NULL));
		return FALSE;
	}
	/* Create a proxy for upstream connection */
	rspamd_dispatcher_pause (session->dispatcher);
	session->proxy = rspamd_create_proxy (session->sock, session->upstream_sock, session->pool,
			session->ev_base, session->ctx->proxy_buf_len,
			&session->ctx->smtp_timeout, smtp_proxy_err_proxy, session);

	return TRUE;
}

/* Resolving and delay handlers */
/*
 * Return from a delay
 */
static void
smtp_delay_handler (gint fd, short what, void *arg)
{
	struct smtp_proxy_session *session = arg;

	remove_normal_event (session->s, (event_finalizer_t) event_del,
			session->delay_timer);
	if (session->state == SMTP_PROXY_STATE_DELAY) {
		/* TODO: Create upstream connection here */
		create_smtp_proxy_upstream_connection (session);
	}
	else {
		/* TODO: Write error here */
		if (rspamd_dispatcher_write (session->dispatcher,
				make_smtp_error (session->pool, 550, "%s Improper use of SMTP command pipelining", "5.5.0"),
				0, FALSE, TRUE)) {
			destroy_session (session->s);
		}
	}
}

/*
 * Make delay for a client
 */
static void
smtp_make_delay (struct smtp_proxy_session *session)
{
	struct event *tev;
	struct timeval *tv;
	gint32 jitter;

	if (session->ctx->smtp_delay != 0 && session->state == SMTP_PROXY_STATE_DELAY) {
		tev = memory_pool_alloc (session->pool, sizeof(struct event));
		tv = memory_pool_alloc (session->pool, sizeof(struct timeval));
		if (session->ctx->delay_jitter != 0) {
			jitter = g_random_int_range (0, session->ctx->delay_jitter);
			msec_to_tv (session->ctx->smtp_delay + jitter, tv);
		}
		else {
			msec_to_tv (session->ctx->smtp_delay, tv);
		}

		evtimer_set (tev, smtp_delay_handler, session);
		evtimer_add (tev, tv);
		register_async_event (session->s, (event_finalizer_t) event_del, tev,
				g_quark_from_static_string ("smtp proxy"));
		session->delay_timer = tev;
	}
	else if (session->state == SMTP_PROXY_STATE_DELAY) {
		/* TODO: Create upstream connection here */
		create_smtp_proxy_upstream_connection (session);
	}
}

/*
 * Handle DNS replies
 */
static void
smtp_dns_cb (struct rspamd_dns_reply *reply, void *arg)
{
	struct smtp_proxy_session *session = arg;
	gint res = 0;
	union rspamd_reply_element *elt;
	GList *cur;

	switch (session->state)
	{
	case SMTP_PROXY_STATE_RESOLVE_REVERSE:
		/* Parse reverse reply and start resolve of this ip */
		if (reply->code != DNS_RC_NOERROR) {
			rspamd_conditional_debug (rspamd_main->logger,
					session->client_addr.s_addr, __FUNCTION__, "DNS error: %s",
					dns_strerror (reply->code));

			if (reply->code == DNS_RC_NXDOMAIN) {
				session->hostname = memory_pool_strdup (session->pool,
						XCLIENT_HOST_UNAVAILABLE);
			}
			else {
				session->hostname = memory_pool_strdup (session->pool,
						XCLIENT_HOST_TEMPFAIL);
			}
			session->state = SMTP_PROXY_STATE_DELAY;
			smtp_make_delay (session);
		}
		else {
			if (reply->elements) {
				elt = reply->elements->data;
				session->hostname = memory_pool_strdup (session->pool,
						elt->ptr.name);
				session->state = SMTP_PROXY_STATE_RESOLVE_NORMAL;
				make_dns_request (session->resolver, session->s, session->pool,
						smtp_dns_cb, session, DNS_REQUEST_A, session->hostname);

			}
		}
		break;
	case SMTP_PROXY_STATE_RESOLVE_NORMAL:
		if (reply->code != DNS_RC_NOERROR) {
			rspamd_conditional_debug (rspamd_main->logger,
					session->client_addr.s_addr, __FUNCTION__, "DNS error: %s",
					dns_strerror (reply->code));

			if (reply->code == DNS_RC_NXDOMAIN) {
				session->hostname = memory_pool_strdup (session->pool,
						XCLIENT_HOST_UNAVAILABLE);
			}
			else {
				session->hostname = memory_pool_strdup (session->pool,
						XCLIENT_HOST_TEMPFAIL);
			}
			session->state = SMTP_PROXY_STATE_DELAY;
			smtp_make_delay (session);
		}
		else {
			res = 0;
			cur = reply->elements;
			while (cur) {
				elt = cur->data;
				if (memcmp (&session->client_addr, &elt->a.addr[0],
						sizeof(struct in_addr)) == 0) {
					res = 1;
					session->resolved = TRUE;
					break;
				}
				cur = g_list_next (cur);
			}

			if (res == 0) {
				msg_info(
						"cannot find address for hostname: %s, ip: %s", session->hostname, inet_ntoa (session->client_addr));
				session->hostname = memory_pool_strdup (session->pool,
						XCLIENT_HOST_UNAVAILABLE);
			}
			session->state = SMTP_PROXY_STATE_DELAY;
			smtp_make_delay (session);
		}
		break;
	default:
		/* TODO: write something about pipelining */
		break;
	}
}

/*
 * Callback that is called when there is data to read in buffer
 */
static                          gboolean
smtp_proxy_read_socket (f_str_t * in, void *arg)
{
	struct smtp_proxy_session            *session = arg;

	/* This can be called only if client is using invalid pipelining */
	if (rspamd_dispatcher_write (session->dispatcher,
			make_smtp_error (session->pool, 550, "%s Improper use of SMTP command pipelining", "5.5.0"),
			0, FALSE, TRUE)) {
		destroy_session (session->s);
	}
	else {
		return FALSE;
	}

	return TRUE;
}

/*
 * Called if something goes wrong
 */
static void
smtp_proxy_err_socket (GError * err, void *arg)
{
	struct smtp_proxy_session            *session = arg;

	if (err) {
		g_error_free (err);
		msg_info ("abnormally closing connection, error: %s", err->message);
	}
	/* Free buffers */
	destroy_session (session->s);
}

/*
 * Accept new connection and construct session
 */
static void
accept_socket (gint fd, short what, void *arg)
{
	struct rspamd_worker           *worker = (struct rspamd_worker *)arg;
	union sa_union                  su;
	struct smtp_proxy_session      *session;
	struct smtp_proxy_ctx          *ctx;

	socklen_t                       addrlen = sizeof (su.ss);
	gint                            nfd;

	if ((nfd = accept_from_socket (fd, (struct sockaddr *)&su.ss, &addrlen)) == -1) {
		msg_warn ("accept failed: %s", strerror (errno));
		return;
	}
	/* Check for EAGAIN */
	if (nfd == 0) {
		return;
	}

	ctx = worker->ctx;
	session = g_slice_alloc0 (sizeof (struct smtp_proxy_session));
	session->pool = memory_pool_new (memory_pool_get_size ());

	if (su.ss.ss_family == AF_UNIX) {
		msg_info ("accepted connection from unix socket");
		session->client_addr.s_addr = INADDR_NONE;
	}
	else if (su.ss.ss_family == AF_INET) {
		msg_info ("accepted connection from %s port %d", inet_ntoa (su.s4.sin_addr), ntohs (su.s4.sin_port));
		memcpy (&session->client_addr, &su.s4.sin_addr, sizeof (struct in_addr));
	}

	session->sock = nfd;
	session->worker = worker;
	session->ctx = ctx;
	session->resolver = ctx->resolver;
	session->ev_base = ctx->ev_base;
	worker->srv->stat->connections_count++;

	/* Resolve client's addr */
	/* Set up async session */
	session->s = new_async_session (session->pool, NULL, NULL, free_smtp_proxy_session, session);
	session->state = SMTP_PROXY_STATE_RESOLVE_REVERSE;
	if (! make_dns_request (session->resolver, session->s, session->pool,
			smtp_dns_cb, session, DNS_REQUEST_PTR, &session->client_addr)) {
		msg_err ("cannot resolve %s", inet_ntoa (session->client_addr));
		g_slice_free1 (sizeof (struct smtp_proxy_session), session);
		close (nfd);
		return;
	}
	else {
		session->dispatcher = rspamd_create_dispatcher (session->ev_base, nfd, BUFFER_ANY,
								smtp_proxy_read_socket, NULL, smtp_proxy_err_socket,
								&session->ctx->smtp_timeout, session);
		session->dispatcher->peer_addr = session->client_addr.s_addr;
	}
}

gpointer
init_smtp_proxy (void)
{
	struct smtp_proxy_ctx         		*ctx;
	GQuark								type;

	type = g_quark_try_string ("smtp_proxy");

	ctx = g_malloc0 (sizeof (struct smtp_worker_ctx));
	ctx->pool = memory_pool_new (memory_pool_get_size ());

	/* Set default values */
	ctx->smtp_timeout_raw = 300000;
	ctx->smtp_delay = 0;

	register_worker_opt (type, "upstreams", xml_handle_string, ctx,
				G_STRUCT_OFFSET (struct smtp_proxy_ctx, upstreams_str));
	register_worker_opt (type, "timeout", xml_handle_seconds, ctx,
					G_STRUCT_OFFSET (struct smtp_proxy_ctx, smtp_timeout_raw));
	register_worker_opt (type, "delay", xml_handle_seconds, ctx,
					G_STRUCT_OFFSET (struct smtp_proxy_ctx, smtp_delay));
	register_worker_opt (type, "jitter", xml_handle_seconds, ctx,
						G_STRUCT_OFFSET (struct smtp_proxy_ctx, delay_jitter));
	register_worker_opt (type, "xclient", xml_handle_boolean, ctx,
							G_STRUCT_OFFSET (struct smtp_proxy_ctx, use_xclient));
	register_worker_opt (type, "proxy_buffer", xml_handle_size, ctx,
								G_STRUCT_OFFSET (struct smtp_proxy_ctx, proxy_buf_len));

	return ctx;
}

/* Make post-init configuration */
static gboolean
config_smtp_proxy_worker (struct rspamd_worker *worker)
{
	struct smtp_proxy_ctx         *ctx = worker->ctx;
	gchar                         *value;

	/* Init timeval */
	msec_to_tv (ctx->smtp_timeout_raw, &ctx->smtp_timeout);

	/* Init upstreams */
	if ((value = ctx->upstreams_str) != NULL) {
		if (!parse_upstreams_line (ctx->pool, ctx->upstreams, value, &ctx->upstream_num)) {
			return FALSE;
		}
	}
	else {
		msg_err ("no upstreams defined, don't know what to do");
		return FALSE;
	}

	if (ctx->proxy_buf_len == 0) {
		ctx->proxy_buf_len = DEFAULT_PROXY_BUF_LEN;
	}

	return TRUE;
}

/*
 * Start worker process
 */
void
start_smtp_proxy (struct rspamd_worker *worker)
{
	struct sigaction                signals;
	struct smtp_proxy_ctx         *ctx = worker->ctx;

	gperf_profiler_init (worker->srv->cfg, "worker");

	worker->srv->pid = getpid ();
	ctx->ev_base = event_init ();

	/* Set smtp options */
	if ( !config_smtp_proxy_worker (worker)) {
		msg_err ("cannot configure smtp worker, exiting");
		exit (EXIT_SUCCESS);
	}

	init_signals (&signals, sig_handler);
	sigprocmask (SIG_UNBLOCK, &signals.sa_mask, NULL);

	/* SIGUSR2 handler */
	signal_set (&worker->sig_ev_usr2, SIGUSR2, sigusr2_handler, (void *) worker);
	event_base_set (ctx->ev_base, &worker->sig_ev_usr2);
	signal_add (&worker->sig_ev_usr2, NULL);

	/* SIGUSR1 handler */
	signal_set (&worker->sig_ev_usr1, SIGUSR1, sigusr1_handler, (void *) worker);
	event_base_set (ctx->ev_base, &worker->sig_ev_usr1);
	signal_add (&worker->sig_ev_usr1, NULL);

	/* Accept event */
	event_set (&worker->bind_ev, worker->cf->listen_sock, EV_READ | EV_PERSIST, accept_socket, (void *)worker);
	event_base_set (ctx->ev_base, &worker->bind_ev);
	event_add (&worker->bind_ev, NULL);

	/* DNS resolver */
	ctx->resolver = dns_resolver_init (ctx->ev_base, worker->srv->cfg);

	/* Set umask */
	umask (S_IWGRP | S_IWOTH | S_IROTH | S_IRGRP);

	event_base_loop (ctx->ev_base, 0);

	close_log (rspamd_main->logger);
	exit (EXIT_SUCCESS);
}

