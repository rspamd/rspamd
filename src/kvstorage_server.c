/* Copyright (c) 2010, Vsevolod Stakhov
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
#include "kvstorage.h"
#include "kvstorage_config.h"
#include "kvstorage_server.h"
#include "cfg_file.h"
#include "cfg_xml.h"
#include "main.h"

/* This is required for normal signals processing */
static GList *global_evbases = NULL;
static struct event_base *main_base = NULL;
static sig_atomic_t wanna_die = 0;

/* Logging functions */
#define thr_err(...)	do {																			\
	g_static_mutex_lock (thr->log_mtx);																\
	rspamd_common_log_function(rspamd_main->logger, G_LOG_LEVEL_CRITICAL, __FUNCTION__, __VA_ARGS__);	\
	g_static_mutex_unlock (thr->log_mtx);																\
} while (0)

#define thr_warn(...)	do {																			\
	g_static_mutex_lock (thr->log_mtx);																\
	rspamd_common_log_function(rspamd_main->logger, G_LOG_LEVEL_WARNING, __FUNCTION__, __VA_ARGS__);	\
	g_static_mutex_unlock (thr->log_mtx);																\
} while (0)

#define thr_info(...)	do {																			\
	g_static_mutex_lock (thr->log_mtx);																\
	rspamd_common_log_function(rspamd_main->logger, G_LOG_LEVEL_INFO, __FUNCTION__, __VA_ARGS__);	\
	g_static_mutex_unlock (thr->log_mtx);																\
} while (0)

#ifndef HAVE_SA_SIGINFO
static void
sig_handler (gint signo)
#else
static void
sig_handler (gint signo, siginfo_t *info, void *unused)
#endif
{
	struct timeval                  tv;
	GList                          *cur;

	switch (signo) {
	case SIGUSR1:
		reopen_log (rspamd_main->logger);
		break;
	case SIGINT:
	case SIGTERM:
		if (!wanna_die) {
			wanna_die = 1;
			tv.tv_sec = 0;
			tv.tv_usec = 0;
			cur = global_evbases;
			while (cur) {
				event_base_loopexit (cur->data, &tv);
			}
			event_base_loopexit (main_base, &tv);
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
sigusr_handler (gint fd, short what, void *arg)
{
	struct rspamd_worker           *worker = (struct rspamd_worker *)arg;
	/* Do not accept new connections, preparing to end worker's process */
	struct timeval                  tv;
	GList                          *cur;
	struct kvstorage_worker_ctx    *ctx;
	struct kvstorage_worker_thread *thr;

	ctx = worker->ctx;
	if (! wanna_die) {
		tv.tv_sec = SOFT_SHUTDOWN_TIME;
		tv.tv_usec = 0;
		event_del (&worker->sig_ev);
		msg_info ("worker's shutdown is pending in %d sec", SOFT_SHUTDOWN_TIME);
		cur = ctx->threads;
		while (cur) {
			thr = cur->data;
			if (thr->ev_base != NULL) {
				event_del (&thr->bind_ev);
				event_base_loopexit (thr->ev_base, &tv);
			}
		}
		event_base_loopexit (ctx->ev_base, &tv);
	}
	return;
}

gpointer
init_kvstorage_worker (void)
{
	struct kvstorage_worker_ctx         *ctx;

	ctx = g_malloc0 (sizeof (struct kvstorage_worker_ctx));
	ctx->pool = memory_pool_new (memory_pool_get_size ());

	/* Set default values */
	ctx->timeout_raw = 300000;

	register_worker_opt (TYPE_SMTP, "timeout", xml_handle_seconds, ctx,
					G_STRUCT_OFFSET (struct kvstorage_worker_ctx, timeout_raw));
	return ctx;
}

/* Make post-init configuration */
static gboolean
config_kvstorage_worker (struct rspamd_worker *worker)
{
	struct kvstorage_worker_ctx         *ctx = worker->ctx;

	/* Init timeval */
	msec_to_tv (ctx->timeout_raw, &ctx->io_timeout);

	return TRUE;
}

/**
 * Accept function
 */
/*
 * Accept new connection and construct task
 */
static void
thr_accept_socket (gint fd, short what, void *arg)
{
	struct kvstorage_worker_thread		*thr = (struct kvstorage_worker_thread *)arg;
	union sa_union                 		 su;
	socklen_t                       	 addrlen = sizeof (su.ss);
	gint                            	 nfd;

	if ((nfd = accept_from_socket (fd, (struct sockaddr *)&su.ss, &addrlen)) == -1) {
		thr_warn ("%ud: accept failed: %s", thr->id, strerror (errno));
		return;
	}
	/* Check for EAGAIN */
	if (nfd == 0) {
		return;
	}

	if (su.ss.ss_family == AF_UNIX) {
		thr_info ("%ud: accepted connection from unix socket", thr->id);
	}
	else if (su.ss.ss_family == AF_INET) {
		thr_info ("%ud: accepted connection from %s port %d", thr->id,
				inet_ntoa (su.s4.sin_addr), ntohs (su.s4.sin_port));
	}
	/* XXX: write the logic */
	close (nfd);
}

/**
 * Thread main worker function
 */
static gpointer
kvstorage_thread (gpointer ud)
{
	struct kvstorage_worker_thread		*thr = ud;

	/* Init thread specific events */
	thr->ev_base = event_init ();
	event_set (&thr->bind_ev, thr->worker->cf->listen_sock, EV_READ | EV_PERSIST, thr_accept_socket, (void *)thr);
	event_base_set (thr->ev_base, &thr->bind_ev);
	event_add (&thr->bind_ev, NULL);

	event_base_loop (thr->ev_base, 0);

	return NULL;
}

/**
 * Create new thread, set it detached
 */
static struct kvstorage_worker_thread *
create_kvstorage_thread (struct rspamd_worker *worker, struct kvstorage_worker_ctx *ctx, guint id)
{
	struct kvstorage_worker_thread 		*new;
	GError								*err = NULL;

	new = memory_pool_alloc (ctx->pool, sizeof (struct kvstorage_worker_thread));
	new->ctx = ctx;
	new->worker = worker;
	new->tv = &ctx->io_timeout;
	new->log_mtx = &ctx->log_mtx;
	new->id = id;
	new->thr = g_thread_create (kvstorage_thread, new, FALSE, &err);
	new->ev_base = NULL;

	if (new->thr == NULL) {
		msg_err ("cannot create thread: %s", err->message);
	}

	return new;
}

/*
 * Start worker process
 */
void
start_kvstorage_worker (struct rspamd_worker *worker)
{
	struct sigaction                	 signals;
	struct kvstorage_worker_ctx         *ctx = worker->ctx;
	guint								 i;
	struct kvstorage_worker_thread 		*thr;

	gperf_profiler_init (worker->srv->cfg, "kvstorage");

	if (!g_thread_supported ()) {
		msg_err ("threads support is not supported on your system so kvstorage is not functionable");
		exit (EXIT_SUCCESS);
	}
	/* Create socketpair */
	if (make_socketpair (ctx->s_pair) == -1) {
		msg_err ("cannot create socketpair, exiting");
		exit (EXIT_SUCCESS);
	}
	worker->srv->pid = getpid ();
	ctx->ev_base = event_init ();
	ctx->threads = NULL;

	g_thread_init (NULL);
	main_base = ctx->ev_base;

	/* Set kvstorage options */
	if ( !config_kvstorage_worker (worker)) {
		msg_err ("cannot configure kvstorage worker, exiting");
		exit (EXIT_SUCCESS);
	}

	init_signals (&signals, sig_handler);
	sigprocmask (SIG_UNBLOCK, &signals.sa_mask, NULL);

	/* SIGUSR2 handler */
	signal_set (&worker->sig_ev, SIGUSR2, sigusr_handler, (void *)worker);
	event_base_set (ctx->ev_base, &worker->sig_ev);
	signal_add (&worker->sig_ev, NULL);

	/* Start workers threads */
	g_static_mutex_init (&ctx->log_mtx);
	for (i = 0; i < worker->cf->count; i ++) {
		thr = create_kvstorage_thread (worker, ctx, i);
		ctx->threads = g_list_prepend (ctx->threads, thr);
	}

	/* Set umask */
	umask (S_IWGRP | S_IWOTH | S_IROTH | S_IRGRP);

	event_base_loop (ctx->ev_base, 0);

	close_log (rspamd_main->logger);
	exit (EXIT_SUCCESS);
}
