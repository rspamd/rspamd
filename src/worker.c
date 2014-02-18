/*
 * Copyright (c) 2009-2012, Vsevolod Stakhov
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

/*
 * Rspamd worker implementation
 */

#include "config.h"
#include "util.h"
#include "main.h"
#include "protocol.h"
#include "upstream.h"
#include "cfg_file.h"
#include "cfg_xml.h"
#include "url.h"
#include "message.h"
#include "map.h"
#include "dns.h"

#include "lua/lua_common.h"

#ifdef WITH_GPERF_TOOLS
#   include <glib/gprintf.h>
#endif

/* 60 seconds for worker's IO */
#define DEFAULT_WORKER_IO_TIMEOUT 60000

gpointer init_worker (struct config_file *cfg);
void start_worker (struct rspamd_worker *worker);

worker_t normal_worker = {
	"normal",					/* Name */
	init_worker,				/* Init function */
	start_worker,				/* Start function */
	TRUE,						/* Has socket */
	FALSE,						/* Non unique */
	FALSE,						/* Non threaded */
	TRUE,						/* Killable */
	SOCK_STREAM					/* TCP socket */
};

/*
 * Worker's context
 */
struct rspamd_worker_ctx {
	guint32                         timeout;
	struct timeval                  io_tv;
	/* Detect whether this worker is mime worker 	*/
	gboolean                        is_mime;
	/* HTTP worker									*/
	gboolean                        is_http;
	/* JSON output     								*/
	gboolean                        is_json;
	/* Allow learning throught worker				*/
	gboolean                        allow_learn;
	/* DNS resolver */
	struct rspamd_dns_resolver     *resolver;
	/* Current tasks */
	guint32                         tasks;
	/* Limit of tasks */
	guint32                         max_tasks;
	/* Classify threads */
	guint32							classify_threads;
	/* Classify threads */
	GThreadPool					   *classify_pool;
	/* Events base */
	struct event_base              *ev_base;
};

static sig_atomic_t             wanna_die = 0;

#ifndef HAVE_SA_SIGINFO
static void
sig_handler (gint signo)
#else
static void
sig_handler (gint signo, siginfo_t * info, void *unused)
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
 * Config reload is designed by sending sigusr2 to active workers and pending shutdown of them
 */
static void
sigusr2_handler (gint fd, short what, void *arg)
{
	struct rspamd_worker           *worker = (struct rspamd_worker *) arg;
	/* Do not accept new connections, preparing to end worker's process */
	struct timeval                  tv;

	if (!wanna_die) {
		tv.tv_sec = SOFT_SHUTDOWN_TIME;
		tv.tv_usec = 0;
		event_del (&worker->sig_ev_usr1);
		event_del (&worker->sig_ev_usr2);
		worker_stop_accept (worker);
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

/*
 * Reduce number of tasks proceeded
 */
static void
reduce_tasks_count (gpointer arg)
{
	guint32                        *tasks = arg;

	(*tasks) --;
}

static gint
rspamd_worker_body_handler (struct rspamd_http_connection *conn,
		struct rspamd_http_message *msg,
		const gchar *chunk, gsize len)
{
	struct worker_task             *task = (struct worker_task *) conn->ud;
	struct rspamd_worker_ctx       *ctx;
	ssize_t                         r;
	GError                         *err = NULL;

	ctx = task->worker->ctx;

	if (task->cmd == CMD_PING) {
		task->state = WRITE_REPLY;
		return 0;
	}

	if (msg->body->len == 0) {
		msg_err ("got zero length body, cannot continue");
		task->last_error = "message's body is empty";
		task->error_code = RSPAMD_LENGTH_ERROR;
		task->state = WRITE_REPLY;
		return 0;
	}

	if (!rspamd_protocol_handle_request (task, msg)) {
		task->state = WRITE_REPLY;
		return 0;
	}

	task->msg = msg->body;

	debug_task ("got string of length %z", task->msg->len);

	/* We got body, set wanna_die flag */
	task->s->wanna_die = TRUE;

	r = process_message (task);
	if (r == -1) {
		msg_warn ("processing of message failed");
		task->last_error = "MIME processing error";
		task->error_code = RSPAMD_FILTER_ERROR;
		task->state = WRITE_REPLY;
		return 0;
	}
	if (task->cmd == CMD_OTHER) {
		/* Skip filters */
		task->state = WRITE_REPLY;
		return 0;
	}
	else {
		if (task->cfg->pre_filters == NULL) {
			r = process_filters (task);
			if (r == -1) {
				task->last_error = "filter processing error";
				task->error_code = RSPAMD_FILTER_ERROR;
				task->state = WRITE_REPLY;
				return 0;
			}
			/* Add task to classify to classify pool */
			if (!task->is_skipped && ctx->classify_pool) {
				register_async_thread (task->s);
				g_thread_pool_push (ctx->classify_pool, task, &err);
				if (err != NULL) {
					msg_err ("cannot pull task to the pool: %s", err->message);
					remove_async_thread (task->s);
				}
			}
			if (task->is_skipped) {
				/* Call write_socket to write reply and exit */
				task->state = WRITE_REPLY;
				return 0;
			}
		}
		else {
			lua_call_pre_filters (task);
			/* We want fin_task after pre filters are processed */
			task->s->wanna_die = TRUE;
			task->state = WAIT_PRE_FILTER;
			check_session_pending (task->s);
		}
	}
	return 0;
}

static void
rspamd_worker_error_handler (struct rspamd_http_connection *conn, GError *err)
{
	struct worker_task             *task = (struct worker_task *) conn->ud;

	msg_info ("abnormally closing connection from: %s, error: %s",
			inet_ntoa (task->client_addr), err->message);
	if (task->state != CLOSING_CONNECTION) {
		/* We still need to write a reply */
		task->error_code = err->code;
		task->last_error = err->message;
		task->state = WRITE_REPLY;
		rspamd_protocol_write_reply (task);
	}
	else {
		/* Terminate session immediately */
		destroy_session (task->s);
	}
}

static gint
rspamd_worker_finish_handler (struct rspamd_http_connection *conn,
		struct rspamd_http_message *msg)
{
	struct worker_task             *task = (struct worker_task *) conn->ud;

	if (task->state == CLOSING_CONNECTION) {
		msg_debug ("normally closing connection from: %s", inet_ntoa (task->client_addr));
		destroy_session (task->s);
	}
	else {
		/*
		 * If all filters have finished their tasks, this function will trigger
		 * writing a reply.
		 */
		task->s->wanna_die = TRUE;
		check_session_pending (task->s);
	}

	return 0;
}

/*
 * Accept new connection and construct task
 */
static void
accept_socket (gint fd, short what, void *arg)
{
	struct rspamd_worker           *worker = (struct rspamd_worker *) arg;
	struct rspamd_worker_ctx       *ctx;
	union sa_union                  su;
	struct worker_task             *new_task;
	char                            ip_str[INET6_ADDRSTRLEN + 1];

	socklen_t                       addrlen = sizeof (su);
	gint                            nfd;

	ctx = worker->ctx;

	if (ctx->max_tasks != 0 && ctx->tasks > ctx->max_tasks) {
		msg_info ("current tasks is now: %uD while maximum is: %uD", ctx->tasks, ctx->max_tasks);
		return;
	}

	if ((nfd =
			accept_from_socket (fd, &su.sa, &addrlen)) == -1) {
		msg_warn ("accept failed: %s", strerror (errno));
		return;
	}
	/* Check for EAGAIN */
	if (nfd == 0){
		return;
	}

	new_task = construct_task (worker);

	if (su.sa.sa_family == AF_UNIX) {
		msg_info ("accepted connection from unix socket");
		new_task->client_addr.s_addr = INADDR_NONE;
	}
	else if (su.sa.sa_family == AF_INET) {
		msg_info ("accepted connection from %s port %d",
				inet_ntoa (su.s4.sin_addr), ntohs (su.s4.sin_port));
		memcpy (&new_task->client_addr, &su.s4.sin_addr,
				sizeof (struct in_addr));
	}
	else if (su.sa.sa_family == AF_INET6) {
		msg_info ("accepted connection from %s port %d",
				inet_ntop (su.sa.sa_family, &su.s6.sin6_addr, ip_str, sizeof (ip_str)),
				ntohs (su.s6.sin6_port));
	}

	/* Copy some variables */
	new_task->sock = nfd;
	new_task->is_mime = ctx->is_mime;
	new_task->is_json = ctx->is_json;
	new_task->allow_learn = ctx->allow_learn;

	worker->srv->stat->connections_count++;
	new_task->resolver = ctx->resolver;

#if 0
	/* Set up dispatcher */
	new_task->dispatcher =
			rspamd_create_dispatcher (ctx->ev_base, nfd, BUFFER_LINE, read_socket, write_socket,
					err_socket, &ctx->io_tv, (void *) new_task);
	new_task->dispatcher->peer_addr = new_task->client_addr.s_addr;
#endif
	new_task->http_conn = rspamd_http_connection_new (rspamd_worker_body_handler,
			rspamd_worker_error_handler, rspamd_worker_finish_handler, 0, RSPAMD_HTTP_SERVER);
	new_task->ev_base = ctx->ev_base;
	ctx->tasks ++;
	memory_pool_add_destructor (new_task->task_pool, (pool_destruct_func)reduce_tasks_count, &ctx->tasks);

	/* Set up async session */
	new_task->s = new_async_session (new_task->task_pool, rspamd_fin_task,
						rspamd_restore_task, free_task_hard, new_task);

	new_task->classify_pool = ctx->classify_pool;

	rspamd_http_connection_read_message (new_task->http_conn, new_task, nfd, &ctx->io_tv, ctx->ev_base);
}

gpointer
init_worker (struct config_file *cfg)
{
	struct rspamd_worker_ctx       *ctx;
	GQuark								type;

	type = g_quark_try_string ("normal");

	ctx = g_malloc0 (sizeof (struct rspamd_worker_ctx));

	ctx->is_mime = TRUE;
	ctx->timeout = DEFAULT_WORKER_IO_TIMEOUT;
	ctx->classify_threads = 1;

	rspamd_rcl_register_worker_option (cfg, type, "mime",
			rspamd_rcl_parse_struct_boolean, ctx,
			G_STRUCT_OFFSET (struct rspamd_worker_ctx, is_mime), 0);

	rspamd_rcl_register_worker_option (cfg, type, "http",
			rspamd_rcl_parse_struct_boolean, ctx,
			G_STRUCT_OFFSET (struct rspamd_worker_ctx, is_http), 0);

	rspamd_rcl_register_worker_option (cfg, type, "json",
			rspamd_rcl_parse_struct_boolean, ctx,
			G_STRUCT_OFFSET (struct rspamd_worker_ctx, is_json), 0);

	rspamd_rcl_register_worker_option (cfg, type, "allow_learn",
			rspamd_rcl_parse_struct_boolean, ctx,
			G_STRUCT_OFFSET (struct rspamd_worker_ctx, allow_learn), 0);

	rspamd_rcl_register_worker_option (cfg, type, "timeout",
			rspamd_rcl_parse_struct_time, ctx,
			G_STRUCT_OFFSET (struct rspamd_worker_ctx, timeout), RSPAMD_CL_FLAG_TIME_INTEGER);

	rspamd_rcl_register_worker_option (cfg, type, "max_tasks",
			rspamd_rcl_parse_struct_integer, ctx,
			G_STRUCT_OFFSET (struct rspamd_worker_ctx, max_tasks), RSPAMD_CL_FLAG_INT_32);

	rspamd_rcl_register_worker_option (cfg, type, "classify_threads",
			rspamd_rcl_parse_struct_integer, ctx,
			G_STRUCT_OFFSET (struct rspamd_worker_ctx, classify_threads), RSPAMD_CL_FLAG_INT_32);

	return ctx;
}

/*
 * Start worker process
 */
void
start_worker (struct rspamd_worker *worker)
{
	struct rspamd_worker_ctx       *ctx = worker->ctx;
	GError						   *err = NULL;
	struct lua_locked_state		   *nL;

	ctx->ev_base = prepare_worker (worker, "normal", sig_handler, accept_socket);
	msec_to_tv (ctx->timeout, &ctx->io_tv);

	/* SIGUSR2 handler */
	signal_set (&worker->sig_ev_usr2, SIGUSR2, sigusr2_handler, (void *) worker);
	event_base_set (ctx->ev_base, &worker->sig_ev_usr2);
	signal_add (&worker->sig_ev_usr2, NULL);

	/* SIGUSR1 handler */
	signal_set (&worker->sig_ev_usr1, SIGUSR1, sigusr1_handler, (void *) worker);
	event_base_set (ctx->ev_base, &worker->sig_ev_usr1);
	signal_add (&worker->sig_ev_usr1, NULL);

	start_map_watch (worker->srv->cfg, ctx->ev_base);


	ctx->resolver = dns_resolver_init (ctx->ev_base, worker->srv->cfg);

	/* Create classify pool */
	ctx->classify_pool = NULL;
	if (ctx->classify_threads > 1) {
		nL = init_lua_locked (worker->srv->cfg);
		ctx->classify_pool = g_thread_pool_new (process_statfiles_threaded, nL, ctx->classify_threads, TRUE, &err);
		if (err != NULL) {
			msg_err ("pool create failed: %s", err->message);
			ctx->classify_pool = NULL;
		}
	}

	event_base_loop (ctx->ev_base, 0);

	g_mime_shutdown ();
	close_log (rspamd_main->logger);
	exit (EXIT_SUCCESS);
}

/* 
 * vi:ts=4 
 */
