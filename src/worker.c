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
#include "libutil/util.h"
#include "libutil/map.h"
#include "libutil/upstream.h"
#include "libserver/protocol.h"
#include "libserver/cfg_file.h"
#include "libserver/url.h"
#include "libserver/dns.h"
#include "libmime/message.h"
#include "main.h"

#include "lua/lua_common.h"

#ifdef WITH_GPERF_TOOLS
#   include <glib/gprintf.h>
#endif

/* 60 seconds for worker's IO */
#define DEFAULT_WORKER_IO_TIMEOUT 60000

gpointer init_worker (struct rspamd_config *cfg);
void start_worker (struct rspamd_worker *worker);

worker_t normal_worker = {
	"normal",                   /* Name */
	init_worker,                /* Init function */
	start_worker,               /* Start function */
	TRUE,                       /* Has socket */
	FALSE,                      /* Non unique */
	FALSE,                      /* Non threaded */
	TRUE,                       /* Killable */
	SOCK_STREAM                 /* TCP socket */
};

/*
 * Worker's context
 */
struct rspamd_worker_ctx {
	guint32 timeout;
	struct timeval io_tv;
	/* Detect whether this worker is mime worker    */
	gboolean is_mime;
	/* HTTP worker									*/
	gboolean is_http;
	/* JSON output                                  */
	gboolean is_json;
	/* Allow learning throught worker				*/
	gboolean allow_learn;
	/* DNS resolver */
	struct rspamd_dns_resolver *resolver;
	/* Current tasks */
	guint32 tasks;
	/* Limit of tasks */
	guint32 max_tasks;
	/* Classify threads */
	guint32 classify_threads;
	/* Classify threads */
	GThreadPool *classify_pool;
	/* Events base */
	struct event_base *ev_base;
	/* Encryption key */
	gpointer key;
};

/*
 * Reduce number of tasks proceeded
 */
static void
reduce_tasks_count (gpointer arg)
{
	guint32 *tasks = arg;

	(*tasks)--;
}

static gint
rspamd_worker_body_handler (struct rspamd_http_connection *conn,
	struct rspamd_http_message *msg,
	const gchar *chunk, gsize len)
{
	struct rspamd_task *task = (struct rspamd_task *) conn->ud;
	struct rspamd_worker_ctx *ctx;

	ctx = task->worker->ctx;

	if (!rspamd_protocol_handle_request (task, msg)) {
		task->state = WRITE_REPLY;
		return 0;
	}

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

	if (msg->peer_key) {
		task->peer_key = g_string_new (msg->peer_key->str);
	}

	if (!rspamd_task_process (task, msg, ctx->classify_pool, TRUE)) {
		task->state = WRITE_REPLY;
	}

	return 0;
}

static void
rspamd_worker_error_handler (struct rspamd_http_connection *conn, GError *err)
{
	struct rspamd_task *task = (struct rspamd_task *) conn->ud;

	msg_info ("abnormally closing connection from: %s, error: %s",
		rspamd_inet_address_to_string (&task->client_addr), err->message);
	/* Terminate session immediately */
	destroy_session (task->s);
}

static gint
rspamd_worker_finish_handler (struct rspamd_http_connection *conn,
	struct rspamd_http_message *msg)
{
	struct rspamd_task *task = (struct rspamd_task *) conn->ud;

	if (task->state == CLOSING_CONNECTION || task->state == WRITING_REPLY) {
		/* We are done here */
		msg_debug ("normally closing connection from: %s",
			rspamd_inet_address_to_string (&task->client_addr));
		destroy_session (task->s);
	}
	else if (task->state == WRITE_REPLY) {
		/*
		 * We can come here if no filters has delayed their job and we want to
		 * write reply immediately. But this handler is executed when message
		 * is read
		 */
		msg_debug ("want write message to the wire: %s",
			rspamd_inet_address_to_string (&task->client_addr));
		rspamd_protocol_write_reply (task);
		/* Forcefully set the state */
		task->state = CLOSING_CONNECTION;
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
	struct rspamd_worker *worker = (struct rspamd_worker *) arg;
	struct rspamd_worker_ctx *ctx;
	struct rspamd_task *new_task;
	rspamd_inet_addr_t addr;
	gint nfd;

	ctx = worker->ctx;

	if (ctx->max_tasks != 0 && ctx->tasks > ctx->max_tasks) {
		msg_info ("current tasks is now: %uD while maximum is: %uD",
			ctx->tasks,
			ctx->max_tasks);
		return;
	}

	if ((nfd =
		rspamd_accept_from_socket (fd, &addr)) == -1) {
		msg_warn ("accept failed: %s", strerror (errno));
		return;
	}
	/* Check for EAGAIN */
	if (nfd == 0) {
		return;
	}

	new_task = rspamd_task_new (worker);

	msg_info ("accepted connection from %s port %d",
		rspamd_inet_address_to_string (&addr),
		rspamd_inet_address_get_port (&addr));

	/* Copy some variables */
	new_task->sock = nfd;
	new_task->is_mime = ctx->is_mime;
	memcpy (&new_task->client_addr, &addr, sizeof (addr));

	worker->srv->stat->connections_count++;
	new_task->resolver = ctx->resolver;

	new_task->http_conn = rspamd_http_connection_new (
		rspamd_worker_body_handler,
		rspamd_worker_error_handler,
		rspamd_worker_finish_handler,
		0,
		RSPAMD_HTTP_SERVER);
	new_task->ev_base = ctx->ev_base;
	ctx->tasks++;
	rspamd_mempool_add_destructor (new_task->task_pool,
		(rspamd_mempool_destruct_t)reduce_tasks_count, &ctx->tasks);

	/* Set up async session */
	new_task->s = new_async_session (new_task->task_pool, rspamd_task_fin,
			rspamd_task_restore, rspamd_task_free_hard, new_task);

	new_task->classify_pool = ctx->classify_pool;

	if (ctx->key) {
		rspamd_http_connection_set_key (new_task->http_conn, ctx->key);
	}

	rspamd_http_connection_read_message (new_task->http_conn,
		new_task,
		nfd,
		&ctx->io_tv,
		ctx->ev_base);
}

gpointer
init_worker (struct rspamd_config *cfg)
{
	struct rspamd_worker_ctx *ctx;
	GQuark type;

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
		G_STRUCT_OFFSET (struct rspamd_worker_ctx,
		timeout), RSPAMD_CL_FLAG_TIME_INTEGER);

	rspamd_rcl_register_worker_option (cfg, type, "max_tasks",
		rspamd_rcl_parse_struct_integer, ctx,
		G_STRUCT_OFFSET (struct rspamd_worker_ctx,
		max_tasks), RSPAMD_CL_FLAG_INT_32);

	rspamd_rcl_register_worker_option (cfg, type, "classify_threads",
		rspamd_rcl_parse_struct_integer, ctx,
		G_STRUCT_OFFSET (struct rspamd_worker_ctx,
		classify_threads), RSPAMD_CL_FLAG_INT_32);


	rspamd_rcl_register_worker_option (cfg, type, "keypair",
		rspamd_rcl_parse_struct_keypair, ctx,
		G_STRUCT_OFFSET (struct rspamd_worker_ctx,
		key), 0);

	return ctx;
}

/*
 * Start worker process
 */
void
start_worker (struct rspamd_worker *worker)
{
	struct rspamd_worker_ctx *ctx = worker->ctx;
	GError *err = NULL;
	struct lua_locked_state *nL;

	ctx->ev_base = rspamd_prepare_worker (worker, "normal", accept_socket);
	msec_to_tv (ctx->timeout, &ctx->io_tv);

	rspamd_map_watch (worker->srv->cfg, ctx->ev_base);


	ctx->resolver = dns_resolver_init (worker->srv->logger,
			ctx->ev_base,
			worker->srv->cfg);

	rspamd_upstreams_library_init (ctx->resolver->r, ctx->ev_base);
	rspamd_upstreams_library_config (worker->srv->cfg);

	/* Create classify pool */
	ctx->classify_pool = NULL;
	if (ctx->classify_threads > 1) {
		nL = rspamd_init_lua_locked (worker->srv->cfg);
		ctx->classify_pool = g_thread_pool_new (rspamd_process_statistic_threaded,
				nL,
				ctx->classify_threads,
				TRUE,
				&err);
		if (err != NULL) {
			msg_err ("pool create failed: %s", err->message);
			ctx->classify_pool = NULL;
		}
	}

	event_base_loop (ctx->ev_base, 0);

	g_mime_shutdown ();
	rspamd_log_close (rspamd_main->logger);

	if (ctx->key) {
		rspamd_http_connection_key_unref (ctx->key);
	}

	exit (EXIT_SUCCESS);
}

/*
 * vi:ts=4
 */
