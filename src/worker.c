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

#include <libserver/rspamd_control.h>
#include <tclDecls.h>
#include <curses.h>
#include "config.h"
#include "libutil/util.h"
#include "libutil/map.h"
#include "libutil/upstream.h"
#include "libserver/protocol.h"
#include "libserver/cfg_file.h"
#include "libserver/url.h"
#include "libserver/dns.h"
#include "libmime/message.h"
#include "rspamd.h"
#include "keypairs_cache.h"
#include "libstat/stat_api.h"
#include "libserver/worker_util.h"
#include "libserver/rspamd_control.h"

#include "lua/lua_common.h"

/* 60 seconds for worker's IO */
#define DEFAULT_WORKER_IO_TIMEOUT 60000
/* Timeout for task processing */
#define DEFAULT_TASK_TIMEOUT 8.0

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

#define msg_err_ctx(...) rspamd_default_log_function(G_LOG_LEVEL_CRITICAL, \
        "controller", ctx->cfg->cfg_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_warn_ctx(...)   rspamd_default_log_function (G_LOG_LEVEL_WARNING, \
        "controller", ctx->cfg->cfg_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_info_ctx(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
        "controller", ctx->cfg->cfg_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_debug_ctx(...)  rspamd_default_log_function (G_LOG_LEVEL_DEBUG, \
        "controller", ctx->cfg->cfg_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)

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
	/* Limit of tasks */
	guint32 max_tasks;
	/* Maximum time for task processing */
	gdouble task_timeout;
	/* Events base */
	struct event_base *ev_base;
	/* Encryption key */
	gpointer key;
	/* Keys cache */
	struct rspamd_keypair_cache *keys_cache;
	/* Configuration */
	struct rspamd_config *cfg;
};

/*
 * Reduce number of tasks proceeded
 */
static void
reduce_tasks_count (gpointer arg)
{
	guint *nconns = arg;

	(*nconns)--;
}

static void
rspamd_task_timeout (gint fd, short what, gpointer ud)
{
	struct rspamd_task *task = (struct rspamd_task *) ud;

	if (!(task->processed_stages & RSPAMD_TASK_STAGE_FILTERS)) {
		msg_info_task ("processing of task timed out, forced processing");
		task->processed_stages |= RSPAMD_TASK_STAGE_FILTERS;
		rspamd_session_cleanup (task->s);
		rspamd_task_process (task, RSPAMD_TASK_PROCESS_ALL);
		rspamd_session_pending (task->s);
	}
}

static gint
rspamd_worker_body_handler (struct rspamd_http_connection *conn,
	struct rspamd_http_message *msg,
	const gchar *chunk, gsize len)
{
	struct rspamd_task *task = (struct rspamd_task *) conn->ud;
	struct rspamd_worker_ctx *ctx;
	struct timeval task_tv;

	ctx = task->worker->ctx;

	if (!rspamd_protocol_handle_request (task, msg)) {
		msg_err_task ("cannot handle request: %e", task->err);
		task->flags |= RSPAMD_TASK_FLAG_SKIP;
	}
	else {
		if (task->cmd == CMD_PING) {
			task->flags |= RSPAMD_TASK_FLAG_SKIP;
		}
		else {
			if (!rspamd_task_load_message (task, msg, chunk, len)) {
				msg_err_task ("cannot load message: %e", task->err);
				task->flags |= RSPAMD_TASK_FLAG_SKIP;
			}
		}
	}

	/* Set global timeout for the task */
	if (ctx->task_timeout > 0.0) {
		event_set (&task->timeout_ev, -1, EV_TIMEOUT, rspamd_task_timeout,
				task);
		event_base_set (ctx->ev_base, &task->timeout_ev);
		double_to_tv (ctx->task_timeout, &task_tv);
		event_add (&task->timeout_ev, &task_tv);
	}

	rspamd_task_process (task, RSPAMD_TASK_PROCESS_ALL);

	return 0;
}

static void
rspamd_worker_error_handler (struct rspamd_http_connection *conn, GError *err)
{
	struct rspamd_task *task = (struct rspamd_task *) conn->ud;

	msg_info_task ("abnormally closing connection from: %s, error: %e",
		rspamd_inet_address_to_string (task->client_addr), err);
	/* Terminate session immediately */
	rspamd_session_destroy (task->s);
}

static gint
rspamd_worker_finish_handler (struct rspamd_http_connection *conn,
	struct rspamd_http_message *msg)
{
	struct rspamd_task *task = (struct rspamd_task *) conn->ud;

	if (task->processed_stages & RSPAMD_TASK_STAGE_REPLIED) {
		/* We are done here */
		msg_debug_task ("normally closing connection from: %s",
			rspamd_inet_address_to_string (task->client_addr));
		rspamd_session_destroy (task->s);
	}
	else if (task->processed_stages & RSPAMD_TASK_STAGE_DONE) {
		rspamd_session_pending (task->s);
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
	struct rspamd_task *task;
	rspamd_inet_addr_t *addr;
	gint nfd;

	ctx = worker->ctx;

	if (ctx->max_tasks != 0 && worker->nconns > ctx->max_tasks) {
		msg_info_ctx ("current tasks is now: %uD while maximum is: %uD",
				worker->nconns,
			ctx->max_tasks);
		return;
	}

	if ((nfd =
		rspamd_accept_from_socket (fd, &addr)) == -1) {
		msg_warn_ctx ("accept failed: %s", strerror (errno));
		return;
	}
	/* Check for EAGAIN */
	if (nfd == 0) {
		return;
	}

	task = rspamd_task_new (worker, ctx->cfg);

	msg_info_task ("accepted connection from %s port %d",
		rspamd_inet_address_to_string (addr),
		rspamd_inet_address_get_port (addr));

	/* Copy some variables */
	if (ctx->is_mime) {
		task->flags |= RSPAMD_TASK_FLAG_MIME;
	}
	else {
		task->flags &= ~RSPAMD_TASK_FLAG_MIME;
	}

	task->sock = nfd;
	task->client_addr = addr;

	worker->srv->stat->connections_count++;
	task->resolver = ctx->resolver;

	task->http_conn = rspamd_http_connection_new (
		rspamd_worker_body_handler,
		rspamd_worker_error_handler,
		rspamd_worker_finish_handler,
		0,
		RSPAMD_HTTP_SERVER,
		ctx->keys_cache);
	task->ev_base = ctx->ev_base;
	worker->nconns++;
	rspamd_mempool_add_destructor (task->task_pool,
		(rspamd_mempool_destruct_t)reduce_tasks_count, &worker->nconns);

	/* Set up async session */
	task->s = rspamd_session_create (task->task_pool, rspamd_task_fin,
			rspamd_task_restore, (event_finalizer_t )rspamd_task_free, task);

	if (ctx->key) {
		rspamd_http_connection_set_key (task->http_conn, ctx->key);
	}

	rspamd_http_connection_read_message (task->http_conn,
			task,
		nfd,
		&ctx->io_tv,
		ctx->ev_base);
}

#ifdef WITH_HYPERSCAN
static gboolean
rspamd_worker_hyperscan_ready (struct rspamd_main *rspamd_main,
		struct rspamd_worker *worker, gint fd,
		struct rspamd_control_command *cmd,
		gpointer ud)
{
	struct rspamd_control_reply rep;

	msg_info ("loading hyperscan expressions after receiving compilation notice");
	memset (&rep, 0, sizeof (rep));
	rep.type = RSPAMD_CONTROL_HYPERSCAN_LOADED;

	rep.reply.hs_loaded.status = rspamd_re_cache_load_hyperscan (
			worker->srv->cfg->re_cache, cmd->cmd.hs_loaded.cache_dir);

	if (write (fd, &rep, sizeof (rep)) != sizeof (rep)) {
		msg_err ("cannot write reply to the control socket: %s",
				strerror (errno));
	}

	return TRUE;
}
#endif

gpointer
init_worker (struct rspamd_config *cfg)
{
	struct rspamd_worker_ctx *ctx;
	GQuark type;

	type = g_quark_try_string ("normal");

	ctx = g_malloc0 (sizeof (struct rspamd_worker_ctx));

	ctx->is_mime = TRUE;
	ctx->timeout = DEFAULT_WORKER_IO_TIMEOUT;
	ctx->cfg = cfg;
	ctx->task_timeout = DEFAULT_TASK_TIMEOUT;

	rspamd_rcl_register_worker_option (cfg,
			type,
			"mime",
			rspamd_rcl_parse_struct_boolean,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_worker_ctx, is_mime),
			0,
			NULL);

	rspamd_rcl_register_worker_option (cfg,
			type,
			"http",
			rspamd_rcl_parse_struct_boolean,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_worker_ctx, is_http),
			0,
			NULL);

	rspamd_rcl_register_worker_option (cfg,
			type,
			"json",
			rspamd_rcl_parse_struct_boolean,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_worker_ctx, is_json),
			0,
			NULL);

	rspamd_rcl_register_worker_option (cfg,
			type,
			"allow_learn",
			rspamd_rcl_parse_struct_boolean,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_worker_ctx, allow_learn),
			0,
			NULL);

	rspamd_rcl_register_worker_option (cfg,
			type,
			"timeout",
			rspamd_rcl_parse_struct_time,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_worker_ctx,
						timeout),
			RSPAMD_CL_FLAG_TIME_INTEGER,
			NULL);

	rspamd_rcl_register_worker_option (cfg,
			type,
			"task_timeout",
			rspamd_rcl_parse_struct_time,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_worker_ctx,
						task_timeout),
			RSPAMD_CL_FLAG_TIME_FLOAT,
			NULL);

	rspamd_rcl_register_worker_option (cfg,
			type,
			"max_tasks",
			rspamd_rcl_parse_struct_integer,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_worker_ctx,
						max_tasks),
			RSPAMD_CL_FLAG_INT_32,
			NULL);

	rspamd_rcl_register_worker_option (cfg,
			type,
			"keypair",
			rspamd_rcl_parse_struct_keypair,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_worker_ctx,
						key),
			0,
			NULL);

	return ctx;
}

/*
 * Start worker process
 */
void
start_worker (struct rspamd_worker *worker)
{
	struct rspamd_worker_ctx *ctx = worker->ctx;

	ctx->ev_base = rspamd_prepare_worker (worker, "normal", accept_socket);
	msec_to_tv (ctx->timeout, &ctx->io_tv);

	rspamd_map_watch (worker->srv->cfg, ctx->ev_base);
	rspamd_symbols_cache_start_refresh (worker->srv->cfg->cache, ctx->ev_base);

	ctx->resolver = dns_resolver_init (worker->srv->logger,
			ctx->ev_base,
			worker->srv->cfg);

	rspamd_upstreams_library_config (worker->srv->cfg, ctx->cfg->ups_ctx,
			ctx->ev_base, ctx->resolver->r);

	/* XXX: stupid default */
	ctx->keys_cache = rspamd_keypair_cache_new (256);
	rspamd_stat_init (worker->srv->cfg);

#ifdef WITH_HYPERSCAN
	rspamd_control_worker_add_cmd_handler (worker, RSPAMD_CONTROL_HYPERSCAN_LOADED,
			rspamd_worker_hyperscan_ready, ctx);
#endif

	event_base_loop (ctx->ev_base, 0);
	rspamd_worker_block_signals ();

	g_mime_shutdown ();
	rspamd_stat_close ();
	rspamd_log_close (worker->srv->logger);

	if (ctx->key) {
		rspamd_http_connection_key_unref (ctx->key);
	}

	rspamd_keypair_cache_destroy (ctx->keys_cache);

	exit (EXIT_SUCCESS);
}
