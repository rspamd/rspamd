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
/*
 * Rspamd worker implementation
 */

#include "config.h"
#include "libutil/util.h"
#include "libserver/maps/map.h"
#include "libutil/upstream.h"
#include "libserver/protocol.h"
#include "libserver/cfg_file.h"
#include "libserver/url.h"
#include "libserver/dns.h"
#include "libmime/message.h"
#include "rspamd.h"
#include "libstat/stat_api.h"
#include "libserver/worker_util.h"
#include "libserver/rspamd_control.h"
#include "worker_private.h"
#include "libserver/http/http_private.h"
#include "libserver/cfg_file_private.h"
#include <math.h>
#include "unix-std.h"

#include "lua/lua_common.h"

/* 60 seconds for worker's IO */
#define DEFAULT_WORKER_IO_TIMEOUT 60.0

gpointer init_worker (struct rspamd_config *cfg);
void start_worker (struct rspamd_worker *worker);

worker_t normal_worker = {
		"normal",                   /* Name */
		init_worker,                /* Init function */
		start_worker,               /* Start function */
		RSPAMD_WORKER_HAS_SOCKET|RSPAMD_WORKER_KILLABLE|RSPAMD_WORKER_SCANNER,
		RSPAMD_WORKER_SOCKET_TCP,   /* TCP socket */
		RSPAMD_WORKER_VER           /* Version info */
};

#define msg_err_ctx(...) rspamd_default_log_function(G_LOG_LEVEL_CRITICAL, \
        "worker", ctx->cfg->cfg_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_warn_ctx(...)   rspamd_default_log_function (G_LOG_LEVEL_WARNING, \
        "worker", ctx->cfg->cfg_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_info_ctx(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
        "worker", ctx->cfg->cfg_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)

struct rspamd_worker_session {
	gint64 magic;
	struct rspamd_task *task;
	gint fd;
	rspamd_inet_addr_t *addr;
	struct rspamd_worker_ctx *ctx;
	struct rspamd_http_connection *http_conn;
	struct rspamd_worker *worker;
};
/*
 * Reduce number of tasks proceeded
 */
static void
reduce_tasks_count (gpointer arg)
{
	struct rspamd_worker *worker = arg;

	worker->nconns --;

	if (worker->state == rspamd_worker_wait_connections && worker->nconns == 0) {

		worker->state = rspamd_worker_wait_final_scripts;
		msg_info ("performing finishing actions");

		if (rspamd_worker_call_finish_handlers (worker)) {
			worker->state = rspamd_worker_wait_final_scripts;
		}
		else {
			worker->state = rspamd_worker_wanna_die;
		}
	}
	else if (worker->state != rspamd_worker_state_running) {
		worker->state = rspamd_worker_wait_connections;
	}
}

static gint
rspamd_worker_body_handler (struct rspamd_http_connection *conn,
	struct rspamd_http_message *msg,
	const gchar *chunk, gsize len)
{
	struct rspamd_worker_session *session = (struct rspamd_worker_session *)conn->ud;
	struct rspamd_task *task;
	struct rspamd_worker_ctx *ctx;
	const rspamd_ftok_t *hv_tok;
	gboolean debug_mempool = FALSE;

	ctx = session->ctx;

	/* Check debug */
	if ((hv_tok = rspamd_http_message_find_header (msg, "Memory")) != NULL) {
		rspamd_ftok_t cmp;

		RSPAMD_FTOK_ASSIGN (&cmp, "debug");

		if (rspamd_ftok_cmp (hv_tok, &cmp) == 0) {
			debug_mempool = TRUE;
		}
	}

	task = rspamd_task_new (session->worker,
			session->ctx->cfg, NULL, session->ctx->lang_det,
			session->ctx->event_loop,
			debug_mempool);
	session->task = task;

	msg_info_task ("accepted connection from %s port %d, task ptr: %p",
			rspamd_inet_address_to_string (session->addr),
			rspamd_inet_address_get_port (session->addr),
			task);

	/* Copy some variables */
	if (ctx->is_mime) {
		task->flags |= RSPAMD_TASK_FLAG_MIME;
	}
	else {
		task->flags &= ~RSPAMD_TASK_FLAG_MIME;
	}

	/* We actually transfer ownership from session to task here  */
	task->sock = session->fd;
	task->client_addr = session->addr;
	task->worker = session->worker;
	task->http_conn = session->http_conn;

	task->resolver = ctx->resolver;
	/* TODO: allow to disable autolearn in protocol */
	task->flags |= RSPAMD_TASK_FLAG_LEARN_AUTO;

	session->worker->nconns++;
	rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t)reduce_tasks_count,
			session->worker);

	/* Session memory is also now handled by task */
	rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t)g_free,
			session);

	/* Set up async session */
	task->s = rspamd_session_create (task->task_pool, rspamd_task_fin,
			rspamd_task_restore, (event_finalizer_t )rspamd_task_free, task);

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
		task->timeout_ev.data = task;
		ev_timer_init (&task->timeout_ev, rspamd_task_timeout,
				ctx->task_timeout,
				ctx->task_timeout);
		ev_set_priority (&task->timeout_ev, EV_MAXPRI);
		ev_timer_start (task->event_loop, &task->timeout_ev);
	}

	/* Set socket guard */
	task->guard_ev.data = task;
	ev_io_init (&task->guard_ev,
			rspamd_worker_guard_handler,
			task->sock, EV_READ);
	ev_io_start (task->event_loop, &task->guard_ev);

	rspamd_task_process (task, RSPAMD_TASK_PROCESS_ALL);

	return 0;
}

static void
rspamd_worker_error_handler (struct rspamd_http_connection *conn, GError *err)
{
	struct rspamd_worker_session *session = (struct rspamd_worker_session *)conn->ud;
	struct rspamd_task *task;
	struct rspamd_http_message *msg;
	rspamd_fstring_t *reply;

	/*
	 * This function can be called with both struct rspamd_worker_session *
	 * and struct rspamd_task *
	 *
	 * The first case is when we read message and it is controlled by this code;
	 * the second case is when a reply is written and we do not control it normally,
	 * as it is managed by `rspamd_protocol_reply` in protocol.c
	 *
	 * Hence, we need to distinguish our arguments...
	 *
	 * The approach here is simple:
	 * - struct rspamd_worker_session starts with gint64 `magic` and we set it to
	 * MAX_INT64
	 * - struct rspamd_task starts with a pointer (or pointer + command on 32 bit system)
	 *
	 * The idea is simple: no sane pointer would reach MAX_INT64, so if this field
	 * is MAX_INT64 then it is our session, and if it is not then it is a task.
	 */

	if (session->magic == G_MAXINT64) {
		task = session->task;
	}
	else {
		task = (struct rspamd_task *)conn->ud;
	}


	if (task) {
		msg_info_task ("abnormally closing connection from: %s, error: %e",
				rspamd_inet_address_to_string_pretty (task->client_addr), err);

		if (task->processed_stages & RSPAMD_TASK_STAGE_REPLIED) {
			/* Terminate session immediately */
			rspamd_session_destroy (task->s);
		}
		else {
			task->processed_stages |= RSPAMD_TASK_STAGE_REPLIED;
			msg = rspamd_http_new_message (HTTP_RESPONSE);

			if (err) {
				msg->status = rspamd_fstring_new_init (err->message,
						strlen (err->message));
				msg->code = err->code;
			}
			else {
				msg->status = rspamd_fstring_new_init ("Internal error",
						strlen ("Internal error"));
				msg->code = 500;
			}

			msg->date = time (NULL);

			reply = rspamd_fstring_sized_new (msg->status->len + 16);
			rspamd_printf_fstring (&reply, "{\"error\":\"%V\"}", msg->status);
			rspamd_http_message_set_body_from_fstring_steal (msg, reply);
			rspamd_http_connection_reset (task->http_conn);
			/* Use a shorter timeout for writing reply */
			rspamd_http_connection_write_message (task->http_conn,
					msg,
					NULL,
					"application/json",
					task,
					session->ctx->timeout / 10.0);
		}
	}
	else {
		/* If there was no task, then session is unmanaged */
		msg_info ("no data received from: %s, error: %e",
				rspamd_inet_address_to_string_pretty (session->addr), err);
		rspamd_http_connection_reset (session->http_conn);
		rspamd_http_connection_unref (session->http_conn);
		rspamd_inet_address_free (session->addr);
		close (session->fd);
		g_free (session);
	}
}

static gint
rspamd_worker_finish_handler (struct rspamd_http_connection *conn,
	struct rspamd_http_message *msg)
{
	struct rspamd_worker_session *session = (struct rspamd_worker_session *)conn->ud;
	struct rspamd_task *task;

	/* Read the comment to rspamd_worker_error_handler */

	if (session->magic == G_MAXINT64) {
		task = session->task;
	}
	else {
		task = (struct rspamd_task *)conn->ud;
	}

	if (task) {
		if (task->processed_stages & RSPAMD_TASK_STAGE_REPLIED) {
			/* We are done here */
			msg_debug_task ("normally closing connection from: %s",
					rspamd_inet_address_to_string (task->client_addr));
			rspamd_session_destroy (task->s);
		}
		else if (task->processed_stages & RSPAMD_TASK_STAGE_DONE) {
			rspamd_session_pending (task->s);
		}
	}
	else {
		/* If there was no task, then session is unmanaged */
		msg_info ("no data received from: %s, closing connection",
				rspamd_inet_address_to_string_pretty (session->addr));
		rspamd_inet_address_free (session->addr);
		rspamd_http_connection_reset (session->http_conn);
		rspamd_http_connection_unref (session->http_conn);
		close (session->fd);
		g_free (session);
	}

	return 0;
}

/*
 * Accept new connection and construct task
 */
static void
accept_socket (EV_P_ ev_io *w, int revents)
{
	struct rspamd_worker *worker = (struct rspamd_worker *) w->data;
	struct rspamd_worker_ctx *ctx;
	struct rspamd_worker_session *session;
	rspamd_inet_addr_t *addr = NULL;
	gint nfd, http_opts = 0;

	ctx = worker->ctx;

	if (ctx->max_tasks != 0 && worker->nconns > ctx->max_tasks) {
		msg_info_ctx ("current tasks is now: %uD while maximum is: %uD",
				worker->nconns,
			ctx->max_tasks);
		return;
	}

	if ((nfd =
		rspamd_accept_from_socket (w->fd, &addr,
				rspamd_worker_throttle_accept_events, worker->accept_events)) == -1) {
		msg_warn_ctx ("accept failed: %s", strerror (errno));
		return;
	}
	/* Check for EAGAIN */
	if (nfd == 0) {
		rspamd_inet_address_free (addr);

		return;
	}

	session = g_malloc0 (sizeof (*session));
	session->magic = G_MAXINT64;
	session->addr = addr;
	session->fd = nfd;
	session->ctx = ctx;
	session->worker = worker;

	if (ctx->encrypted_only && !rspamd_inet_address_is_local (addr)) {
		http_opts = RSPAMD_HTTP_REQUIRE_ENCRYPTION;
	}

	session->http_conn = rspamd_http_connection_new_server (
			ctx->http_ctx,
			nfd,
			rspamd_worker_body_handler,
			rspamd_worker_error_handler,
			rspamd_worker_finish_handler,
			http_opts);

	worker->srv->stat->connections_count++;
	rspamd_http_connection_set_max_size (session->http_conn,
			ctx->cfg->max_message);

	if (ctx->key) {
		rspamd_http_connection_set_key (session->http_conn, ctx->key);
	}

	rspamd_http_connection_read_message (session->http_conn,
			session,
			ctx->timeout);
}

gpointer
init_worker (struct rspamd_config *cfg)
{
	struct rspamd_worker_ctx *ctx;
	GQuark type;

	type = g_quark_try_string ("normal");
	ctx = rspamd_mempool_alloc0 (cfg->cfg_pool,
			sizeof (struct rspamd_worker_ctx));

	ctx->magic = rspamd_worker_magic;
	ctx->is_mime = TRUE;
	ctx->timeout = DEFAULT_WORKER_IO_TIMEOUT;
	ctx->cfg = cfg;
	ctx->task_timeout = NAN;

	rspamd_rcl_register_worker_option (cfg,
			type,
			"mime",
			rspamd_rcl_parse_struct_boolean,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_worker_ctx, is_mime),
			0,
			"Set to `false` if this worker is intended to work with non-MIME messages");

	rspamd_rcl_register_worker_option (cfg,
			type,
			"encrypted_only",
			rspamd_rcl_parse_struct_boolean,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_worker_ctx, encrypted_only),
			0,
			"Allow only encrypted connections");


	rspamd_rcl_register_worker_option (cfg,
			type,
			"timeout",
			rspamd_rcl_parse_struct_time,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_worker_ctx,
						timeout),
			RSPAMD_CL_FLAG_TIME_FLOAT,
			"Protocol IO timeout");

	rspamd_rcl_register_worker_option (cfg,
			type,
			"task_timeout",
			rspamd_rcl_parse_struct_time,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_worker_ctx,
						task_timeout),
			RSPAMD_CL_FLAG_TIME_FLOAT,
			"Maximum task processing time, default: 8.0 seconds");

	rspamd_rcl_register_worker_option (cfg,
			type,
			"max_tasks",
			rspamd_rcl_parse_struct_integer,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_worker_ctx,
						max_tasks),
			RSPAMD_CL_FLAG_INT_32,
			"Maximum count of parallel tasks processed by a single worker process");

	rspamd_rcl_register_worker_option (cfg,
			type,
			"keypair",
			rspamd_rcl_parse_struct_keypair,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_worker_ctx,
						key),
			0,
			"Encryption keypair");

	return ctx;
}

/*
 * Start worker process
 */
__attribute__((noreturn))
void
start_worker (struct rspamd_worker *worker)
{
	struct rspamd_worker_ctx *ctx = worker->ctx;
	gboolean is_controller = FALSE;

	g_assert (rspamd_worker_check_context (worker->ctx, rspamd_worker_magic));
	ctx->cfg = worker->srv->cfg;
	ctx->event_loop = rspamd_prepare_worker (worker, "normal", accept_socket);
	rspamd_symcache_start_refresh (worker->srv->cfg->cache, ctx->event_loop,
			worker);

	if (isnan (ctx->task_timeout)) {
		if (isnan (ctx->cfg->task_timeout)) {
			ctx->task_timeout = 0;
		}
		else {
			ctx->task_timeout = ctx->cfg->task_timeout;
		}
	}

	ctx->resolver = rspamd_dns_resolver_init (worker->srv->logger,
			ctx->event_loop,
			worker->srv->cfg);
	rspamd_upstreams_library_config (worker->srv->cfg, ctx->cfg->ups_ctx,
			ctx->event_loop, ctx->resolver->r);

	ctx->http_ctx = rspamd_http_context_create (ctx->cfg, ctx->event_loop,
			ctx->cfg->ups_ctx);
	rspamd_mempool_add_destructor (ctx->cfg->cfg_pool,
			(rspamd_mempool_destruct_t)rspamd_http_context_free,
			ctx->http_ctx);
	rspamd_worker_init_scanner (worker, ctx->event_loop, ctx->resolver,
			&ctx->lang_det);

	if (worker->index == 0) {
		/* If there are no controllers, then pretend that we are a controller */
		gboolean controller_seen = FALSE;
		GList *cur;

		cur = worker->srv->cfg->workers;

		while (cur) {
			struct rspamd_worker_conf *cf;

			cf = (struct rspamd_worker_conf *)cur->data;
			if (cf->type == g_quark_from_static_string ("controller")) {
				if (cf->enabled && cf->count >= 0) {
					controller_seen = TRUE;
					break;
				}
			}

			cur = g_list_next (cur);
		}

		if (!controller_seen) {
			msg_info_ctx ("no controller workers defined, execute "
				 "controller periodics in this worker");
			worker->flags |= RSPAMD_WORKER_CONTROLLER;
			is_controller = TRUE;
		}
	}

	if (is_controller) {
		rspamd_worker_init_controller (worker, NULL);
	}
	else {
		rspamd_map_watch (worker->srv->cfg, ctx->event_loop, ctx->resolver,
				worker, RSPAMD_MAP_WATCH_SCANNER);
	}

	rspamd_lua_run_postloads (ctx->cfg->lua_state, ctx->cfg, ctx->event_loop,
			worker);

	ev_loop (ctx->event_loop, 0);
	rspamd_worker_block_signals ();

	if (is_controller) {
		rspamd_controller_on_terminate (worker, NULL);
	}

	rspamd_stat_close ();
	REF_RELEASE (ctx->cfg);
	rspamd_log_close (worker->srv->logger);

	exit (EXIT_SUCCESS);
}
