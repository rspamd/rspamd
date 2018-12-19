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
#include "worker_private.h"
#include "utlist.h"
#include "libutil/http_private.h"
#include "libmime/lang_detection.h"
#include <math.h>
#include "unix-std.h"

#include "lua/lua_common.h"

/* 60 seconds for worker's IO */
#define DEFAULT_WORKER_IO_TIMEOUT 60000

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

static gboolean
rspamd_worker_finalize (gpointer user_data)
{
	struct rspamd_task *task = user_data;
	struct timeval tv = {.tv_sec = 0, .tv_usec = 0};

	if (!(task->flags & RSPAMD_TASK_FLAG_PROCESSING)) {
		msg_info_task ("finishing actions has been processed, terminating");
		event_base_loopexit (task->ev_base, &tv);
		rspamd_session_destroy (task->s);

		return TRUE;
	}

	return FALSE;
}

static gboolean
rspamd_worker_call_finish_handlers (struct rspamd_worker *worker)
{
	struct rspamd_task *task;
	struct rspamd_config *cfg = worker->srv->cfg;
	struct rspamd_abstract_worker_ctx *ctx;
	struct rspamd_config_post_load_script *sc;

	if (cfg->finish_callbacks) {
		ctx = worker->ctx;
		/* Create a fake task object for async events */
		task = rspamd_task_new (worker, cfg, NULL, NULL, ctx->ev_base);
		task->resolver = ctx->resolver;
		task->flags |= RSPAMD_TASK_FLAG_PROCESSING;
		task->s = rspamd_session_create (task->task_pool,
				rspamd_worker_finalize,
				NULL,
				(event_finalizer_t) rspamd_task_free,
				task);

		DL_FOREACH (cfg->finish_callbacks, sc) {
			lua_call_finish_script (sc, task);
		}

		task->flags &= ~RSPAMD_TASK_FLAG_PROCESSING;

		if (rspamd_session_pending (task->s)) {
			return TRUE;
		}
	}

	return FALSE;
}

/*
 * Reduce number of tasks proceeded
 */
static void
reduce_tasks_count (gpointer arg)
{
	struct rspamd_worker *worker = arg;

	worker->nconns --;

	if (worker->wanna_die && worker->nconns == 0) {
		msg_info ("performing finishing actions");
		rspamd_worker_call_finish_handlers (worker);
	}
}

void
rspamd_task_timeout (gint fd, short what, gpointer ud)
{
	struct rspamd_task *task = (struct rspamd_task *) ud;

	if (!(task->processed_stages & RSPAMD_TASK_STAGE_FILTERS)) {
		msg_info_task ("processing of task timed out, forced processing");

		if (task->cfg->soft_reject_on_timeout) {
			struct rspamd_metric_result *res = task->result;

			if (rspamd_check_action_metric (task, res) != METRIC_ACTION_REJECT) {
				rspamd_add_passthrough_result (task,
						METRIC_ACTION_SOFT_REJECT,
						0,
						NAN,
						"timeout processing message",
						"task timeout");

				ucl_object_replace_key (task->messages,
						ucl_object_fromstring_common ("timeout processing message",
								0, UCL_STRING_RAW),
						"smtp_message", 0,
						false);
			}
		}

		task->processed_stages |= RSPAMD_TASK_STAGE_FILTERS;
		rspamd_session_cleanup (task->s);
		rspamd_task_process (task, RSPAMD_TASK_PROCESS_ALL);
		rspamd_session_pending (task->s);
	}
}

void
rspamd_worker_guard_handler (gint fd, short what, void *data)
{
	struct rspamd_task *task = data;
	gchar fake_buf[1024];
	gssize r;

#ifdef EV_CLOSED
	if (what == EV_CLOSED) {
		if (!(task->flags & RSPAMD_TASK_FLAG_JSON) &&
				task->cfg->enable_shutdown_workaround) {
			msg_info_task ("workaround for shutdown enabled, please update "
					"your client, this support might be removed in future");
			shutdown (fd, SHUT_RD);
			event_del (task->guard_ev);
			task->guard_ev = NULL;
		}
		else {
			msg_err_task ("the peer has closed connection unexpectedly");
			rspamd_session_destroy (task->s);
		}

		return;
	}
#endif

	r = read (fd, fake_buf, sizeof (fake_buf));

	if (r > 0) {
		msg_warn_task ("received extra data after task is loaded, ignoring");
	}
	else {
		if (r == 0) {
			/*
			 * Poor man approach, that might break things in case of
			 * shutdown (SHUT_WR) but sockets are so bad that there's no
			 * reliable way to distinguish between shutdown(SHUT_WR) and
			 * close.
			 */
			if (!(task->flags & RSPAMD_TASK_FLAG_JSON) &&
					task->cfg->enable_shutdown_workaround) {
				msg_info_task ("workaround for shutdown enabled, please update "
						"your client, this support might be removed in future");
				shutdown (fd, SHUT_RD);
				event_del (task->guard_ev);
				task->guard_ev = NULL;
			}
			else {
				msg_err_task ("the peer has closed connection unexpectedly");
				rspamd_session_destroy (task->s);
			}
		}
		else if (errno != EAGAIN) {
			msg_err_task ("the peer has closed connection unexpectedly: %s",
					strerror (errno));
			rspamd_session_destroy (task->s);
		}
		else {
			return;
		}
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
	struct event *guard_ev;

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

	/* Set socket guard */
	guard_ev = rspamd_mempool_alloc (task->task_pool, sizeof (*guard_ev));
#ifdef EV_CLOSED
	event_set (guard_ev, task->sock, EV_READ|EV_PERSIST|EV_CLOSED,
				rspamd_worker_guard_handler, task);
#else
	event_set (guard_ev, task->sock, EV_READ|EV_PERSIST,
			rspamd_worker_guard_handler, task);
#endif
	event_base_set (task->ev_base, guard_ev);
	event_add (guard_ev, NULL);
	task->guard_ev = guard_ev;

	rspamd_task_process (task, RSPAMD_TASK_PROCESS_ALL);

	return 0;
}

static void
rspamd_worker_error_handler (struct rspamd_http_connection *conn, GError *err)
{
	struct rspamd_task *task = (struct rspamd_task *) conn->ud;
	struct rspamd_http_message *msg;
	rspamd_fstring_t *reply;

	msg_info_task ("abnormally closing connection from: %s, error: %e",
		rspamd_inet_address_to_string (task->client_addr), err);
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
		rspamd_http_connection_write_message (task->http_conn,
				msg,
				NULL,
				"application/json",
				task,
				task->http_conn->fd,
				&task->tv,
				task->ev_base);
	}
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
	gint nfd, http_opts = 0;

	ctx = worker->ctx;

	if (ctx->max_tasks != 0 && worker->nconns > ctx->max_tasks) {
		msg_info_ctx ("current tasks is now: %uD while maximum is: %uD",
				worker->nconns,
			ctx->max_tasks);
		return;
	}

	if ((nfd =
		rspamd_accept_from_socket (fd, &addr, worker->accept_events)) == -1) {
		msg_warn_ctx ("accept failed: %s", strerror (errno));
		return;
	}
	/* Check for EAGAIN */
	if (nfd == 0) {
		return;
	}

	task = rspamd_task_new (worker, ctx->cfg, NULL, ctx->lang_det, ctx->ev_base);

	msg_info_task ("accepted connection from %s port %d, task ptr: %p",
		rspamd_inet_address_to_string (addr),
		rspamd_inet_address_get_port (addr),
		task);

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
	/* TODO: allow to disable autolearn in protocol */
	task->flags |= RSPAMD_TASK_FLAG_LEARN_AUTO;

	if (ctx->encrypted_only && !rspamd_inet_address_is_local (addr, FALSE)) {
		http_opts = RSPAMD_HTTP_REQUIRE_ENCRYPTION;
	}

	task->http_conn = rspamd_http_connection_new (rspamd_worker_body_handler,
			rspamd_worker_error_handler,
			rspamd_worker_finish_handler,
			http_opts,
			RSPAMD_HTTP_SERVER,
			ctx->keys_cache,
			NULL);
	rspamd_http_connection_set_max_size (task->http_conn, task->cfg->max_message);
	worker->nconns++;
	rspamd_mempool_add_destructor (task->task_pool,
		(rspamd_mempool_destruct_t)reduce_tasks_count, worker);

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
		gint attached_fd,
		struct rspamd_control_command *cmd,
		gpointer ud)
{
	struct rspamd_control_reply rep;
	struct rspamd_re_cache *cache = worker->srv->cfg->re_cache;

	memset (&rep, 0, sizeof (rep));
	rep.type = RSPAMD_CONTROL_HYPERSCAN_LOADED;

	if (!rspamd_re_cache_is_hs_loaded (cache) || cmd->cmd.hs_loaded.forced) {
		msg_info ("loading hyperscan expressions after receiving compilation "
				"notice: %s",
				(!rspamd_re_cache_is_hs_loaded (cache)) ?
						"new db" : "forced update");
		rep.reply.hs_loaded.status = rspamd_re_cache_load_hyperscan (
				worker->srv->cfg->re_cache, cmd->cmd.hs_loaded.cache_dir);
	}

	if (write (fd, &rep, sizeof (rep)) != sizeof (rep)) {
		msg_err ("cannot write reply to the control socket: %s",
				strerror (errno));
	}

	return TRUE;
}
#endif

static gboolean
rspamd_worker_log_pipe_handler (struct rspamd_main *rspamd_main,
		struct rspamd_worker *worker, gint fd,
		gint attached_fd,
		struct rspamd_control_command *cmd,
		gpointer ud)
{
	struct rspamd_config *cfg = ud;
	struct rspamd_worker_log_pipe *lp;
	struct rspamd_control_reply rep;

	memset (&rep, 0, sizeof (rep));
	rep.type = RSPAMD_CONTROL_LOG_PIPE;

	if (attached_fd != -1) {
		lp = g_malloc0 (sizeof (*lp));
		lp->fd = attached_fd;
		lp->type = cmd->cmd.log_pipe.type;

		DL_APPEND (cfg->log_pipes, lp);
		msg_info ("added new log pipe");
	}
	else {
		rep.reply.log_pipe.status = ENOENT;
		msg_err ("cannot attach log pipe: invalid fd");
	}

	if (write (fd, &rep, sizeof (rep)) != sizeof (rep)) {
		msg_err ("cannot write reply to the control socket: %s",
				strerror (errno));
	}

	return TRUE;
}

static gboolean
rspamd_worker_monitored_handler (struct rspamd_main *rspamd_main,
		struct rspamd_worker *worker, gint fd,
		gint attached_fd,
		struct rspamd_control_command *cmd,
		gpointer ud)
{
	struct rspamd_control_reply rep;
	struct rspamd_monitored *m;
	struct rspamd_monitored_ctx *mctx = worker->srv->cfg->monitored_ctx;
	struct rspamd_config *cfg = ud;

	memset (&rep, 0, sizeof (rep));
	rep.type = RSPAMD_CONTROL_MONITORED_CHANGE;

	if (cmd->cmd.monitored_change.sender != getpid ()) {
		m = rspamd_monitored_by_tag (mctx, cmd->cmd.monitored_change.tag);

		if (m != NULL) {
			rspamd_monitored_set_alive (m, cmd->cmd.monitored_change.alive);
			rep.reply.monitored_change.status = 1;
			msg_info_config ("updated monitored status for %s: %s",
					cmd->cmd.monitored_change.tag,
					cmd->cmd.monitored_change.alive ? "alive" : "dead");
		} else {
			msg_err ("cannot find monitored by tag: %*s", 32,
					cmd->cmd.monitored_change.tag);
			rep.reply.monitored_change.status = 0;
		}
	}

	if (write (fd, &rep, sizeof (rep)) != sizeof (rep)) {
		msg_err ("cannot write reply to the control socket: %s",
				strerror (errno));
	}

	return TRUE;
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
			"Deprecated: always true now");


	rspamd_rcl_register_worker_option (cfg,
			type,
			"timeout",
			rspamd_rcl_parse_struct_time,
			ctx,
			G_STRUCT_OFFSET (struct rspamd_worker_ctx,
						timeout),
			RSPAMD_CL_FLAG_TIME_INTEGER,
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

static gboolean
rspamd_worker_on_terminate (struct rspamd_worker *worker)
{
	if (worker->nconns == 0) {
		msg_info ("performing finishing actions");
		if (rspamd_worker_call_finish_handlers (worker)) {
			return TRUE;
		}
	}

	return FALSE;
}

void
rspamd_worker_init_scanner (struct rspamd_worker *worker,
		struct event_base *ev_base,
		struct rspamd_dns_resolver *resolver,
		struct rspamd_lang_detector **plang_det)
{
	rspamd_stat_init (worker->srv->cfg, ev_base);
	g_ptr_array_add (worker->finish_actions,
			(gpointer) rspamd_worker_on_terminate);
#ifdef WITH_HYPERSCAN
	rspamd_control_worker_add_cmd_handler (worker,
			RSPAMD_CONTROL_HYPERSCAN_LOADED,
			rspamd_worker_hyperscan_ready,
			NULL);
#endif
	rspamd_control_worker_add_cmd_handler (worker,
			RSPAMD_CONTROL_LOG_PIPE,
			rspamd_worker_log_pipe_handler,
			worker->srv->cfg);
	rspamd_control_worker_add_cmd_handler (worker,
			RSPAMD_CONTROL_MONITORED_CHANGE,
			rspamd_worker_monitored_handler,
			worker->srv->cfg);

	*plang_det = worker->srv->cfg->lang_det;
}

/*
 * Start worker process
 */
void
start_worker (struct rspamd_worker *worker)
{
	struct rspamd_worker_ctx *ctx = worker->ctx;

	ctx->cfg = worker->srv->cfg;
	ctx->ev_base = rspamd_prepare_worker (worker, "normal", accept_socket);
	msec_to_tv (ctx->timeout, &ctx->io_tv);
	rspamd_symcache_start_refresh (worker->srv->cfg->cache, ctx->ev_base,
			worker);

	if (isnan (ctx->task_timeout)) {
		if (isnan (ctx->cfg->task_timeout)) {
			ctx->task_timeout = 0;
		}
		else {
			ctx->task_timeout = ctx->cfg->task_timeout;
		}
	}

	ctx->resolver = dns_resolver_init (worker->srv->logger,
			ctx->ev_base,
			worker->srv->cfg);
	rspamd_map_watch (worker->srv->cfg, ctx->ev_base, ctx->resolver, worker, 0);
	rspamd_upstreams_library_config (worker->srv->cfg, ctx->cfg->ups_ctx,
			ctx->ev_base, ctx->resolver->r);

	/* XXX: stupid default */
	ctx->keys_cache = rspamd_keypair_cache_new (256);
	rspamd_worker_init_scanner (worker, ctx->ev_base, ctx->resolver,
			&ctx->lang_det);
	rspamd_lua_run_postloads (ctx->cfg->lua_state, ctx->cfg, ctx->ev_base,
			worker);

	event_base_loop (ctx->ev_base, 0);
	rspamd_worker_block_signals ();

	rspamd_stat_close ();
	rspamd_keypair_cache_destroy (ctx->keys_cache);
	REF_RELEASE (ctx->cfg);
	rspamd_log_close (worker->srv->logger, TRUE);

	exit (EXIT_SUCCESS);
}
