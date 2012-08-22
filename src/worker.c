/*
 * Copyright (c) 2009, Rambler media
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
 * THIS SOFTWARE IS PROVIDED BY Rambler media ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Rambler BE LIABLE FOR ANY
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

gpointer init_worker (void);
void start_worker (struct rspamd_worker *worker);

worker_t normal_worker = {
	"normal",					/* Name */
	init_worker,				/* Init function */
	start_worker,				/* Start function */
	TRUE,						/* Has socket */
	FALSE,						/* Non unique */
	FALSE,						/* Non threaded */
	TRUE						/* Killable */
};

#ifndef BUILD_STATIC

#define MODULE_INIT_FUNC "module_init"
#define MODULE_FINIT_FUNC "module_fin"
#define MODULE_BEFORE_CONNECT_FUNC "before_connect"
#define MODULE_AFTER_CONNECT_FUNC "after_connect"
#define MODULE_PARSE_LINE_FUNC "parse_line"

struct custom_filter {
	gchar                          *filename;	/*< filename           */
	GModule                        *handle;	/*< returned by dlopen */
	void                            (*init_func) (struct config_file * cfg);	/*< called at start of worker */
	void                           *(*before_connect) (void);	/*< called when clients connects */
	gboolean (*process_line) (const gchar * line, size_t len, gchar ** output, void *user_data);	/*< called when client send data line */
	void                            (*after_connect) (gchar ** output, gchar ** log_line, void *user_data);	/*< called when client disconnects */
	void                            (*fin_func) (void);
};

#endif

/*
 * Worker's context
 */
struct rspamd_worker_ctx {
	guint32                         timeout;
	struct timeval                  io_tv;
	/* Detect whether this worker is mime worker 	*/
	gboolean                        is_mime;
	/* Detect whether this worker is custom worker 	*/
	gboolean                        is_custom;
	/* HTTP worker									*/
	gboolean                        is_http;
	/* JSON output     								*/
	gboolean                        is_json;
	/* Allow learning throught worker				*/
	gboolean                        allow_learn;
	GList                          *custom_filters;
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

static gboolean                 write_socket (void *arg);

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

#ifndef BUILD_STATIC
static void
fin_custom_filters (struct worker_task *task)
{
	GList                          *cur, *curd;
	struct custom_filter           *filt;
	gchar                          *output = NULL, *log = NULL;
	struct rspamd_worker_ctx       *ctx = task->worker->ctx;

	cur = ctx->custom_filters;
	curd = task->rcpt;
	while (cur) {
		filt = cur->data;
		if (filt->after_connect) {
			filt->after_connect (&output, &log, curd->data);
			if (output != NULL) {
				if (!rspamd_dispatcher_write
						(task->dispatcher, output, strlen (output), FALSE, FALSE)){
					g_free (output);
					return;
				}
				g_free (output);
			}
			if (log != NULL) {
				msg_info ("%s", log);
				g_free (log);
			}
			if (curd->next) {
				curd = g_list_next (curd);
			}
		}
		cur = g_list_next (cur);
	}
}

static                          gboolean
parse_line_custom (struct worker_task *task, f_str_t * in)
{
	GList                          *cur, *curd;
	struct custom_filter           *filt;
	gchar                          *output = NULL;
	gboolean                        res = TRUE;
	struct rspamd_worker_ctx       *ctx = task->worker->ctx;

	cur = ctx->custom_filters;
	curd = task->rcpt;
	while (cur) {
		filt = cur->data;
		if (filt->after_connect) {
			if (!filt->process_line (in->begin, in->len, &output, curd->data)) {
				res = FALSE;
			}
			if (output != NULL) {
				if (!rspamd_dispatcher_write
						(task->dispatcher, output, strlen (output), FALSE, FALSE)) {
					g_free (output);
					return FALSE;
				}
				g_free (output);
			}
			if (curd->next) {
				curd = g_list_next (curd);
			}
		}
		cur = g_list_next (cur);
	}

	return res;
}
#else
/* Stubs */
static void
fin_custom_filters (struct worker_task *task)
{

}

static                          gboolean
parse_line_custom (struct worker_task *task, f_str_t * in)
{
  return FALSE;
}
#endif


/*
 * Callback that is called when there is data to read in buffer
 */
static                          gboolean
read_socket (f_str_t * in, void *arg)
{
	struct worker_task             *task = (struct worker_task *) arg;
	struct rspamd_worker_ctx       *ctx;
	ssize_t                         r;
	GError                         *err = NULL;

	ctx = task->worker->ctx;
	switch (task->state) {
	case READ_COMMAND:
	case READ_HEADER:
		if (ctx->is_custom) {
			if (!parse_line_custom (task, in)) {
				task->last_error = "Read error";
				task->error_code = RSPAMD_NETWORK_ERROR;
				task->state = WRITE_ERROR;
			}
		}
		else {
			if (!read_rspamd_input_line (task, in)) {
				if (!task->last_error) {
					task->last_error = "Read error";
					task->error_code = RSPAMD_NETWORK_ERROR;
				}
				task->state = WRITE_ERROR;
			}
		}
		if (task->state == WRITE_REPLY || task->state == WRITE_ERROR) {
			return write_socket (task);
		}
		break;
	case READ_MESSAGE:
		task->msg = memory_pool_alloc (task->task_pool, sizeof (f_str_t));
		task->msg->begin = in->begin;
		task->msg->len = in->len;
		debug_task ("got string of length %z", task->msg->len);
		task->state = WAIT_FILTER;
		/* No more need of reading allowing half-closed connections to be proceed */
		task->dispatcher->want_read = FALSE;
		r = process_message (task);
		if (r == -1) {
			msg_warn ("processing of message failed");
			task->last_error = "MIME processing error";
			task->error_code = RSPAMD_FILTER_ERROR;
			task->state = WRITE_ERROR;
			return write_socket (task);
		}
		if (task->cmd == CMD_OTHER) {
			/* Skip filters */
			task->state = WRITE_REPLY;
			return write_socket (task);
		}
		else if (task->cmd == CMD_LEARN) {
			if (!learn_task (task->statfile, task, &err)) {
				task->last_error = memory_pool_strdup (task->task_pool, err->message);
				task->error_code = err->code;
				g_error_free (err);
				task->state = WRITE_ERROR;
			}
			else {
				task->last_error = "learn ok";
				task->error_code = 0;
				task->state = WRITE_REPLY;
			}
			return write_socket (task);
		}
		else {
			if (task->cfg->pre_filters == NULL) {
				r = process_filters (task);
				if (r == -1) {
					task->last_error = "Filter processing error";
					task->error_code = RSPAMD_FILTER_ERROR;
					task->state = WRITE_ERROR;
					return write_socket (task);
				}
				/* Add task to classify to classify pool */
				if (ctx->classify_pool) {
					register_async_thread (task->s);
					g_thread_pool_push (ctx->classify_pool, task, &err);
					if (err != NULL) {
						msg_err ("cannot pull task to the pool: %s", err->message);
						remove_async_thread (task->s);
					}
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
		break;
	case WRITE_REPLY:
	case WRITE_ERROR:
		return write_socket (task);
		break;
	case WAIT_FILTER:
	case WAIT_POST_FILTER:
	case WAIT_PRE_FILTER:
		msg_info ("ignoring trailing garbadge of size %z", in->len);
		break;
	default:
		debug_task ("invalid state on reading stage");
		break;
	}

	return TRUE;
}

/*
 * Callback for socket writing
 */
static                          gboolean
write_socket (void *arg)
{
	struct worker_task             *task = (struct worker_task *) arg;
	struct rspamd_worker_ctx       *ctx;
	GError							*err = NULL;
	gint							 r;

	ctx = task->worker->ctx;

	switch (task->state) {
	case WRITE_REPLY:
		task->state = WRITING_REPLY;
		if (!write_reply (task)) {
			return FALSE;
		}
		if (ctx->is_custom) {
			fin_custom_filters (task);
		}
		destroy_session (task->s);
		return FALSE;
		break;
	case WRITE_ERROR:
		task->state = WRITING_REPLY;
		if (!write_reply (task)) {
			return FALSE;
		}
		if (ctx->is_custom) {
			fin_custom_filters (task);
		}
		destroy_session (task->s);
		return FALSE;
		break;
	case CLOSING_CONNECTION:
		debug_task ("normally closing connection");
		if (ctx->is_custom) {
			fin_custom_filters (task);
		}
		destroy_session (task->s);
		return FALSE;
		break;
	case WRITING_REPLY:
	case WAIT_FILTER:
	case WAIT_POST_FILTER:
		/* Do nothing here */
		break;
	case WAIT_PRE_FILTER:
		task->state = WAIT_FILTER;
		r = process_filters (task);
		if (r == -1) {
			task->last_error = "Filter processing error";
			task->error_code = RSPAMD_FILTER_ERROR;
			task->state = WRITE_ERROR;
			return write_socket (task);
		}
		/* Add task to classify to classify pool */
		if (ctx->classify_pool) {
			register_async_thread (task->s);
			g_thread_pool_push (ctx->classify_pool, task, &err);
			if (err != NULL) {
				msg_err ("cannot pull task to the pool: %s", err->message);
				remove_async_thread (task->s);
			}
		}
		break;
	default:
		msg_info ("abnormally closing connection at state: %d", task->state);
		if (ctx->is_custom) {
			fin_custom_filters (task);
		}
		destroy_session (task->s);
		return FALSE;
		break;
	}
	return TRUE;
}

/*
 * Called if something goes wrong
 */
static void
err_socket (GError * err, void *arg)
{
	struct worker_task             *task = (struct worker_task *) arg;
	struct rspamd_worker_ctx       *ctx;

	ctx = task->worker->ctx;

	msg_info ("abnormally closing connection from: %s, error: %s", inet_ntoa (task->client_addr), err->message);
	/* Free buffers */
	if (ctx->is_custom) {
		fin_custom_filters (task);
	}
	g_error_free (err);
	destroy_session (task->s);
}

/*
 * Called if all filters are processed
 */
static gboolean
fin_task (void *arg)
{
	struct worker_task              *task = (struct worker_task *) arg;
	struct rspamd_worker_ctx        *ctx;


	ctx = task->worker->ctx;
	if (task->state != WAIT_POST_FILTER && task->state != WAIT_PRE_FILTER) {
		/* Process all statfiles */
		if (ctx->classify_pool == NULL) {
			/* Non-threaded version */
			process_statfiles (task);
		}
		else {
			/* Just process composites */
			make_composites (task);
		}
		if (task->cfg->post_filters) {
			/* More to process */
			/* Special state */
			task->state = WAIT_POST_FILTER;
			return FALSE;
		}

	}

	if (task->state != WAIT_PRE_FILTER) {
		/* Check if we have all events finished */
		task->state = WRITE_REPLY;
		if (task->fin_callback) {
			task->fin_callback (task->fin_arg);
		}
		else {
			rspamd_dispatcher_restore (task->dispatcher);
		}
	}
	else {
		if (task->pre_result.action != METRIC_ACTION_NOACTION) {
			/* Write result based on pre filters */
			task->state = WRITE_REPLY;
			if (task->fin_callback) {
				task->fin_callback (task->fin_arg);
			}
			else {
				rspamd_dispatcher_restore (task->dispatcher);
			}
		}
		else {
			/* Check normal filters in write callback */
			rspamd_dispatcher_restore (task->dispatcher);
		}
	}

	return TRUE;
}

/*
 * Called if session was restored inside fin callback
 */
static void
restore_task (void *arg)
{
	struct worker_task             *task = (struct worker_task *) arg;

	/* Call post filters */
	lua_call_post_filters (task);
	task->s->wanna_die = TRUE;
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
	GList                          *cur;
	struct custom_filter           *filt;

	socklen_t                       addrlen = sizeof (su.ss);
	gint                            nfd;

	ctx = worker->ctx;

	if (ctx->max_tasks != 0 && ctx->tasks > ctx->max_tasks) {
		msg_info ("current tasks is now: %uD while maximum is: %uD", ctx->tasks, ctx->max_tasks);
		return;
	}

	if ((nfd =
			accept_from_socket (fd, (struct sockaddr *) &su.ss, &addrlen)) == -1) {
		msg_warn ("accept failed: %s", strerror (errno));
		return;
	}
	/* Check for EAGAIN */
	if (nfd == 0){
		return;
	}

	new_task = construct_task (worker);

	if (su.ss.ss_family == AF_UNIX) {
		msg_info ("accepted connection from unix socket");
		new_task->client_addr.s_addr = INADDR_NONE;
	}
	else if (su.ss.ss_family == AF_INET) {
		msg_info ("accepted connection from %s port %d",
				inet_ntoa (su.s4.sin_addr), ntohs (su.s4.sin_port));
		memcpy (&new_task->client_addr, &su.s4.sin_addr,
				sizeof (struct in_addr));
	}

	/* Copy some variables */
	new_task->sock = nfd;
	new_task->is_mime = ctx->is_mime;
	new_task->is_json = ctx->is_json;
	new_task->is_http = ctx->is_http;
	new_task->allow_learn = ctx->allow_learn;

	worker->srv->stat->connections_count++;
	new_task->resolver = ctx->resolver;
	msec_to_tv (ctx->timeout, &ctx->io_tv);

	/* Set up dispatcher */
	new_task->dispatcher =
			rspamd_create_dispatcher (ctx->ev_base, nfd, BUFFER_LINE, read_socket, write_socket,
					err_socket, &ctx->io_tv, (void *) new_task);
	new_task->dispatcher->peer_addr = new_task->client_addr.s_addr;
	new_task->ev_base = ctx->ev_base;
	ctx->tasks ++;
	memory_pool_add_destructor (new_task->task_pool, (pool_destruct_func)reduce_tasks_count, &ctx->tasks);

	/* Set up async session */
	new_task->s =
				new_async_session (new_task->task_pool, fin_task, restore_task, free_task_hard, new_task);

	/* Init custom filters */
#ifndef BUILD_STATIC
	if (ctx->is_custom) {
		cur = ctx->custom_filters;
		while (cur) {
			filt = cur->data;
			if (filt->before_connect) {
				/* XXX: maybe not use rcpt list here for custom filters data, but this can save some bytes in task structure */
				new_task->rcpt =
						g_list_prepend (new_task->rcpt, filt->before_connect ());
			}
			cur = g_list_next (cur);
		}
		/* Keep user data in the same order as custom filters */
		new_task->rcpt = g_list_reverse (new_task->rcpt);
	}
#endif
}

#ifndef BUILD_STATIC
static                          gboolean
load_custom_filter (struct config_file *cfg, const gchar * file,
		struct rspamd_worker_ctx *ctx)
{
	struct custom_filter           *filt;
	struct stat                     st;

	if (stat (file, &st) == -1 || !S_ISREG (st.st_mode)) {
		msg_info ("stat failed for %s", file);
		return FALSE;
	}

	filt = g_malloc (sizeof (struct custom_filter));

	filt->handle = g_module_open (file, G_MODULE_BIND_LAZY);
	if (!filt->handle) {
		msg_info ("module load failed: %s", g_module_error ());
		g_free (filt);
		return FALSE;
	}

	/* Now extract functions from custom module */
	if (!g_module_symbol
			(filt->handle, MODULE_INIT_FUNC, (gpointer *) & filt->init_func)
			|| !g_module_symbol (filt->handle, MODULE_FINIT_FUNC,
					(gpointer *) & filt->fin_func)
					|| !g_module_symbol (filt->handle, MODULE_BEFORE_CONNECT_FUNC,
							(gpointer *) & filt->before_connect)
							|| !g_module_symbol (filt->handle, MODULE_AFTER_CONNECT_FUNC,
									(gpointer *) & filt->after_connect)
									|| !g_module_symbol (filt->handle, MODULE_PARSE_LINE_FUNC,
											(gpointer *) & filt->process_line)) {

		msg_info ("cannot find handlers in module %s: %s", file,
				g_module_error ());
		g_free (filt);
		return FALSE;
	}

	filt->init_func (cfg);
	filt->filename = g_strdup (file);
	ctx->custom_filters = g_list_prepend (ctx->custom_filters, filt);

	return TRUE;
}

/*
 * Load custom filters from specified path
 */
static                          gboolean
load_custom_filters (struct rspamd_worker *worker, const gchar * path)
{
	glob_t                          gp;
	gint                            r, i;
	struct rspamd_worker_ctx       *ctx = worker->ctx;

	gp.gl_offs = 0;
	if ((r = glob (path, GLOB_NOSORT, NULL, &gp)) != 0) {
		msg_warn ("glob failed: %s, %d", strerror (errno), r);
		return FALSE;
	}

	for (i = 0; i < (gint)gp.gl_pathc; i++) {
		if (!load_custom_filter (worker->srv->cfg, gp.gl_pathv[i], ctx)) {
			globfree (&gp);
			return FALSE;
		}
	}

	globfree (&gp);

	return TRUE;
}

static void
unload_custom_filters (struct rspamd_worker_ctx *ctx)
{
	GList                          *cur;
	struct custom_filter           *filt;

	cur = ctx->custom_filters;
	while (cur) {
		filt = cur->data;
		if (filt->fin_func) {
			filt->fin_func ();
		}
		g_module_close (filt->handle);
		g_free (filt);
		cur = g_list_next (cur);
	}

	g_list_free (ctx->custom_filters);
}

#endif

gpointer
init_worker (void)
{
	struct rspamd_worker_ctx       *ctx;
	GQuark								type;

	type = g_quark_try_string ("normal");

	ctx = g_malloc0 (sizeof (struct rspamd_worker_ctx));

	ctx->is_mime = TRUE;
	ctx->timeout = DEFAULT_WORKER_IO_TIMEOUT;
	ctx->classify_threads = 1;

	register_worker_opt (type, "mime", xml_handle_boolean, ctx, G_STRUCT_OFFSET (struct rspamd_worker_ctx, is_mime));
	register_worker_opt (type, "http", xml_handle_boolean, ctx, G_STRUCT_OFFSET (struct rspamd_worker_ctx, is_http));
	register_worker_opt (type, "json", xml_handle_boolean, ctx, G_STRUCT_OFFSET (struct rspamd_worker_ctx, is_json));
	register_worker_opt (type, "allow_learn", xml_handle_boolean, ctx, G_STRUCT_OFFSET (struct rspamd_worker_ctx, allow_learn));
	register_worker_opt (type, "timeout", xml_handle_seconds, ctx, G_STRUCT_OFFSET (struct rspamd_worker_ctx, timeout));
	register_worker_opt (type, "max_tasks", xml_handle_uint32, ctx, G_STRUCT_OFFSET (struct rspamd_worker_ctx, max_tasks));
	register_worker_opt (type, "classify_threads", xml_handle_uint32, ctx, G_STRUCT_OFFSET (struct rspamd_worker_ctx, classify_threads));

	return ctx;
}

/*
 * Start worker process
 */
void
start_worker (struct rspamd_worker *worker)
{
	struct sigaction                signals;
	gchar                          *is_custom_str;
	struct rspamd_worker_ctx       *ctx = worker->ctx;
	GError						   *err = NULL;
	struct lua_locked_state		   *nL;

#ifdef WITH_PROFILER
	extern void                     _start (void), etext (void);
	monstartup ((u_long) & _start, (u_long) & etext);
#endif

	gperf_profiler_init (worker->srv->cfg, "worker");

	worker->srv->pid = getpid ();

	ctx->ev_base = event_init ();

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
	event_set (&worker->bind_ev, worker->cf->listen_sock, EV_READ | EV_PERSIST,
			accept_socket, (void *) worker);
	event_base_set (ctx->ev_base, &worker->bind_ev);
	event_add (&worker->bind_ev, NULL);


#ifndef BUILD_STATIC
	/* Check if this worker is not usual rspamd worker, but uses custom filters from specified path */
	is_custom_str = g_hash_table_lookup (worker->cf->params, "custom_filters");
	if (is_custom_str && g_module_supported ()
	&& load_custom_filters (worker, is_custom_str)) {
		msg_info ("starting custom process, loaded modules from %s",
				is_custom_str);
		ctx->is_custom = TRUE;
	}
	else {
#endif
		/* Maps events */
		start_map_watch (ctx->ev_base);
#ifndef BUILD_STATIC
	}
#endif

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

#ifndef BUILD_STATIC
	if (ctx->is_custom) {
		unload_custom_filters (ctx);
	}
#endif

	close_log (rspamd_main->logger);
	exit (EXIT_SUCCESS);
}

/* 
 * vi:ts=4 
 */
