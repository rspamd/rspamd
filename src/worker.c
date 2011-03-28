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
#include "modules.h"
#include "message.h"
#include "map.h"
#include "dns.h"

#include "lua/lua_common.h"

#ifndef WITHOUT_PERL
#   include <EXTERN.h>		/* from the Perl distribution     */
#   include <perl.h>		/* from the Perl distribution   */

extern PerlInterpreter         *perl_interpreter;
#endif

#ifdef WITH_GPERF_TOOLS
#   include <glib/gprintf.h>
#endif

/* 60 seconds for worker's IO */
#define DEFAULT_WORKER_IO_TIMEOUT 60000

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
	/* Detect whether this worker is mime worker */
	gboolean                        is_mime;
	/* Detect whether this worker is mime worker */
	gboolean                        is_custom;
	GList                          *custom_filters;
	/* DNS resolver */
	struct rspamd_dns_resolver     *resolver;
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
	case SIGUSR1:
		reopen_log ();
		break;
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
sigusr_handler (gint fd, short what, void *arg)
{
	struct rspamd_worker           *worker = (struct rspamd_worker *) arg;
	/* Do not accept new connections, preparing to end worker's process */
	struct timeval                  tv;

	if (!wanna_die) {
		tv.tv_sec = SOFT_SHUTDOWN_TIME;
		tv.tv_usec = 0;
		event_del (&worker->sig_ev);
		event_del (&worker->bind_ev);
		do_reopen_log = 1;
		msg_info ("worker's shutdown is pending in %d sec", SOFT_SHUTDOWN_TIME);
		event_loopexit (&tv);
	}
	return;
}

/*
 * Destructor for recipients list
 */
static void
rcpt_destruct (void *pointer)
{
	struct worker_task             *task = (struct worker_task *) pointer;

	if (task->rcpt) {
		g_list_free (task->rcpt);
	}
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
 * Free all structures of worker_task
 */
void
free_task (struct worker_task *task, gboolean is_soft)
{
	GList                          *part;
	struct mime_part               *p;

	if (task) {
		debug_task ("free pointer %p", task);
		while ((part = g_list_first (task->parts))) {
			task->parts = g_list_remove_link (task->parts, part);
			p = (struct mime_part *) part->data;
			g_byte_array_free (p->content, TRUE);
			g_list_free_1 (part);
		}
		if (task->text_parts) {
			g_list_free (task->text_parts);
		}
		if (task->images) {
			g_list_free (task->images);
		}
		if (task->messages) {
			g_list_free (task->messages);
		}
		if (task->received) {
			g_list_free (task->received);
		}
		memory_pool_delete (task->task_pool);
		if (task->dispatcher) {
			if (is_soft) {
				/* Plan dispatcher shutdown */
				task->dispatcher->wanna_die = 1;
			}
			else {
				rspamd_remove_dispatcher (task->dispatcher);
			}
		}
		if (task->sock != -1) {
			close (task->sock);
		}
		g_free (task);
	}
}

void
free_task_hard (gpointer ud)
{
  struct worker_task             *task = ud;

  free_task (task, FALSE);
}

void
free_task_soft (gpointer ud)
{
  struct worker_task             *task = ud;

  free_task (task, FALSE);
}

/*
 * Callback that is called when there is data to read in buffer
 */
static                          gboolean
read_socket (f_str_t * in, void *arg)
{
	struct worker_task             *task = (struct worker_task *) arg;
	struct rspamd_worker_ctx       *ctx;
	ssize_t                         r;

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
			if (read_rspamd_input_line (task, in) != 0) {
				task->last_error = "Read error";
				task->error_code = RSPAMD_NETWORK_ERROR;
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
		r = process_filters (task);
		if (r == -1) {
			task->last_error = "Filter processing error";
			task->error_code = RSPAMD_FILTER_ERROR;
			task->state = WRITE_ERROR;
			return write_socket (task);
		}
		else if (r == 0) {
			task->state = WAIT_FILTER;
			rspamd_dispatcher_pause (task->dispatcher);
		}
		else {
			process_statfiles (task);
			lua_call_post_filters (task);
			task->state = WRITE_REPLY;
			return write_socket (task);
		}
		break;
	case WRITE_REPLY:
	case WRITE_ERROR:
		return write_socket (task);
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

	ctx = task->worker->ctx;

	switch (task->state) {
	case WRITE_REPLY:
		if (!write_reply (task)) {
			destroy_session (task->s);
			return FALSE;
		}
		if (ctx->is_custom) {
			fin_custom_filters (task);
		}
		destroy_session (task->s);
		return FALSE;
		break;
	case WRITE_ERROR:
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
	default:
		msg_info ("abnormally closing connection");
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
	if (task->state != WRITE_REPLY) {
		destroy_session (task->s);
	}
}

/* Compare two emails for building emails tree */
static gint
compare_email_func (gconstpointer a, gconstpointer b)
{
	const struct uri               *u1 = a, *u2 = b;
	gint                            r;

	if (u1->hostlen != u2->hostlen || u1->hostlen == 0) {
		return u1->hostlen - u2->hostlen;
	}
	else {
		if ((r = g_ascii_strncasecmp (u1->host, u2->host, u1->hostlen)) == 0){
			if (u1->userlen != u2->userlen || u1->userlen == 0) {
				return u1->userlen - u2->userlen;
			}
			else {
				return g_ascii_strncasecmp (u1->user, u2->user, u1->userlen);
			}
		}
		else {
			return r;
		}
	}

	return 0;
}

static gint
compare_url_func (gconstpointer a, gconstpointer b)
{
	const struct uri               *u1 = a, *u2 = b;
	int                             r;

	if (u1->hostlen != u2->hostlen || u1->hostlen == 0) {
		return u1->hostlen - u2->hostlen;
	}
	else {
		r = g_ascii_strncasecmp (u1->host, u2->host, u1->hostlen);
	}

	return r;
}

/*
 * Create new task
 */
struct worker_task             *
construct_task (struct rspamd_worker *worker)
{
	struct worker_task             *new_task;

	new_task = g_malloc (sizeof (struct worker_task));

	bzero (new_task, sizeof (struct worker_task));
	new_task->worker = worker;
	new_task->state = READ_COMMAND;
	new_task->cfg = worker->srv->cfg;
	new_task->from_addr.s_addr = INADDR_NONE;
	new_task->view_checked = FALSE;
#ifdef HAVE_CLOCK_GETTIME
# ifdef HAVE_CLOCK_PROCESS_CPUTIME_ID
	clock_gettime (CLOCK_PROCESS_CPUTIME_ID, &new_task->ts);
# elif defined(HAVE_CLOCK_VIRTUAL)
	clock_gettime (CLOCK_VIRTUAL, &new_task->ts);
# else
	clock_gettime (CLOCK_REALTIME, &new_task->ts);
# endif
#endif
	if (gettimeofday (&new_task->tv, NULL) == -1) {
		msg_warn ("gettimeofday failed: %s", strerror (errno));
	}

	new_task->task_pool = memory_pool_new (memory_pool_get_size ());

	/* Add destructor for recipients list (it would be better to use anonymous function here */
	memory_pool_add_destructor (new_task->task_pool,
			(pool_destruct_func) rcpt_destruct, new_task);
	new_task->results = g_hash_table_new (g_str_hash, g_str_equal);
	memory_pool_add_destructor (new_task->task_pool,
			(pool_destruct_func) g_hash_table_destroy,
			new_task->results);
	new_task->re_cache = g_hash_table_new (g_str_hash, g_str_equal);
	memory_pool_add_destructor (new_task->task_pool,
			(pool_destruct_func) g_hash_table_destroy,
			new_task->re_cache);
	new_task->emails = g_tree_new (compare_email_func);
	memory_pool_add_destructor (new_task->task_pool,
				(pool_destruct_func) g_tree_destroy,
				new_task->emails);
	new_task->urls = g_tree_new (compare_url_func);
	memory_pool_add_destructor (new_task->task_pool,
					(pool_destruct_func) g_tree_destroy,
					new_task->urls);
	new_task->s =
			new_async_session (new_task->task_pool, free_task_hard, new_task);
	new_task->sock = -1;
	new_task->is_mime = TRUE;

	return new_task;
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

	new_task->sock = nfd;
	new_task->is_mime = ctx->is_mime;
	worker->srv->stat->connections_count++;
	new_task->resolver = ctx->resolver;
	msec_to_tv (ctx->timeout, &ctx->io_tv);

	/* Set up dispatcher */
	new_task->dispatcher =
			rspamd_create_dispatcher (nfd, BUFFER_LINE, read_socket, write_socket,
					err_socket, &ctx->io_tv, (void *) new_task);
	new_task->dispatcher->peer_addr = new_task->client_addr.s_addr;

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

	for (i = 0; i < gp.gl_pathc; i++) {
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

	ctx = g_malloc0 (sizeof (struct rspamd_worker_ctx));

	ctx->is_mime = TRUE;
	ctx->timeout = DEFAULT_WORKER_IO_TIMEOUT;

	register_worker_opt (TYPE_WORKER, "mime", xml_handle_boolean, ctx, G_STRUCT_OFFSET (struct rspamd_worker_ctx, is_mime));
	register_worker_opt (TYPE_WORKER, "timeout", xml_handle_seconds, ctx, G_STRUCT_OFFSET (struct rspamd_worker_ctx, timeout));

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

#ifdef WITH_PROFILER
	extern void                     _start (void), etext (void);
	monstartup ((u_long) & _start, (u_long) & etext);
#endif

	gperf_profiler_init (worker->srv->cfg, "worker");

	worker->srv->pid = getpid ();

	event_init ();

	init_signals (&signals, sig_handler);
	sigprocmask (SIG_UNBLOCK, &signals.sa_mask, NULL);

	/* SIGUSR2 handler */
	signal_set (&worker->sig_ev, SIGUSR2, sigusr_handler, (void *) worker);
	signal_add (&worker->sig_ev, NULL);

	/* Accept event */
	event_set (&worker->bind_ev, worker->cf->listen_sock, EV_READ | EV_PERSIST,
			accept_socket, (void *) worker);
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
		start_map_watch ();
#ifndef BUILD_STATIC
	}
#endif

	ctx->resolver = dns_resolver_init (worker->srv->cfg);

	event_loop (0);

#ifndef BUILD_STATIC
	if (ctx->is_custom) {
		unload_custom_filters (ctx);
	}
#endif

	close_log ();
	exit (EXIT_SUCCESS);
}

/* 
 * vi:ts=4 
 */
