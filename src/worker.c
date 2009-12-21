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
#include "url.h"
#include "modules.h"
#include "message.h"
#include "map.h"

#include <evdns.h>

#ifndef WITHOUT_PERL
#   include <EXTERN.h>			/* from the Perl distribution     */
#   include <perl.h>			/* from the Perl distribution   */

extern PerlInterpreter         *perl_interpreter;
#endif

#ifdef WITH_GPERF_TOOLS
#   include <glib/gprintf.h>
#endif

static struct timeval           io_tv;
/* Detect whether this worker is mime worker */
static gboolean                 is_mime;

static gboolean                 write_socket (void *arg);

#ifndef HAVE_SA_SIGINFO
static void
sig_handler (int signo)
#else
static void
sig_handler (int signo, siginfo_t *info, void *unused)
#endif
{
	switch (signo) {
	case SIGINT:
	case SIGTERM:
		close_log ();
#ifdef WITH_GPERF_TOOLS
		ProfilerStop ();
#endif
#ifdef WITH_PROFILER
		exit (0);
#else
		_exit (1);
#endif
		break;
	}
}

/*
 * Config reload is designed by sending sigusr to active workers and pending shutdown of them
 */
static void
sigusr_handler (int fd, short what, void *arg)
{
	struct rspamd_worker           *worker = (struct rspamd_worker *)arg;
	/* Do not accept new connections, preparing to end worker's process */
	struct timeval                  tv;
	tv.tv_sec = SOFT_SHUTDOWN_TIME;
	tv.tv_usec = 0;
	event_del (&worker->sig_ev);
	event_del (&worker->bind_ev);
	do_reopen_log = 1;
	msg_info ("worker's shutdown is pending in %d sec", SOFT_SHUTDOWN_TIME);
	event_loopexit (&tv);
	return;
}

/*
 * Destructor for recipients list
 */
static void
rcpt_destruct (void *pointer)
{
	struct worker_task             *task = (struct worker_task *)pointer;

	if (task->rcpt) {
		g_list_free (task->rcpt);
	}
}

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
		if (task->memc_ctx) {
			memc_close_ctx (task->memc_ctx);
		}
		while ((part = g_list_first (task->parts))) {
			task->parts = g_list_remove_link (task->parts, part);
			p = (struct mime_part *)part->data;
			g_byte_array_free (p->content, TRUE);
			g_list_free_1 (part);
		}
		if (task->text_parts) {
			g_list_free (task->text_parts);
		}
		if (task->urls) {
			g_list_free (task->urls);
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

static void
free_task_hard (void *ud)
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
	struct worker_task             *task = (struct worker_task *)arg;
	ssize_t                         r;

	switch (task->state) {
	case READ_COMMAND:
	case READ_HEADER:
		if (read_rspamd_input_line (task, in) != 0) {
			task->last_error = "Read error";
			task->error_code = RSPAMD_NETWORK_ERROR;
			task->state = WRITE_ERROR;
		}
		if (task->state == WRITE_REPLY || task->state == WRITE_ERROR) {
			return write_socket (task);
		}
		break;
	case READ_MESSAGE:
		task->msg = memory_pool_alloc (task->task_pool, sizeof (f_str_t));
		task->msg->begin = in->begin;
		task->msg->len = in->len;
		debug_task ("got string of length %ld", (long int)task->msg->len);
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
			return write_socket (task);
		}
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
	struct worker_task             *task = (struct worker_task *)arg;

	switch (task->state) {
	case WRITE_REPLY:
		write_reply (task);
		destroy_session (task->s);
		return FALSE;
		break;
	case WRITE_ERROR:
		write_reply (task);
		destroy_session (task->s);
		return FALSE;
		break;
	case CLOSING_CONNECTION:
		debug_task ("normally closing connection");
		destroy_session (task->s);
		return FALSE;
		break;
	default:
		msg_info ("abnormally closing connection");
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
	struct worker_task             *task = (struct worker_task *)arg;
	msg_info ("abnormally closing connection, error: %s", err->message);
	/* Free buffers */
	destroy_session (task->s);
}

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
#ifdef HAVE_CLOCK_PROCESS_CPUTIME_ID
	clock_gettime (CLOCK_PROCESS_CPUTIME_ID, &new_task->ts);
#elif defined(HAVE_CLOCK_VIRTUAL)
	clock_gettime (CLOCK_VIRTUAL, &new_task->ts);
#else
	clock_gettime (CLOCK_REALTIME, &new_task->ts);
#endif
	io_tv.tv_sec = WORKER_IO_TIMEOUT;
	io_tv.tv_usec = 0;
	new_task->task_pool = memory_pool_new (memory_pool_get_size ());
	/* Add destructor for recipients list (it would be better to use anonymous function here */
	memory_pool_add_destructor (new_task->task_pool, (pool_destruct_func) rcpt_destruct, new_task);
	new_task->results = g_hash_table_new (g_str_hash, g_str_equal);
	memory_pool_add_destructor (new_task->task_pool, (pool_destruct_func) g_hash_table_destroy, new_task->results);
	new_task->re_cache = g_hash_table_new (g_str_hash, g_str_equal);
	memory_pool_add_destructor (new_task->task_pool, (pool_destruct_func) g_hash_table_destroy, new_task->re_cache);
	new_task->s = new_async_session (new_task->task_pool, free_task_hard, new_task);
	new_task->sock = -1;
	new_task->is_mime = TRUE;

	return new_task;
}

/*
 * Accept new connection and construct task
 */
static void
accept_socket (int fd, short what, void *arg)
{
	struct rspamd_worker           *worker = (struct rspamd_worker *)arg;
	struct sockaddr_storage         ss;
	struct sockaddr_in             *sin;
	struct worker_task             *new_task;
	socklen_t                       addrlen = sizeof (ss);
	int                             nfd;

	if ((nfd = accept_from_socket (fd, (struct sockaddr *)&ss, &addrlen)) == -1) {
		msg_warn ("accept failed: %s", strerror (errno));
		return;
	}
	/* Check for EAGAIN */
	if (nfd == 0) {
		return;
	}


	new_task = construct_task (worker);

	if (ss.ss_family == AF_UNIX) {
		msg_info ("accepted connection from unix socket");
		new_task->client_addr.s_addr = INADDR_NONE;
	}
	else if (ss.ss_family == AF_INET) {
		sin = (struct sockaddr_in *)&ss;
		msg_info ("accepted connection from %s port %d", inet_ntoa (sin->sin_addr), ntohs (sin->sin_port));
		memcpy (&new_task->client_addr, &sin->sin_addr, sizeof (struct in_addr));
	}

	new_task->sock = nfd;
	new_task->is_mime = is_mime;
	worker->srv->stat->connections_count++;

	/* Set up dispatcher */
	new_task->dispatcher = rspamd_create_dispatcher (nfd, BUFFER_LINE, read_socket, write_socket, err_socket, &io_tv, (void *)new_task);
	new_task->dispatcher->peer_addr = new_task->client_addr.s_addr;

}

/*
 * Start worker process
 */
void
start_worker (struct rspamd_worker *worker)
{
	struct sigaction                signals;
	char                           *is_mime_str;

#ifdef WITH_PROFILER
	extern void                     _start (void), etext (void);
	monstartup ((u_long) & _start, (u_long) & etext);
#endif

	gperf_profiler_init (worker->srv->cfg, "worker");

	worker->srv->pid = getpid ();

	event_init ();
	evdns_init ();

	init_signals (&signals, sig_handler);
	sigprocmask (SIG_UNBLOCK, &signals.sa_mask, NULL);

	/* SIGUSR2 handler */
	signal_set (&worker->sig_ev, SIGUSR2, sigusr_handler, (void *)worker);
	signal_add (&worker->sig_ev, NULL);

	/* Accept event */
	event_set (&worker->bind_ev, worker->cf->listen_sock, EV_READ | EV_PERSIST, accept_socket, (void *)worker);
	event_add (&worker->bind_ev, NULL);

	/* Maps events */
	start_map_watch ();
	/* Check whether we are mime worker */
	is_mime_str = g_hash_table_lookup (worker->cf->params, "mime");
	if (is_mime_str != NULL && (g_ascii_strcasecmp (is_mime_str, "no") == 0 || g_ascii_strcasecmp (is_mime_str, "false") == 0)) {
		is_mime = FALSE;
	}
	else {
		is_mime = TRUE;
	}

	event_loop (0);
	
	close_log ();
	exit (EXIT_SUCCESS);
}

/* 
 * vi:ts=4 
 */
