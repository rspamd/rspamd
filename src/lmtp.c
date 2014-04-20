/*
 * Copyright (c) 2009-2012, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
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

#include "config.h"
#include "buffer.h"
#include "main.h"
#include "lmtp.h"
#include "lmtp_proto.h"
#include "cfg_file.h"
#include "util.h"
#include "url.h"
#include "message.h"

static gchar                     greetingbuf[1024];
static struct timeval           io_tv;

static gboolean                 lmtp_write_socket (void *arg);

void start_lmtp (struct rspamd_worker *worker);

worker_t lmtp_worker = {
	"controller",				/* Name */
	NULL,						/* Init function */
	start_lmtp,					/* Start function */
	TRUE,						/* Has socket */
	FALSE,						/* Non unique */
	FALSE,						/* Non threaded */
	TRUE						/* Killable */
};

#ifndef HAVE_SA_SIGINFO
static void
sig_handler (gint signo)
#else
static void
sig_handler (gint signo, siginfo_t *info, void *unused)
#endif
{
	switch (signo) {
	case SIGINT:
	case SIGTERM:
		_exit (1);
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
	tv.tv_sec = SOFT_SHUTDOWN_TIME;
	tv.tv_usec = 0;
	event_del (&worker->sig_ev_usr1);
	event_del (&worker->sig_ev_usr2);
	event_del (&worker->bind_ev);
	msg_info ("lmtp worker's shutdown is pending in %d sec", SOFT_SHUTDOWN_TIME);
	event_loopexit (&tv);
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
 * Free all structures of lmtp proto
 */
static void
free_lmtp_task (struct rspamd_lmtp_proto *lmtp, gboolean is_soft)
{
	GList                          *part;
	struct mime_part               *p;
	struct worker_task             *task = lmtp->task;

	if (lmtp) {
		debug_task ("free pointer %p", lmtp->task);
		while ((part = g_list_first (lmtp->task->parts))) {
			lmtp->task->parts = g_list_remove_link (lmtp->task->parts, part);
			p = (struct mime_part *)part->data;
			g_byte_array_free (p->content, FALSE);
			g_list_free_1 (part);
		}
		rspamd_mempool_delete (lmtp->task->task_pool);
		if (is_soft) {
			/* Plan dispatcher shutdown */
			lmtp->task->dispatcher->wanna_die = 1;
		}
		else {
			rspamd_remove_dispatcher (lmtp->task->dispatcher);
		}
		close (lmtp->task->sock);
		g_free (lmtp->task);
		g_free (lmtp);
	}
}

/*
 * Callback that is called when there is data to read in buffer
 */
static                          gboolean
lmtp_read_socket (f_str_t * in, void *arg)
{
	struct rspamd_lmtp_proto       *lmtp = (struct rspamd_lmtp_proto *)arg;
	struct worker_task             *task = lmtp->task;
	ssize_t                         r;

	switch (task->state) {
	case READ_COMMAND:
	case READ_HEADER:
		if (read_lmtp_input_line (lmtp, in) != 0) {
			msg_info ("closing lmtp connection due to protocol error");
			lmtp->task->state = CLOSING_CONNECTION;
		}
		/* Task was read, recall read handler once more with new state to process message and write reply */
		if (task->state == READ_MESSAGE) {
			lmtp_read_socket (in, arg);
		}
		break;
	case READ_MESSAGE:
		r = process_message (lmtp->task);
		r = process_filters (lmtp->task);
		if (r == -1) {
			return FALSE;
		}
		else if (r == 0) {
			task->state = WAIT_FILTER;
			rspamd_dispatcher_pause (lmtp->task->dispatcher);
		}
		else {
			process_statfiles (lmtp->task);
			task->state = WRITE_REPLY;
			lmtp_write_socket (lmtp);
		}
		break;
	default:
		debug_task ("invalid state while reading from socket %d", lmtp->task->state);
		break;
	}

	return TRUE;
}

/*
 * Callback for socket writing
 */
static                          gboolean
lmtp_write_socket (void *arg)
{
	struct rspamd_lmtp_proto       *lmtp = (struct rspamd_lmtp_proto *)arg;
	struct worker_task             *task = lmtp->task;

	switch (lmtp->task->state) {
	case WRITE_REPLY:
		if (write_lmtp_reply (lmtp) == 1) {
			lmtp->task->state = WAIT_FILTER;
		}
		else {
			lmtp->task->state = CLOSING_CONNECTION;
		}
		break;
	case WRITE_ERROR:
		write_lmtp_reply (lmtp);
		lmtp->task->state = CLOSING_CONNECTION;
		break;
	case CLOSING_CONNECTION:
		debug_task ("normally closing connection");
		free_lmtp_task (lmtp, TRUE);
		return FALSE;
		break;
	default:
		debug_task ("invalid state while writing to socket %d", lmtp->task->state);
		break;
	}

	return TRUE;
}

/*
 * Called if something goes wrong
 */
static void
lmtp_err_socket (GError * err, void *arg)
{
	struct rspamd_lmtp_proto       *lmtp = (struct rspamd_lmtp_proto *)arg;
	msg_info ("abnormally closing connection, error: %s", err->message);
	/* Free buffers */
	free_lmtp_task (lmtp, FALSE);
}

/*
 * Accept new connection and construct task
 */
static void
accept_socket (gint fd, short what, void *arg)
{
	struct rspamd_worker           *worker = (struct rspamd_worker *)arg;
	union sa_union                  su;
	struct worker_task             *new_task;
	struct rspamd_lmtp_proto       *lmtp;
	socklen_t                       addrlen = sizeof (su.ss);
	gint                            nfd;

	if ((nfd = accept_from_socket (fd, (struct sockaddr *)&su.ss, &addrlen)) == -1) {
		msg_warn ("accept failed: %s", strerror (errno));
		return;
	}

	lmtp = g_malloc (sizeof (struct rspamd_lmtp_proto));

	new_task = construct_task (worker);

	if (su.ss.ss_family == AF_UNIX) {
		msg_info ("accepted connection from unix socket");
		new_task->client_addr.s_addr = INADDR_NONE;
	}
	else if (su.ss.ss_family == AF_INET) {
		msg_info ("accepted connection from %s port %d", inet_ntoa (su.s4.sin_addr), ntohs (su.s4.sin_port));
		memcpy (&new_task->client_addr, &su.s4.sin_addr, sizeof (struct in_addr));
	}

	new_task->sock = nfd;
	new_task->cfg = worker->srv->cfg;
	new_task->task_pool = rspamd_mempool_new (rspamd_mempool_suggest_size ());
	/* Add destructor for recipients list (it would be better to use anonymous function here */
	rspamd_mempool_add_destructor (new_task->task_pool, (rspamd_mempool_destruct_t) rcpt_destruct, new_task);
	new_task->results = g_hash_table_new (rspamd_str_hash, rspamd_str_equal);
	new_task->ev_base = worker->ctx;
	rspamd_mempool_add_destructor (new_task->task_pool, (rspamd_mempool_destruct_t) g_hash_table_destroy, new_task->results);
	worker->srv->stat->connections_count++;
	lmtp->task = new_task;
	lmtp->state = LMTP_READ_LHLO;

	/* Set up dispatcher */
	new_task->dispatcher = rspamd_create_dispatcher (new_task->ev_base, nfd, BUFFER_LINE, lmtp_read_socket, lmtp_write_socket, lmtp_err_socket, &io_tv, (void *)lmtp);
	new_task->dispatcher->peer_addr = new_task->client_addr.s_addr;
	if (! rspamd_dispatcher_write (lmtp->task->dispatcher, greetingbuf, strlen (greetingbuf), FALSE, FALSE)) {
		msg_warn ("cannot write greeting");
	}
}

/*
 * Start lmtp worker process
 */
void
start_lmtp (struct rspamd_worker *worker)
{
	struct sigaction                signals;
	gchar                          *hostbuf;
	gsize                           hostmax;
	module_t					  **mod;

	worker->srv->pid = getpid ();
	worker->ctx = event_init ();
	g_mime_init (0);

	init_signals (&signals, sig_handler);
	sigprocmask (SIG_UNBLOCK, &signals.sa_mask, NULL);

	/* SIGUSR2 handler */
	signal_set (&worker->sig_ev_usr2, SIGUSR2, sigusr2_handler, (void *) worker);
	event_base_set (worker->ctx, &worker->sig_ev_usr2);
	signal_add (&worker->sig_ev_usr2, NULL);

	/* SIGUSR1 handler */
	signal_set (&worker->sig_ev_usr1, SIGUSR1, sigusr1_handler, (void *) worker);
	event_base_set (worker->ctx, &worker->sig_ev_usr1);
	signal_add (&worker->sig_ev_usr1, NULL);

	/* Accept event */
	event_set (&worker->bind_ev, worker->cf->listen_sock, EV_READ | EV_PERSIST, accept_socket, (void *)worker);
	event_base_set (worker->ctx, &worker->bind_ev);
	event_add (&worker->bind_ev, NULL);

	/* Perform modules configuring */
	mod = &modules[0];
	while (*mod) {
		(*mod)->module_config_func (worker->srv->cfg);
		mod ++;
	}

	/* Fill hostname buf */
	hostmax = sysconf (_SC_HOST_NAME_MAX) + 1;
	hostbuf = alloca (hostmax);
	gethostname (hostbuf, hostmax);
	hostbuf[hostmax - 1] = '\0';
	rspamd_snprintf (greetingbuf, sizeof (greetingbuf), "%d rspamd version %s LMTP on %s Ready\r\n", LMTP_OK, RVERSION, hostbuf);

	io_tv.tv_sec = 60000;
	io_tv.tv_usec = 0;

	gperf_profiler_init (worker->srv->cfg, "lmtp");

	event_base_loop (worker->ctx, 0);
	exit (EXIT_SUCCESS);
}

/* 
 * vi:ts=4 
 */
