/*
 * Copyright (c) 2009, Rambler media
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

#include "config.h"
#include "buffer.h"
#include "main.h"
#include "lmtp.h"
#include "lmtp_proto.h"
#include "cfg_file.h"
#include "util.h"
#include "url.h"
#include "modules.h"
#include "message.h"

static char greetingbuf[1024];
static struct timeval io_tv;

static void lmtp_write_socket (void *arg);

static 
void sig_handler (int signo)
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
sigusr_handler (int fd, short what, void *arg)
{
	struct rspamd_worker *worker = (struct rspamd_worker *)arg;
	/* Do not accept new connections, preparing to end worker's process */
	struct timeval tv;
	tv.tv_sec = SOFT_SHUTDOWN_TIME;
	tv.tv_usec = 0;
	event_del (&worker->sig_ev);
	event_del (&worker->bind_ev);
	do_reopen_log = 1;
	msg_info ("lmtp worker's shutdown is pending in %d sec", SOFT_SHUTDOWN_TIME);
	event_loopexit (&tv);
	return;
}

/*
 * Destructor for recipients list
 */
static void
rcpt_destruct (void *pointer)
{
	struct worker_task *task = (struct worker_task *)pointer;

	if (task->rcpt) {
		g_list_free (task->rcpt);
	}
}

/*
 * Free all structures of lmtp proto
 */
static void
free_task (struct rspamd_lmtp_proto *lmtp, gboolean is_soft)
{
	GList *part;
	struct mime_part *p;

	if (lmtp) {
		msg_debug ("free_task: free pointer %p", lmtp->task);
		if (lmtp->task->memc_ctx) {
			memc_close_ctx (lmtp->task->memc_ctx);
		}
		while ((part = g_list_first (lmtp->task->parts))) {
			lmtp->task->parts = g_list_remove_link (lmtp->task->parts, part);
			p = (struct mime_part *)part->data;
			g_byte_array_free (p->content, FALSE);
			g_list_free_1 (part);
		}
		memory_pool_delete (lmtp->task->task_pool);
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
static void
lmtp_read_socket (f_str_t *in, void *arg)
{
	struct rspamd_lmtp_proto *lmtp = (struct rspamd_lmtp_proto *)arg;
	struct worker_task *task = lmtp->task;
	ssize_t r;

	switch (task->state) {
		case READ_COMMAND:
		case READ_HEADER:
			if (read_lmtp_input_line (lmtp, in) != 0) {
				msg_info ("read_lmtp_socket: closing lmtp connection due to protocol error");
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
				task->last_error = "Filter processing error";
				task->error_code = LMTP_FAILURE;
				task->state = WRITE_ERROR;
				lmtp_write_socket (lmtp);
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
			msg_debug ("lmtp_read_socket: invalid state while reading from socket %d", lmtp->task->state);
			break;
	}
}

/*
 * Callback for socket writing
 */
static void
lmtp_write_socket (void *arg)
{
	struct rspamd_lmtp_proto *lmtp = (struct rspamd_lmtp_proto *)arg;
	
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
			msg_debug ("lmtp_write_socket: normally closing connection");
			free_task (lmtp, TRUE);
			break;
		default:
			msg_debug ("lmtp_write_socket: invalid state while writing to socket %d", lmtp->task->state);
			break;
	}
}

/*
 * Called if something goes wrong
 */
static void
lmtp_err_socket (GError *err, void *arg)
{
	struct rspamd_lmtp_proto *lmtp = (struct rspamd_lmtp_proto *)arg;
	msg_info ("lmtp_err_socket: abnormally closing connection, error: %s", err->message);
	/* Free buffers */
	free_task (lmtp, FALSE);
}

/*
 * Accept new connection and construct task
 */
static void
accept_socket (int fd, short what, void *arg)
{
	struct rspamd_worker *worker = (struct rspamd_worker *)arg;
	struct sockaddr_storage ss;
	struct worker_task *new_task;
	struct rspamd_lmtp_proto *lmtp;
	socklen_t addrlen = sizeof(ss);
	int nfd;

	if ((nfd = accept_from_socket (fd, (struct sockaddr *)&ss, &addrlen)) == -1) {
		msg_warn ("accept_socket: accept failed: %s", strerror (errno));
		return;
	}

	lmtp = g_malloc (sizeof (struct rspamd_lmtp_proto));
	new_task = g_malloc (sizeof (struct worker_task));
	bzero (new_task, sizeof (struct worker_task));
	new_task->worker = worker;
	new_task->state = READ_COMMAND;
	new_task->sock = nfd;
	new_task->cfg = worker->srv->cfg;
	TAILQ_INIT (&new_task->urls);
	new_task->task_pool = memory_pool_new (memory_pool_get_size ());
	/* Add destructor for recipients list (it would be better to use anonymous function here */
	memory_pool_add_destructor (new_task->task_pool, (pool_destruct_func)rcpt_destruct, new_task);
	new_task->results = g_hash_table_new (g_str_hash, g_str_equal);
	memory_pool_add_destructor (new_task->task_pool, (pool_destruct_func)g_hash_table_destroy, new_task->results);
	worker->srv->stat->connections_count ++;
	lmtp->task = new_task;
	lmtp->state = LMTP_READ_LHLO;

	/* Set up dispatcher */
	new_task->dispatcher = rspamd_create_dispatcher (nfd, BUFFER_LINE, lmtp_read_socket,
														lmtp_write_socket, lmtp_err_socket, &io_tv,
														(void *)lmtp);
	rspamd_dispatcher_write (lmtp->task->dispatcher, greetingbuf, strlen (greetingbuf), FALSE);
}

/*
 * Start lmtp worker process
 */
void
start_lmtp_worker (struct rspamd_worker *worker, int listen_sock)
{
	struct sigaction signals;
	int i;
	char *hostbuf;
	long int hostmax;

	worker->srv->pid = getpid ();
	worker->srv->type = TYPE_LMTP;
	event_init ();
	g_mime_init (0);

	init_signals (&signals, sig_handler);
	sigprocmask (SIG_UNBLOCK, &signals.sa_mask, NULL);

	/* SIGUSR2 handler */
	signal_set (&worker->sig_ev, SIGUSR2, sigusr_handler, (void *) worker);
	signal_add (&worker->sig_ev, NULL);
	
	/* Accept event */
	event_set(&worker->bind_ev, listen_sock, EV_READ | EV_PERSIST, accept_socket, (void *)worker);
	event_add(&worker->bind_ev, NULL);

	/* Perform modules configuring */
	for (i = 0; i < MODULES_NUM; i ++) {
		modules[i].module_config_func (worker->srv->cfg);
	}

	/* Fill hostname buf */
	hostmax = sysconf (_SC_HOST_NAME_MAX) + 1;
	hostbuf = alloca (hostmax);
	gethostname (hostbuf, hostmax);
	hostbuf[hostmax - 1] = '\0';
	snprintf (greetingbuf, sizeof (greetingbuf), "%d rspamd version %s LMTP on %s Ready\r\n", LMTP_OK, RVERSION, hostbuf);

	/* Send SIGUSR2 to parent */
	kill (getppid (), SIGUSR2);

	io_tv.tv_sec = WORKER_IO_TIMEOUT;
	io_tv.tv_usec = 0;

	event_loop (0);
	exit (EXIT_SUCCESS);
}

/* 
 * vi:ts=4 
 */
