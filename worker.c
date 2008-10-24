#include <sys/stat.h>
#include <sys/param.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>

#include <netinet/in.h>
#include <syslog.h>
#include <fcntl.h>
#include <netdb.h>

#include <EXTERN.h>               /* from the Perl distribution     */
#include <perl.h>                 /* from the Perl distribution     */

#include <glib.h>
#include <gmime/gmime.h>

#include "util.h"
#include "main.h"
#include "protocol.h"
#include "upstream.h"
#include "cfg_file.h"
#include "url.h"
#include "modules.h"

#define TASK_POOL_SIZE 4095

const f_str_t CRLF = {
	/* begin */"\r\n",
	/* len */2,
	/* size */2
};

extern PerlInterpreter *perl_interpreter;

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
	msg_info ("worker's shutdown is pending in %d sec", SOFT_SHUTDOWN_TIME);
	event_loopexit (&tv);
	return;
}

static void
free_task (struct worker_task *task)
{
	struct mime_part *part;

	if (task) {
		if (task->memc_ctx) {
			memc_close_ctx (task->memc_ctx);
		}
		while (!TAILQ_EMPTY (&task->parts)) {
			part = TAILQ_FIRST (&task->parts);
			g_object_unref (part->type);
			g_object_unref (part->content);
			TAILQ_REMOVE (&task->parts, part, next);
		}
		memory_pool_delete (task->task_pool);
		bufferevent_disable (task->bev, EV_READ | EV_WRITE);
		bufferevent_free (task->bev);
		close (task->sock);
		g_free (task);
	}
}

static void
mime_foreach_callback (GMimeObject *part, gpointer user_data)
{
	struct worker_task *task = (struct worker_task *)user_data;
	struct mime_part *mime_part;
	GMimeContentType *type;
	GMimeDataWrapper *wrapper;
	GMimeStream *part_stream;
	GByteArray *part_content;
	
	task->parts_count ++;
	
	/* 'part' points to the current part node that g_mime_message_foreach_part() is iterating over */
	
	/* find out what class 'part' is... */
	if (GMIME_IS_MESSAGE_PART (part)) {
		/* message/rfc822 or message/news */
		GMimeMessage *message;
		
		/* g_mime_message_foreach_part() won't descend into
                   child message parts, so if we want to count any
                   subparts of this child message, we'll have to call
                   g_mime_message_foreach_part() again here. */
		
		message = g_mime_message_part_get_message ((GMimeMessagePart *) part);
		g_mime_message_foreach_part (message, mime_foreach_callback, task);
		g_object_unref (message);
	} else if (GMIME_IS_MESSAGE_PARTIAL (part)) {
		/* message/partial */
		
		/* this is an incomplete message part, probably a
                   large message that the sender has broken into
                   smaller parts and is sending us bit by bit. we
                   could save some info about it so that we could
                   piece this back together again once we get all the
                   parts? */
	} else if (GMIME_IS_MULTIPART (part)) {
		/* multipart/mixed, multipart/alternative, multipart/related, multipart/signed, multipart/encrypted, etc... */
		
		/* we'll get to finding out if this is a signed/encrypted multipart later... */
	} else if (GMIME_IS_PART (part)) {
		/* a normal leaf part, could be text/plain or image/jpeg etc */
		wrapper = g_mime_part_get_content_object (GMIME_PART (part));
		if (wrapper != NULL) {
			part_stream = g_mime_stream_mem_new ();
			if (g_mime_data_wrapper_write_to_stream (wrapper, part_stream) != -1) {
				part_content = g_mime_stream_mem_get_byte_array (GMIME_STREAM_MEM (part_stream));
				type = (GMimeContentType *)g_mime_part_get_content_type (GMIME_PART (part));
				mime_part = memory_pool_alloc (task->task_pool, sizeof (struct mime_part));
				mime_part->type = type;
				mime_part->content = part_content;
				TAILQ_INSERT_TAIL (&task->parts, mime_part, next);
				if (g_mime_content_type_is_type (type, "text", "html")) {
					url_parse_html (task, part_content);
				} 
				else if (g_mime_content_type_is_type (type, "text", "plain")) {
					url_parse_text (task, part_content);
				}
			}
		}
	} else {
		g_assert_not_reached ();
	}
}

static int
process_message (struct worker_task *task)
{
	GMimeMessage *message;
	GMimeParser *parser;
	GMimeStream *stream;

	stream = g_mime_stream_mem_new_with_buffer (task->msg->buf->begin, task->msg->buf->len);
	/* create a new parser object to parse the stream */
	parser = g_mime_parser_new_with_stream (stream);

	/* unref the stream (parser owns a ref, so this object does not actually get free'd until we destroy the parser) */
	g_object_unref (stream);

	/* parse the message from the stream */
	message = g_mime_parser_construct_message (parser);
	
	task->message = message;
	memory_pool_add_destructor (task->task_pool, (pool_destruct_func)g_object_unref, task->message);

	/* free the parser (and the stream) */
	g_object_unref (parser);

	g_mime_message_foreach_part (message, mime_foreach_callback, task);
	
	msg_info ("process_message: found %d parts in message", task->parts_count);

	return process_filters (task);
}

static void
read_socket (struct bufferevent *bev, void *arg)
{
	struct worker_task *task = (struct worker_task *)arg;
	ssize_t r;
	char *s;

	switch (task->state) {
		case READ_COMMAND:
		case READ_HEADER:
			s = evbuffer_readline (EVBUFFER_INPUT (bev));
			if (read_rspamd_input_line (task, s) != 0) {
				task->last_error = "Read error";
				task->error_code = RSPAMD_NETWORK_ERROR;
				task->state = WRITE_ERROR;
			}
			if (task->state == WRITE_ERROR || task->state == WRITE_REPLY) {
				bufferevent_enable (bev, EV_WRITE);
				bufferevent_disable (bev, EV_READ);
			}
			free (s);
			break;
		case READ_MESSAGE:
			r = bufferevent_read (bev, task->msg->pos, task->msg->free);
			if (r > 0) {
				task->msg->pos += r;
				update_buf_size (task->msg);
				if (task->msg->free == 0) {
					r = process_message (task);
					if (r == -1) {
						task->last_error = "Filter processing error";
						task->error_code = RSPAMD_FILTER_ERROR;
						task->state = WRITE_ERROR;
					}
					else if (r == 1) {
						task->state = WAIT_FILTER;
					}
				}
				if (task->state == WRITE_ERROR || task->state == WRITE_REPLY) {
					bufferevent_enable (bev, EV_WRITE);
					bufferevent_disable (bev, EV_READ);
				}
			}
			else {
				msg_err ("read_socket: cannot read data to buffer: %ld", (long int)r);
				bufferevent_disable (bev, EV_READ);
				bufferevent_free (bev);
				free_task (task);
			}
			break;
		case WAIT_FILTER:
			bufferevent_disable (bev, EV_READ);
			break;
	}
}

static void
write_socket (struct bufferevent *bev, void *arg)
{
	struct worker_task *task = (struct worker_task *)arg;
	
	switch (task->state) {
		case WRITE_REPLY:
			write_reply (task);
			task->state = CLOSING_CONNECTION;
			bufferevent_disable (bev, EV_READ);
			break;
		case WRITE_ERROR:
			write_reply (task);
			task->state = CLOSING_CONNECTION;
			bufferevent_disable (bev, EV_READ);
			break;
		case CLOSING_CONNECTION:
			msg_debug ("write_socket: normally closing connection");
			free_task (task);
			break;
		default:
			msg_info ("write_socket: abnormally closing connection");
			free_task (task);
			break;
	}
}

static void
err_socket (struct bufferevent *bev, short what, void *arg)
{
	struct worker_task *task = (struct worker_task *)arg;
	msg_info ("err_socket: abnormally closing connection");
	/* Free buffers */
	free_task (task);
}

static void
accept_socket (int fd, short what, void *arg)
{
	struct rspamd_worker *worker = (struct rspamd_worker *)arg;
	struct sockaddr_storage ss;
	struct worker_task *new_task;
	socklen_t addrlen = sizeof(ss);
	int nfd;

	if ((nfd = accept (fd, (struct sockaddr *)&ss, &addrlen)) == -1) {
		return;
	}
	if (event_make_socket_nonblocking(fd) < 0) {
		return;
	}
	
	new_task = g_malloc (sizeof (struct worker_task));
	if (new_task == NULL) {
		msg_err ("accept_socket: cannot allocate memory for task, %m");
		return;
	}
	bzero (new_task, sizeof (struct worker_task));
	new_task->worker = worker;
	new_task->state = READ_COMMAND;
	new_task->sock = nfd;
	new_task->cfg = worker->srv->cfg;
	TAILQ_INIT (&new_task->urls);
	TAILQ_INIT (&new_task->parts);
#ifdef HAVE_GETPAGESIZE
	new_task->task_pool = memory_pool_new (getpagesize () - 1);
#else
	new_task->task_pool = memory_pool_new (TASK_POOL_SIZE);
#endif

	/* Read event */
	new_task->bev = bufferevent_new (nfd, read_socket, write_socket, err_socket, (void *)new_task);
	bufferevent_enable (new_task->bev, EV_READ);
}

void
start_worker (struct rspamd_worker *worker, int listen_sock)
{
	struct sigaction signals;
	int i;


	worker->srv->pid = getpid ();
	worker->srv->type = TYPE_WORKER;
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

	/* Send SIGUSR2 to parent */
	kill (getppid (), SIGUSR2);

	event_loop (0);
}

/* 
 * vi:ts=4 
 */
