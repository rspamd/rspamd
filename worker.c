
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

#include <glib.h>
#include <gmime/gmime.h>

#include "util.h"
#include "main.h"
#include "upstream.h"
#include "cfg_file.h"

#define CONTENT_LENGTH_HEADER "Content-Length:"

const f_str_t CRLF = {
	/* begin */"\r\n",
	/* len */2,
	/* size */2
};

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
mime_foreach_callback (GMimeObject *part, gpointer user_data)
{
	int *count = user_data;
	
	(*count)++;
	
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
		g_mime_message_foreach_part (message, mime_foreach_callback, count);
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
	} else {
		g_assert_not_reached ();
	}
}


static void
process_message (f_str_t *msg)
{
	int count = 0;
	GMimeMessage *message;
	GMimeParser *parser;
	GMimeStream *stream;

	stream = g_mime_stream_mem_new_with_buffer (msg->begin, msg->len);
	/* create a new parser object to parse the stream */
	parser = g_mime_parser_new_with_stream (stream);
	/* create a new parser object to parse the stream */
	parser = g_mime_parser_new_with_stream (stream);

	/* unref the stream (parser owns a ref, so this object does not actually get free'd until we destroy the parser) */
	g_object_unref (stream);

	/* parse the message from the stream */
	message = g_mime_parser_construct_message (parser);

	/* free the parser (and the stream) */
	g_object_unref (parser);

	g_mime_message_foreach_part (message, mime_foreach_callback, &count);
	
	msg_info ("process_message: found %d parts in message", count);
}

static void
read_socket (struct bufferevent *bev, void *arg)
{
	struct worker_task *task = (struct worker_task *)arg;
	ssize_t r;
	char *s;

	switch (task->state) {
		case READ_COMMAND:
			s = evbuffer_readline (EVBUFFER_INPUT (bev));
			if (s != NULL) {
				msg_info ("read_socket: got command %s", s);
				free (s);
				task->state = READ_HEADER;
			}
			break;
		case READ_HEADER:
			s = evbuffer_readline (EVBUFFER_INPUT (bev));
			if (s != NULL) {
				msg_info ("read_socket: got header %s", s);
				if (strncasecmp (s, CONTENT_LENGTH_HEADER, sizeof (CONTENT_LENGTH_HEADER) - 1) == 0) {
					task->content_length = atoi (s + sizeof (CONTENT_LENGTH_HEADER));
					msg_info ("read_socket: parsed content-length: %ld", (long int)task->content_length);
					task->msg = malloc (sizeof (f_str_buf_t));
					if (task->msg == NULL) {
						msg_err ("read_socket: cannot allocate memory");
						bufferevent_disable (bev, EV_READ);
						bufferevent_free (bev);
						free (task);
					}
					task->msg->buf = fstralloc (task->content_length);
					if (task->msg->buf == NULL) {
						msg_err ("read_socket: cannot allocate memory for message buffer");
						bufferevent_disable (bev, EV_READ);
						bufferevent_free (bev);
						free (task->msg);
						free (task);
					}
					task->msg->pos = task->msg->buf->begin;
					update_buf_size (task->msg);
				}
				else if (strlen (s) == 0) {
					if (task->content_length != 0) {
						task->state = READ_MESSAGE;
					}
					else {
						task->state = WRITE_ERROR;
					}
				}
				free (s);
			}
			break;
		case READ_MESSAGE:
			r = bufferevent_read (bev, task->msg->pos, task->msg->free);
			if (r > 0) {
				task->msg->pos += r;
				update_buf_size (task->msg);
				if (task->msg->free == 0) {
					process_message (task->msg->buf);
					task->state = WRITE_REPLY;
				}
			}
			else {
				msg_err ("read_socket: cannot read data to buffer: %ld", (long int)r);
				bufferevent_disable (bev, EV_READ);
				bufferevent_free (bev);
				fstrfree (task->msg->buf);
				free (task->msg);
				free (task);
			}
			break;
		case WRITE_REPLY:
			r = bufferevent_write (bev, "Ok\r\n", sizeof ("Ok\r\n") - 1);
			bufferevent_disable (bev, EV_READ);
			bufferevent_enable (bev, EV_WRITE);
			break;
		case WRITE_ERROR:
			r = bufferevent_write (bev, "Error\r\n", sizeof ("Error\r\n") - 1);
			bufferevent_disable (bev, EV_READ);
			bufferevent_enable (bev, EV_WRITE);
			break;
	}
}

static void
write_socket (struct bufferevent *bev, void *arg)
{
	struct worker_task *task = (struct worker_task *)arg;

	if (task->state > READ_MESSAGE) {
		msg_info ("closing connection");
		/* Free buffers */
		fstrfree (task->msg->buf);
		free (task->msg);
		bufferevent_disable (bev, EV_WRITE);
		bufferevent_free (bev);

		free (task);
	}
}

static void
err_socket (struct bufferevent *bev, short what, void *arg)
{
	struct worker_task *task = (struct worker_task *)arg;
	msg_info ("closing connection");
	/* Free buffers */
	if (task->state > READ_HEADER) {
		fstrfree (task->msg->buf);
		free (task->msg);
	}
	bufferevent_disable (bev, EV_READ);
	bufferevent_free (bev);

	free (task);
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
	
	new_task = malloc (sizeof (struct worker_task));
	if (new_task == NULL) {
		msg_err ("accept_socket: cannot allocate memory for task");
		return;
	}
	new_task->worker = worker;
	new_task->state = READ_COMMAND;
	new_task->content_length = 0;

	/* Read event */
	new_task->bev = bufferevent_new (nfd, read_socket, write_socket, err_socket, (void *)new_task);
	bufferevent_enable (new_task->bev, EV_READ);
}

void
start_worker (struct rspamd_worker *worker, int listen_sock)
{
	struct sigaction signals;
	struct config_file *cfg = worker->srv->cfg;
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

	/* Send SIGUSR2 to parent */
	kill (getppid (), SIGUSR2);

	event_loop (0);
}

/* 
 * vi:ts=4 
 */
