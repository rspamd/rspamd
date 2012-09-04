/*
 * Copyright (c) 2012, Vsevolod Stakhov
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

#ifdef _THREAD_SAFE
#   include <pthread.h>
#endif

#include <stdarg.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <syslog.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <event.h>
#include <glib.h>

#include "memcached.h"

#define CRLF "\r\n"
#define END_TRAILER "END" CRLF
#define STORED_TRAILER "STORED" CRLF
#define NOT_STORED_TRAILER "NOT STORED" CRLF
#define EXISTS_TRAILER "EXISTS" CRLF
#define DELETED_TRAILER "DELETED" CRLF
#define NOT_FOUND_TRAILER "NOT_FOUND" CRLF
#define CLIENT_ERROR_TRAILER "CLIENT_ERROR"
#define SERVER_ERROR_TRAILER "SERVER_ERROR"

#define READ_BUFSIZ 1500
#define MAX_RETRIES 3

/* Header for udp protocol */
struct memc_udp_header {
	guint16                        req_id;
	guint16                        seq_num;
	guint16                        dg_sent;
	guint16                        unused;
};

static void                     socket_callback (gint fd, short what, void *arg);
static gint                      memc_parse_header (gchar *buf, size_t * len, gchar **end);

/*
 * Write to syslog if OPT_DEBUG is specified
 */
static void
memc_log (const memcached_ctx_t * ctx, gint line, const gchar *fmt, ...)
{
	va_list                         args;
	if (ctx->options & MEMC_OPT_DEBUG) {
		va_start (args, fmt);
		g_log (G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "memc_debug(%d): host: %s, port: %d", line, inet_ntoa (ctx->addr), ntohs (ctx->port));
		g_logv (G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, fmt, args);
		va_end (args);
	}
}

/*
 * Callback for write command
 */
static void
write_handler (gint fd, short what, memcached_ctx_t * ctx)
{
	gchar                           read_buf[READ_BUFSIZ];
	gint                            retries;
	ssize_t                         r;
	struct memc_udp_header          header;
	struct iovec                    iov[4];

	/* Write something to memcached */
	if (what == EV_WRITE) {
		if (ctx->protocol == UDP_TEXT) {
			/* Send udp header */
			bzero (&header, sizeof (header));
			header.dg_sent = htons (1);
			header.req_id = ctx->count;
		}

		r = snprintf (read_buf, READ_BUFSIZ, "%s %s 0 %d %zu" CRLF, ctx->cmd, ctx->param->key, ctx->param->expire, ctx->param->bufsize);
		memc_log (ctx, __LINE__, "memc_write: send write request to memcached: %s", read_buf);

		if (ctx->protocol == UDP_TEXT) {
			iov[0].iov_base = &header;
			iov[0].iov_len = sizeof (struct memc_udp_header);
			if (ctx->param->bufpos == 0) {
				iov[1].iov_base = read_buf;
				iov[1].iov_len = r;
			}
			else {
				iov[1].iov_base = NULL;
				iov[1].iov_len = 0;
			}
			iov[2].iov_base = ctx->param->buf + ctx->param->bufpos;
			iov[2].iov_len = ctx->param->bufsize - ctx->param->bufpos;
			iov[3].iov_base = CRLF;
			iov[3].iov_len = sizeof (CRLF) - 1;
			if (writev (ctx->sock, iov, 4) == -1) {
				memc_log (ctx, __LINE__, "memc_write: writev failed: %s", strerror (errno));
			}
		}
		else {
			iov[0].iov_base = read_buf;
			iov[0].iov_len = r;
			iov[1].iov_base = ctx->param->buf + ctx->param->bufpos;
			iov[1].iov_len = ctx->param->bufsize - ctx->param->bufpos;
			iov[2].iov_base = CRLF;
			iov[2].iov_len = sizeof (CRLF) - 1;
			if (writev (ctx->sock, iov, 3) == -1) {
				memc_log (ctx, __LINE__, "memc_write: writev failed: %s", strerror (errno));
			}
		}
		event_del (&ctx->mem_ev);
		event_set (&ctx->mem_ev, ctx->sock, EV_READ | EV_PERSIST | EV_TIMEOUT, socket_callback, (void *)ctx);
		event_add (&ctx->mem_ev, &ctx->timeout);
	}
	else if (what == EV_READ) {
		/* Read header */
		retries = 0;
		while (ctx->protocol == UDP_TEXT) {
			iov[0].iov_base = &header;
			iov[0].iov_len = sizeof (struct memc_udp_header);
			iov[1].iov_base = read_buf;
			iov[1].iov_len = READ_BUFSIZ;
			if ((r = readv (ctx->sock, iov, 2)) == -1) {
				event_del (&ctx->mem_ev);
				ctx->callback (ctx, SERVER_ERROR, ctx->callback_data);
			}
			if (header.req_id != ctx->count && retries < MAX_RETRIES) {
				retries++;
				/* Not our reply packet */
				continue;
			}
			break;
		}
		if (ctx->protocol != UDP_TEXT) {
			r = read (ctx->sock, read_buf, READ_BUFSIZ - 1);
		}
		memc_log (ctx, __LINE__, "memc_write: read reply from memcached: %s", read_buf);
		/* Increment count */
		ctx->count++;
		event_del (&ctx->mem_ev);
		if (strncmp (read_buf, STORED_TRAILER, sizeof (STORED_TRAILER) - 1) == 0) {
			ctx->callback (ctx, OK, ctx->callback_data);
		}
		else if (strncmp (read_buf, NOT_STORED_TRAILER, sizeof (NOT_STORED_TRAILER) - 1) == 0) {
			ctx->callback (ctx, CLIENT_ERROR, ctx->callback_data);
		}
		else if (strncmp (read_buf, EXISTS_TRAILER, sizeof (EXISTS_TRAILER) - 1) == 0) {
			ctx->callback (ctx, EXISTS, ctx->callback_data);
		}
		else {
			ctx->callback (ctx, SERVER_ERROR, ctx->callback_data);
		}
	}
	else if (what == EV_TIMEOUT) {
		event_del (&ctx->mem_ev);
		ctx->callback (ctx, SERVER_TIMEOUT, ctx->callback_data);
	}
}

/*
 * Callback for read command
 */
static void
read_handler (gint fd, short what, memcached_ctx_t * ctx)
{
	gchar                           read_buf[READ_BUFSIZ];
	gchar                           *p;
	ssize_t                         r;
	size_t                          datalen;
	struct memc_udp_header          header;
	struct iovec                    iov[2];
	gint                            retries = 0, t;

	if (what == EV_WRITE) {
		/* Send command to memcached */
		if (ctx->protocol == UDP_TEXT) {
			/* Send udp header */
			bzero (&header, sizeof (header));
			header.dg_sent = htons (1);
			header.req_id = ctx->count;
		}

		r = snprintf (read_buf, READ_BUFSIZ, "%s %s" CRLF, ctx->cmd, ctx->param->key);
		memc_log (ctx, __LINE__, "memc_read: send read request to memcached: %s", read_buf);
		if (ctx->protocol == UDP_TEXT) {
			iov[0].iov_base = &header;
			iov[0].iov_len = sizeof (struct memc_udp_header);
			iov[1].iov_base = read_buf;
			iov[1].iov_len = r;
			if (writev (ctx->sock, iov, 2) == -1) {
				memc_log (ctx, __LINE__, "memc_write: writev failed: %s", strerror (errno));
			}
		}
		else {
			if (write (ctx->sock, read_buf, r) == -1) {
				memc_log (ctx, __LINE__, "memc_write: write failed: %s", strerror (errno));
			}
		}
		event_del (&ctx->mem_ev);
		event_set (&ctx->mem_ev, ctx->sock, EV_READ | EV_PERSIST | EV_TIMEOUT, socket_callback, (void *)ctx);
		event_add (&ctx->mem_ev, &ctx->timeout);
	}
	else if (what == EV_READ) {
		while (ctx->protocol == UDP_TEXT) {
			iov[0].iov_base = &header;
			iov[0].iov_len = sizeof (struct memc_udp_header);
			iov[1].iov_base = read_buf;
			iov[1].iov_len = READ_BUFSIZ;
			if ((r = readv (ctx->sock, iov, 2)) == -1) {
				event_del (&ctx->mem_ev);
				ctx->callback (ctx, SERVER_ERROR, ctx->callback_data);
				return;
			}
			memc_log (ctx, __LINE__, "memc_read: got read_buf: %s", read_buf);
			if (header.req_id != ctx->count && retries < MAX_RETRIES) {
				memc_log (ctx, __LINE__, "memc_read: got wrong packet id: %d, %d was awaited", header.req_id, ctx->count);
				retries++;
				/* Not our reply packet */
				continue;
			}
			break;
		}
		if (ctx->protocol != UDP_TEXT) {
			r = read (ctx->sock, read_buf, READ_BUFSIZ - 1);
		}

		if (r > 0) {
			read_buf[r] = 0;
			if (ctx->param->bufpos == 0) {
				t = memc_parse_header (read_buf, &datalen, &p);
				if (t < 0) {
					event_del (&ctx->mem_ev);
					memc_log (ctx, __LINE__, "memc_read: cannot parse memcached reply");
					ctx->callback (ctx, SERVER_ERROR, ctx->callback_data);
					return;
				}
				else if (t == 0) {
					memc_log (ctx, __LINE__, "memc_read: record does not exists");
					event_del (&ctx->mem_ev);
					ctx->callback (ctx, NOT_EXISTS, ctx->callback_data);
					return;
				}

				if (datalen > ctx->param->bufsize) {
					memc_log (ctx, __LINE__, "memc_read: user's buffer is too small: %zd, %zd required", ctx->param->bufsize, datalen);
					event_del (&ctx->mem_ev);
					ctx->callback (ctx, WRONG_LENGTH, ctx->callback_data);
					return;
				}
				/* Check if we already have all data in buffer */
				if (r >= (ssize_t)(datalen + sizeof (END_TRAILER) + sizeof (CRLF) - 2)) {
					/* Store all data in param's buffer */
					memcpy (ctx->param->buf + ctx->param->bufpos, p, datalen);
					/* Increment count */
					ctx->count++;
					event_del (&ctx->mem_ev);
					ctx->callback (ctx, OK, ctx->callback_data);
					return;
				}
				/* Subtract from sum parsed header's length */
				r -= p - read_buf;
			}
			else {
				p = read_buf;
			}

			if (strncmp (ctx->param->buf + ctx->param->bufpos + r - sizeof (END_TRAILER) - sizeof (CRLF) + 2, END_TRAILER, sizeof (END_TRAILER) - 1) == 0) {
				r -= sizeof (END_TRAILER) - sizeof (CRLF) - 2;
				memcpy (ctx->param->buf + ctx->param->bufpos, p, r);
				event_del (&ctx->mem_ev);
				ctx->callback (ctx, OK, ctx->callback_data);
				return;
			}
			/* Store this part of data in param's buffer */
			memcpy (ctx->param->buf + ctx->param->bufpos, p, r);
			ctx->param->bufpos += r;
		}
		else {
			memc_log (ctx, __LINE__, "memc_read: read(v) failed: %d, %s", r, strerror (errno));
			event_del (&ctx->mem_ev);
			ctx->callback (ctx, SERVER_ERROR, ctx->callback_data);
			return;
		}

		ctx->count++;
	}
	else if (what == EV_TIMEOUT) {
		event_del (&ctx->mem_ev);
		ctx->callback (ctx, SERVER_TIMEOUT, ctx->callback_data);
	}

}

/*
 * Callback for delete command
 */
static void
delete_handler (gint fd, short what, memcached_ctx_t * ctx)
{
	gchar                           read_buf[READ_BUFSIZ];
	gint                            retries;
	ssize_t                         r;
	struct memc_udp_header          header;
	struct iovec                    iov[2];

	/* Write something to memcached */
	if (what == EV_WRITE) {
		if (ctx->protocol == UDP_TEXT) {
			/* Send udp header */
			bzero (&header, sizeof (header));
			header.dg_sent = htons (1);
			header.req_id = ctx->count;
		}
		r = snprintf (read_buf, READ_BUFSIZ, "delete %s" CRLF, ctx->param->key);
		memc_log (ctx, __LINE__, "memc_delete: send delete request to memcached: %s", read_buf);

		if (ctx->protocol == UDP_TEXT) {
			iov[0].iov_base = &header;
			iov[0].iov_len = sizeof (struct memc_udp_header);
			iov[1].iov_base = read_buf;
			iov[1].iov_len = r;
			ctx->param->bufpos = writev (ctx->sock, iov, 2);
			if (ctx->param->bufpos == (size_t)-1) {
				memc_log (ctx, __LINE__, "memc_write: writev failed: %s", strerror (errno));
			}
		}
		else {
			if (write (ctx->sock, read_buf, r) == -1) {
				memc_log (ctx, __LINE__, "memc_write: write failed: %s", strerror (errno));
			}
		}
		event_del (&ctx->mem_ev);
		event_set (&ctx->mem_ev, ctx->sock, EV_READ | EV_PERSIST | EV_TIMEOUT, socket_callback, (void *)ctx);
		event_add (&ctx->mem_ev, &ctx->timeout);
	}
	else if (what == EV_READ) {
		/* Read header */
		retries = 0;
		while (ctx->protocol == UDP_TEXT) {
			iov[0].iov_base = &header;
			iov[0].iov_len = sizeof (struct memc_udp_header);
			iov[1].iov_base = read_buf;
			iov[1].iov_len = READ_BUFSIZ;
			if ((r = readv (ctx->sock, iov, 2)) == -1) {
				event_del (&ctx->mem_ev);
				ctx->callback (ctx, SERVER_ERROR, ctx->callback_data);
				return;
			}
			if (header.req_id != ctx->count && retries < MAX_RETRIES) {
				retries++;
				/* Not our reply packet */
				continue;
			}
			break;
		}
		if (ctx->protocol != UDP_TEXT) {
			r = read (ctx->sock, read_buf, READ_BUFSIZ - 1);
		}
		/* Increment count */
		ctx->count++;
		event_del (&ctx->mem_ev);
		if (strncmp (read_buf, DELETED_TRAILER, sizeof (STORED_TRAILER) - 1) == 0) {
			ctx->callback (ctx, OK, ctx->callback_data);
		}
		else if (strncmp (read_buf, NOT_FOUND_TRAILER, sizeof (NOT_FOUND_TRAILER) - 1) == 0) {
			ctx->callback (ctx, NOT_EXISTS, ctx->callback_data);
		}
		else {
			ctx->callback (ctx, SERVER_ERROR, ctx->callback_data);
		}
	}
	else if (what == EV_TIMEOUT) {
		event_del (&ctx->mem_ev);
		ctx->callback (ctx, SERVER_TIMEOUT, ctx->callback_data);
	}
}

/*
 * Callback for our socket events
 */
static void
socket_callback (gint fd, short what, void *arg)
{
	memcached_ctx_t                *ctx = (memcached_ctx_t *) arg;

	switch (ctx->op) {
	case CMD_NULL:
		/* Do nothing here */
		break;
	case CMD_CONNECT:
		/* We have write readiness after connect call, so reinit event */
		ctx->cmd = "connect";
		if (what == EV_WRITE) {
			event_del (&ctx->mem_ev);
			event_set (&ctx->mem_ev, ctx->sock, EV_READ | EV_PERSIST | EV_TIMEOUT, socket_callback, (void *)ctx);
			event_add (&ctx->mem_ev, NULL);
			ctx->callback (ctx, OK, ctx->callback_data);
			ctx->alive = 1;
		}
		else {
			ctx->callback (ctx, SERVER_TIMEOUT, ctx->callback_data);
			ctx->alive = 0;
		}
		break;
	case CMD_WRITE:
		write_handler (fd, what, ctx);
		break;
	case CMD_READ:
		read_handler (fd, what, ctx);
		break;
	case CMD_DELETE:
		delete_handler (fd, what, ctx);
		break;
	}
}

/*
 * Common callback function for memcached operations if no user's callback is specified
 */
static void
common_memc_callback (memcached_ctx_t * ctx, memc_error_t error, void *data)
{
	memc_log (ctx, __LINE__, "common_memc_callback: result of memc command '%s' is '%s'", ctx->cmd, memc_strerror (error));
}

/*
 * Make socket for udp connection
 */
static gint
memc_make_udp_sock (memcached_ctx_t * ctx)
{
	struct sockaddr_in              sc;
	gint                            ofl;

	bzero (&sc, sizeof (struct sockaddr_in *));
	sc.sin_family = AF_INET;
	sc.sin_port = ctx->port;
	memcpy (&sc.sin_addr, &ctx->addr, sizeof (struct in_addr));

	ctx->sock = socket (PF_INET, SOCK_DGRAM, 0);

	if (ctx->sock == -1) {
		memc_log (ctx, __LINE__, "memc_make_udp_sock: socket() failed: %s", strerror (errno));
		return -1;
	}

	/* set nonblocking */
	ofl = fcntl (ctx->sock, F_GETFL, 0);
	fcntl (ctx->sock, F_SETFL, ofl | O_NONBLOCK);

	/* 
	 * Call connect to set default destination for datagrams 
	 * May not block
	 */
	ctx->op = CMD_CONNECT;
	event_set (&ctx->mem_ev, ctx->sock, EV_WRITE | EV_TIMEOUT, socket_callback, (void *)ctx);
	event_add (&ctx->mem_ev, NULL);
	return connect (ctx->sock, (struct sockaddr *)&sc, sizeof (struct sockaddr_in));
}

/*
 * Make socket for tcp connection
 */
static gint
memc_make_tcp_sock (memcached_ctx_t * ctx)
{
	struct sockaddr_in              sc;
	gint                            ofl, r;

	bzero (&sc, sizeof (struct sockaddr_in *));
	sc.sin_family = AF_INET;
	sc.sin_port = ctx->port;
	memcpy (&sc.sin_addr, &ctx->addr, sizeof (struct in_addr));

	ctx->sock = socket (PF_INET, SOCK_STREAM, 0);

	if (ctx->sock == -1) {
		memc_log (ctx, __LINE__, "memc_make_tcp_sock: socket() failed: %s", strerror (errno));
		return -1;
	}

	/* set nonblocking */
	ofl = fcntl (ctx->sock, F_GETFL, 0);
	fcntl (ctx->sock, F_SETFL, ofl | O_NONBLOCK);

	if ((r = connect (ctx->sock, (struct sockaddr *)&sc, sizeof (struct sockaddr_in))) == -1) {
		if (errno != EINPROGRESS) {
			close (ctx->sock);
			ctx->sock = -1;
			memc_log (ctx, __LINE__, "memc_make_tcp_sock: connect() failed: %s", strerror (errno));
			return -1;
		}
	}
	ctx->op = CMD_CONNECT;
	event_set (&ctx->mem_ev, ctx->sock, EV_WRITE | EV_TIMEOUT, socket_callback, (void *)ctx);
	event_add (&ctx->mem_ev, &ctx->timeout);
	return 0;
}

/* 
 * Parse VALUE reply from server and set len argument to value returned by memcached 
 */
static gint
memc_parse_header (gchar *buf, size_t * len, gchar **end)
{
	gchar                           *p, *c;
	gint                            i;

	/* VALUE <key> <flags> <bytes> [<cas unique>]\r\n */
	c = strstr (buf, CRLF);
	if (c == NULL) {
		return -1;
	}
	*end = c + sizeof (CRLF) - 1;

	if (strncmp (buf, "VALUE ", sizeof ("VALUE ") - 1) == 0) {
		p = buf + sizeof ("VALUE ") - 1;

		/* Read bytes value and ignore all other fields, such as flags and key */
		for (i = 0; i < 2; i++) {
			while (p++ < c && *p != ' ');

			if (p > c) {
				return -1;
			}
		}
		*len = strtoul (p, &c, 10);
		return 1;
	}
	/* If value not found memcached return just END\r\n , in this case return 0 */
	else if (strncmp (buf, END_TRAILER, sizeof (END_TRAILER) - 1) == 0) {
		return 0;
	}

	return -1;
}


/*
 * Common read command handler for memcached
 */
memc_error_t
memc_read (memcached_ctx_t * ctx, const gchar *cmd, memcached_param_t * param)
{
	ctx->cmd = cmd;
	ctx->op = CMD_READ;
	ctx->param = param;
	event_set (&ctx->mem_ev, ctx->sock, EV_WRITE | EV_TIMEOUT, socket_callback, (void *)ctx);
	event_add (&ctx->mem_ev, &ctx->timeout);

	return OK;
}

/*
 * Common write command handler for memcached
 */
memc_error_t
memc_write (memcached_ctx_t * ctx, const gchar *cmd, memcached_param_t * param, gint expire)
{
	ctx->cmd = cmd;
	ctx->op = CMD_WRITE;
	ctx->param = param;
	param->expire = expire;
	event_set (&ctx->mem_ev, ctx->sock, EV_WRITE | EV_TIMEOUT, socket_callback, (void *)ctx);
	event_add (&ctx->mem_ev, &ctx->timeout);

	return OK;
}

/*
 * Delete command handler
 */
memc_error_t
memc_delete (memcached_ctx_t * ctx, memcached_param_t * param)
{
	ctx->cmd = "delete";
	ctx->op = CMD_DELETE;
	ctx->param = param;
	event_set (&ctx->mem_ev, ctx->sock, EV_WRITE | EV_TIMEOUT, socket_callback, (void *)ctx);
	event_add (&ctx->mem_ev, &ctx->timeout);

	return OK;
}

/*
 * Write handler for memcached mirroring
 * writing is done to each memcached server
 */
memc_error_t
memc_write_mirror (memcached_ctx_t * ctx, size_t memcached_num, const gchar *cmd, memcached_param_t * param, gint expire)
{
	memc_error_t                    r, result = OK;

	while (memcached_num--) {
		if (ctx[memcached_num].alive == 1) {
			r = memc_write (&ctx[memcached_num], cmd, param, expire);
			if (r != OK) {
				memc_log (&ctx[memcached_num], __LINE__, "memc_write_mirror: cannot write to mirror server: %s", memc_strerror (r));
				result = r;
				ctx[memcached_num].alive = 0;
			}
		}
	}

	return result;
}

/*
 * Read handler for memcached mirroring
 * reading is done from first active memcached server
 */
memc_error_t
memc_read_mirror (memcached_ctx_t * ctx, size_t memcached_num, const gchar *cmd, memcached_param_t * param)
{
	memc_error_t                    r, result = OK;

	while (memcached_num--) {
		if (ctx[memcached_num].alive == 1) {
			r = memc_read (&ctx[memcached_num], cmd, param);
			if (r != OK) {
				result = r;
				if (r != NOT_EXISTS) {
					ctx[memcached_num].alive = 0;
					memc_log (&ctx[memcached_num], __LINE__, "memc_read_mirror: cannot write read from mirror server: %s", memc_strerror (r));
				}
				else {
					memc_log (&ctx[memcached_num], __LINE__, "memc_read_mirror: record not exists", memc_strerror (r));
				}
			}
			else {
				break;
			}
		}
	}

	return result;
}

/*
 * Delete handler for memcached mirroring
 * deleting is done for each active memcached server
 */
memc_error_t
memc_delete_mirror (memcached_ctx_t * ctx, size_t memcached_num, const gchar *cmd, memcached_param_t * param)
{
	memc_error_t                    r, result = OK;

	while (memcached_num--) {
		if (ctx[memcached_num].alive == 1) {
			r = memc_delete (&ctx[memcached_num], param);
			if (r != OK) {
				result = r;
				if (r != NOT_EXISTS) {
					ctx[memcached_num].alive = 0;
					memc_log (&ctx[memcached_num], __LINE__, "memc_delete_mirror: cannot delete from mirror server: %s", memc_strerror (r));
				}
			}
		}
	}

	return result;
}


/* 
 * Initialize memcached context for specified protocol
 */
gint
memc_init_ctx (memcached_ctx_t * ctx)
{
	if (ctx == NULL) {
		return -1;
	}

	ctx->count = 0;
	ctx->alive = 0;
	ctx->op = CMD_NULL;
	/* Set default callback */
	if (ctx->callback == NULL) {
		ctx->callback = common_memc_callback;
	}

	switch (ctx->protocol) {
	case UDP_TEXT:
		return memc_make_udp_sock (ctx);
		break;
	case TCP_TEXT:
		return memc_make_tcp_sock (ctx);
		break;
		/* Not implemented */
	case UDP_BIN:
	case TCP_BIN:
	default:
		return -1;
	}
}

/*
 * Mirror init
 */
gint
memc_init_ctx_mirror (memcached_ctx_t * ctx, size_t memcached_num)
{
	gint                            r, result = -1;
	while (memcached_num--) {
		if (ctx[memcached_num].alive == 1) {
			r = memc_init_ctx (&ctx[memcached_num]);
			if (r == -1) {
				ctx[memcached_num].alive = 0;
				memc_log (&ctx[memcached_num], __LINE__, "memc_init_ctx_mirror: cannot connect to server");
			}
			else {
				result = 1;
			}
		}
	}

	return result;
}

/*
 * Close context connection
 */
gint
memc_close_ctx (memcached_ctx_t * ctx)
{
	if (ctx != NULL && ctx->sock != -1) {
		event_del (&ctx->mem_ev);
		return close (ctx->sock);
	}

	return -1;
}

/* 
 * Mirror close
 */
gint
memc_close_ctx_mirror (memcached_ctx_t * ctx, size_t memcached_num)
{
	gint                            r = 0;
	while (memcached_num--) {
		if (ctx[memcached_num].alive == 1) {
			r = memc_close_ctx (&ctx[memcached_num]);
			if (r == -1) {
				memc_log (&ctx[memcached_num], __LINE__, "memc_close_ctx_mirror: cannot close connection to server properly");
				ctx[memcached_num].alive = 0;
			}
		}
	}

	return r;
}


const gchar                     *
memc_strerror (memc_error_t err)
{
	const gchar                     *p;

	switch (err) {
	case OK:
		p = "Ok";
		break;
	case BAD_COMMAND:
		p = "Bad command";
		break;
	case CLIENT_ERROR:
		p = "Client error";
		break;
	case SERVER_ERROR:
		p = "Server error";
		break;
	case SERVER_TIMEOUT:
		p = "Server timeout";
		break;
	case NOT_EXISTS:
		p = "Key not found";
		break;
	case EXISTS:
		p = "Key already exists";
		break;
	case WRONG_LENGTH:
		p = "Wrong result length";
		break;
	default:
		p = "Unknown error";
		break;
	}

	return p;
}

/* 
 * vi:ts=4 
 */
