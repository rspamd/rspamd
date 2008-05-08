#ifdef _THREAD_SAFE
#include <pthread.h>
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
struct memc_udp_header
{
	uint16_t req_id;
	uint16_t seq_num;
	uint16_t dg_sent;
	uint16_t unused;
};

/*
 * Poll file descriptor for read or write during specified timeout
 */
static int
poll_d (int fd, u_char want_read, u_char want_write, int timeout)
{
	int r;
    struct pollfd fds[1];
	
	fds->fd = fd;
    fds->revents = 0;
	fds->events = 0;

	if (want_read != 0) {
		fds->events |= POLLIN;
	}
	if (want_write != 0) {
		fds->events |= POLLOUT;
	}
	while ((r = poll(fds, 1, timeout)) < 0) {
		if (errno != EINTR)
	    	break;
    }

	return r;
}

/*
 * Write to syslog if OPT_DEBUG is specified
 */
static void
memc_log (const memcached_ctx_t *ctx, int line, const char *fmt, ...) 
{
	va_list args;
	if (ctx->options & MEMC_OPT_DEBUG) {
		va_start (args, fmt);
		syslog (LOG_DEBUG, "memc_debug(%d): host: %s, port: %d", line, inet_ntoa (ctx->addr), ntohs (ctx->port));
		vsyslog (LOG_DEBUG, fmt, args);
		va_end (args);
	}
}

/*
 * Make socket for udp connection
 */
static int
memc_make_udp_sock (memcached_ctx_t *ctx)
{
	struct sockaddr_in sc;
	int ofl;

	bzero (&sc, sizeof (struct sockaddr_in *));
	sc.sin_family = AF_INET;
	sc.sin_port = ctx->port;
	memcpy (&sc.sin_addr, &ctx->addr, sizeof (struct in_addr));

	ctx->sock = socket (PF_INET, SOCK_DGRAM, 0);

	if (ctx->sock == -1) {
		memc_log (ctx, __LINE__, "memc_make_udp_sock: socket() failed: %m");
		return -1;
	}

	/* set nonblocking */
    ofl = fcntl(ctx->sock, F_GETFL, 0);
    fcntl(ctx->sock, F_SETFL, ofl | O_NONBLOCK);

	/* 
	 * Call connect to set default destination for datagrams 
	 * May not block
	 */
	return connect (ctx->sock, (struct sockaddr*)&sc, sizeof (struct sockaddr_in));
}

/*
 * Make socket for tcp connection
 */
static int
memc_make_tcp_sock (memcached_ctx_t *ctx)
{
	struct sockaddr_in sc;
	int ofl, r;

	bzero (&sc, sizeof (struct sockaddr_in *));
	sc.sin_family = AF_INET;
	sc.sin_port = ctx->port;
	memcpy (&sc.sin_addr, &ctx->addr, sizeof (struct in_addr));

	ctx->sock = socket (PF_INET, SOCK_STREAM, 0);

	if (ctx->sock == -1) {
		memc_log (ctx, __LINE__, "memc_make_tcp_sock: socket() failed: %m");
		return -1;
	}

	/* set nonblocking */
    ofl = fcntl(ctx->sock, F_GETFL, 0);
    fcntl(ctx->sock, F_SETFL, ofl | O_NONBLOCK);
	
	if ((r = connect (ctx->sock, (struct sockaddr*)&sc, sizeof (struct sockaddr_in))) == -1) {
		if (errno != EINPROGRESS) {
			close (ctx->sock);
			ctx->sock = -1;
			memc_log (ctx, __LINE__, "memc_make_tcp_sock: connect() failed: %m");
			return -1;
		}
	}
	/* Get write readiness */
	if (poll_d (ctx->sock, 0, 1, ctx->timeout) == 1) {
		return 0;
	} 
	else {
		memc_log (ctx, __LINE__, "memc_make_tcp_sock: poll() timeout");
		close (ctx->sock);
		ctx->sock = -1;
		return -1;
	}
}

/* 
 * Parse VALUE reply from server and set len argument to value returned by memcached 
 */
static int
memc_parse_header (char *buf, size_t *len, char **end)
{
	char *p, *c;
	int i;

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
memc_read (memcached_ctx_t *ctx, const char *cmd, memcached_param_t *params, size_t *nelem)
{
	char read_buf[READ_BUFSIZ];
	char *p;
	int i, retries;
	ssize_t r, sum = 0, written = 0;
	size_t datalen;
	struct memc_udp_header header;
	struct iovec iov[2];
	
	for (i = 0; i < *nelem; i++) {
		if (ctx->protocol == UDP_TEXT) {
			/* Send udp header */
			bzero (&header, sizeof (header));
			header.dg_sent = htons (1);
			header.req_id = ctx->count;
		}

		r = snprintf (read_buf, READ_BUFSIZ, "%s %s" CRLF, cmd, params[i].key);
		memc_log (ctx, __LINE__, "memc_read: send read request to memcached: %s", read_buf);
		if (ctx->protocol == UDP_TEXT) {
			iov[0].iov_base = &header;
			iov[0].iov_len = sizeof (struct memc_udp_header);
			iov[1].iov_base = read_buf;
			iov[1].iov_len = r;
			writev (ctx->sock, iov, 2);
		}
		else {
			write (ctx->sock, read_buf, r);
		}

		/* Read reply from server */
		retries = 0;
		while (ctx->protocol == UDP_TEXT) {
			if (poll_d (ctx->sock, 1, 0, ctx->timeout) != 1) {
				return SERVER_TIMEOUT;
			}
			iov[0].iov_base = &header;
			iov[0].iov_len = sizeof (struct memc_udp_header);
			iov[1].iov_base = read_buf;
			iov[1].iov_len = READ_BUFSIZ;
			if ((r = readv (ctx->sock, iov, 2)) == -1) {
				return SERVER_ERROR;
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
			if (poll_d (ctx->sock, 1, 0, ctx->timeout) != 1) {
				memc_log (ctx, __LINE__, "memc_read: timeout waiting reply");
				return SERVER_TIMEOUT;
			}
			r = read (ctx->sock, read_buf, READ_BUFSIZ - 1);
		}

		if (r > 0) {
			sum += r;
			read_buf[r] = 0;
			r = memc_parse_header (read_buf, &datalen, &p);
			if (r < 0) {
				memc_log (ctx, __LINE__, "memc_read: cannot parse memcached reply");
				return SERVER_ERROR;
			}
			else if (r == 0) {
				memc_log (ctx, __LINE__, "memc_read: record does not exists");
				return NOT_EXISTS;
			}

			if (datalen != params[i].bufsize) {
				memc_log (ctx, __LINE__, "memc_read: user's buffer is too small: %zd, %zd required", params[i].bufsize, datalen);
				return WRONG_LENGTH;
			}

			/* Subtract from sum parsed header's length */
			sum -= p - read_buf;
			/* Check if we already have all data in buffer */
			if (sum >= datalen + sizeof (END_TRAILER) + sizeof (CRLF) - 2) {
				/* Store all data in param's buffer */
				memcpy (params[i].buf, p, datalen);
				/* Increment count */
				ctx->count++;
				return OK;
			}
			else {
				/* Store this part of data in param's buffer */
				memcpy (params[i].buf, p, sum);
				written += sum;
			}
		}
		else {
			memc_log (ctx, __LINE__, "memc_read: read(v) failed: %d, %m", r);
			return SERVER_ERROR;
		}
		/* Read data from multiply datagrams */
		p = read_buf;

		while (sum < datalen + sizeof (END_TRAILER) + sizeof (CRLF) - 2) {
			retries = 0;
			while (ctx->protocol == UDP_TEXT) {
				if (poll_d (ctx->sock, 1, 0, ctx->timeout) != 1) {
					memc_log (ctx, __LINE__, "memc_read: timeout waiting reply");
					return SERVER_TIMEOUT;
				}
				iov[0].iov_base = &header;
				iov[0].iov_len = sizeof (struct memc_udp_header);
				iov[1].iov_base = read_buf;
				iov[1].iov_len = READ_BUFSIZ;
				if ((r = readv (ctx->sock, iov, 2)) == -1) {
					memc_log (ctx, __LINE__, "memc_read: read(v) failed: %d, %m", r);
					return SERVER_ERROR;
				}
				if (header.req_id != ctx->count && retries < MAX_RETRIES) {
					memc_log (ctx, __LINE__, "memc_read: got wrong packet id: %d, %d was awaited", header.req_id, ctx->count);
					retries ++;
					/* Not our reply packet */
					continue;
				}
			}
			if (ctx->protocol != UDP_TEXT) {
				if (poll_d (ctx->sock, 1, 0, ctx->timeout) != 1) {
					memc_log (ctx, __LINE__, "memc_read: timeout waiting reply");
					return SERVER_TIMEOUT;
				}
				r = read (ctx->sock, read_buf, READ_BUFSIZ - 1);
			}
			
			p = read_buf;
			sum += r;
			if (r <= 0) {
				break;
			}
			/* Copy received buffer to result buffer */
			while (r--) {
				/* Break on reading END\r\n */
				if (strncmp (p, END_TRAILER, sizeof (END_TRAILER) - 1) == 0) {
					break;
				}
				if (written < datalen) {
					params[i].buf[written++] = *p++;
				}
			}
		}
		/* Increment count */
		ctx->count++;
	}

	return OK;
}

/*
 * Common write command handler for memcached
 */
memc_error_t
memc_write (memcached_ctx_t *ctx, const char *cmd, memcached_param_t *params, size_t *nelem, int expire)
{
	char read_buf[READ_BUFSIZ];
	int i, retries, ofl;
	ssize_t r;
	struct memc_udp_header header;
	struct iovec iov[4];
	
	for (i = 0; i < *nelem; i++) {
		if (ctx->protocol == UDP_TEXT) {
			/* Send udp header */
			bzero (&header, sizeof (header));
			header.dg_sent = htons (1);
			header.req_id = ctx->count;
		}

		r = snprintf (read_buf, READ_BUFSIZ, "%s %s 0 %d %zu" CRLF, cmd, params[i].key, expire, params[i].bufsize);
		memc_log (ctx, __LINE__, "memc_write: send write request to memcached: %s", read_buf);
		/* Set socket blocking */
		ofl = fcntl(ctx->sock, F_GETFL, 0);
		fcntl(ctx->sock, F_SETFL, ofl & (~O_NONBLOCK));

		if (ctx->protocol == UDP_TEXT) {
			iov[0].iov_base = &header;
			iov[0].iov_len = sizeof (struct memc_udp_header);
			iov[1].iov_base = read_buf;
			iov[1].iov_len = r;
			iov[2].iov_base = params[i].buf;
			iov[2].iov_len = params[i].bufsize;
			iov[3].iov_base = CRLF;
			iov[3].iov_len = sizeof (CRLF) - 1;
			writev (ctx->sock, iov, 4);
		}
		else {
			iov[0].iov_base = read_buf;
			iov[0].iov_len = r;
			iov[1].iov_base = params[i].buf;
			iov[1].iov_len = params[i].bufsize;
			iov[2].iov_base = CRLF;
			iov[2].iov_len = sizeof (CRLF) - 1;
			writev (ctx->sock, iov, 3);	
		}
		
		/* Restore socket mode */
		fcntl(ctx->sock, F_SETFL, ofl);
		/* Read reply from server */
		if (poll_d (ctx->sock, 1, 0, ctx->timeout) != 1) {
			memc_log (ctx, __LINE__, "memc_write: server timeout while reading reply");
			return SERVER_ERROR;
		}
		/* Read header */
		retries = 0;
		while (ctx->protocol == UDP_TEXT) {
			if (poll_d (ctx->sock, 1, 0, ctx->timeout) != 1) {
				memc_log (ctx, __LINE__, "memc_write: timeout waiting reply");
				return SERVER_TIMEOUT;
			}
			iov[0].iov_base = &header;
			iov[0].iov_len = sizeof (struct memc_udp_header);
			iov[1].iov_base = read_buf;
			iov[1].iov_len = READ_BUFSIZ;
			if ((r = readv (ctx->sock, iov, 2)) == -1) {
				return SERVER_ERROR;
			}
			if (header.req_id != ctx->count && retries < MAX_RETRIES) {
				retries ++;
				/* Not our reply packet */
				continue;
			}
			break;
		}
		if (ctx->protocol != UDP_TEXT) {
			if (poll_d (ctx->sock, 1, 0, ctx->timeout) != 1) {
				memc_log (ctx, __LINE__, "memc_write: timeout waiting reply");
				return SERVER_TIMEOUT;
			}
			r = read (ctx->sock, read_buf, READ_BUFSIZ - 1);
		}
		/* Increment count */
		ctx->count++;
		
		if (strncmp (read_buf, STORED_TRAILER, sizeof (STORED_TRAILER) - 1) == 0) {
			continue;
		}
		else if (strncmp (read_buf, NOT_STORED_TRAILER, sizeof (NOT_STORED_TRAILER) - 1) == 0) {
			return CLIENT_ERROR;
		}
		else if (strncmp (read_buf, EXISTS_TRAILER, sizeof (EXISTS_TRAILER) - 1) == 0) {
			return EXISTS;
		}
		else {
			return SERVER_ERROR;
		}
	}

	return OK;
}
/*
 * Delete command handler
 */
memc_error_t
memc_delete (memcached_ctx_t *ctx, memcached_param_t *params, size_t *nelem)
{
	char read_buf[READ_BUFSIZ];
	int i, retries;
	ssize_t r;
	struct memc_udp_header header;
	struct iovec iov[2];
	
	for (i = 0; i < *nelem; i++) {
		if (ctx->protocol == UDP_TEXT) {
			/* Send udp header */
			bzero (&header, sizeof (header));
			header.dg_sent = htons(1);
			header.req_id = ctx->count;
		}

		r = snprintf (read_buf, READ_BUFSIZ, "delete %s" CRLF, params[i].key);
		memc_log (ctx, __LINE__, "memc_delete: send delete request to memcached: %s", read_buf);
		if (ctx->protocol == UDP_TEXT) {
			iov[0].iov_base = &header;
			iov[0].iov_len = sizeof (struct memc_udp_header);
			iov[1].iov_base = read_buf;
			iov[1].iov_len = r;
			writev (ctx->sock, iov, 2);
		}
		else {
			write (ctx->sock, read_buf, r);
		}

		/* Read reply from server */
		retries = 0;
		while (ctx->protocol == UDP_TEXT) {
			if (poll_d (ctx->sock, 1, 0, ctx->timeout) != 1) {
				return SERVER_TIMEOUT;
			}
			iov[0].iov_base = &header;
			iov[0].iov_len = sizeof (struct memc_udp_header);
			iov[1].iov_base = read_buf;
			iov[1].iov_len = READ_BUFSIZ;
			if ((r = readv (ctx->sock, iov, 2)) == -1) {
				return SERVER_ERROR;
			}
			if (header.req_id != ctx->count && retries < MAX_RETRIES) {
				retries ++;
				/* Not our reply packet */
				continue;
			}
			break;
		}
		if (ctx->protocol != UDP_TEXT) {
			if (poll_d (ctx->sock, 1, 0, ctx->timeout) != 1) {
				return SERVER_TIMEOUT;
			}
			r = read (ctx->sock, read_buf, READ_BUFSIZ - 1);
		}
		
		/* Increment count */
		ctx->count++;
		if (strncmp (read_buf, DELETED_TRAILER, sizeof (DELETED_TRAILER) - 1) == 0) {
			continue;
		}
		else if (strncmp (read_buf, NOT_FOUND_TRAILER, sizeof (NOT_FOUND_TRAILER) - 1) == 0) {
			return NOT_EXISTS;
		}
		else {
			return SERVER_ERROR;
		}
	}

	return OK;
}

/*
 * Write handler for memcached mirroring
 * writing is done to each memcached server
 */
memc_error_t
memc_write_mirror (memcached_ctx_t *ctx, size_t memcached_num, const char *cmd, memcached_param_t *params, size_t *nelem, int expire)
{
	memc_error_t r, result = OK;

	while (memcached_num --) {
		if (ctx[memcached_num].alive == 1) {
			r = memc_write (&ctx[memcached_num], cmd, params, nelem, expire);
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
memc_read_mirror (memcached_ctx_t *ctx, size_t memcached_num, const char *cmd, memcached_param_t *params, size_t *nelem)
{
	memc_error_t r, result = OK;

	while (memcached_num --) {
		if (ctx[memcached_num].alive == 1) {
			r = memc_read (&ctx[memcached_num], cmd, params, nelem);
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
memc_delete_mirror (memcached_ctx_t *ctx, size_t memcached_num, const char *cmd, memcached_param_t *params, size_t *nelem)
{
	memc_error_t r, result = OK;

	while (memcached_num --) {
		if (ctx[memcached_num].alive == 1) {
			r = memc_delete (&ctx[memcached_num], params, nelem);
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
int 
memc_init_ctx (memcached_ctx_t *ctx)
{
	if (ctx == NULL) {
		return -1;
	}

	ctx->count = 0;
	ctx->alive = 1;

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
int 
memc_init_ctx_mirror (memcached_ctx_t *ctx, size_t memcached_num)
{
	int r, result = -1;
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
int
memc_close_ctx (memcached_ctx_t *ctx)
{
	if (ctx != NULL && ctx->sock != -1) {
		return close (ctx->sock);
	}

	return -1;
}
/* 
 * Mirror close
 */
int 
memc_close_ctx_mirror (memcached_ctx_t *ctx, size_t memcached_num)
{
	int r = 0;
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


const char * memc_strerror (memc_error_t err)
{
	const char *p;

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
