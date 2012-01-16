/* Copyright (c) 2010-2011, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
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
#include "aio_event.h"
#include "main.h"

/* Linux syscall numbers */
#define SYS_io_setup      245
#define SYS_io_destroy    246
#define SYS_io_getevents  247
#define SYS_io_submit     248
#define SYS_io_cancel     249
#define SYS_eventfd       323
#define MAX_AIO_EV        32768

struct io_cbdata {
	rspamd_aio_cb cb;
	gsize len;
	gpointer buf;
	gpointer ud;
};

#ifdef LINUX

/* Linux specific mappings and utilities to avoid using of libaio */

typedef unsigned int aio_context_t;

typedef enum io_iocb_cmd {
	IO_CMD_PREAD = 0,
	IO_CMD_PWRITE = 1,

	IO_CMD_FSYNC = 2,
	IO_CMD_FDSYNC = 3,

	IO_CMD_POLL = 5,
	IO_CMD_NOOP = 6,
} io_iocb_cmd_t;

struct io_iocb_common {
	void *buf;
	unsigned __pad1;
	long nbytes;
	unsigned __pad2;
	long long offset;
	long long __pad3;
    unsigned flags;
    unsigned resfd;
}; /* result code is the amount read or -'ve errno */

struct iocb {
	void *data;
	unsigned key;
	short aio_lio_opcode;
	short aio_reqprio;
	int aio_fildes;
	union {
		struct io_iocb_common c;
	} u;
};

struct io_event {
	uint64_t  data;  /* the data field from the iocb */
	uint64_t  obj;   /* what iocb this event came from */
	int64_t   res;   /* result code for this event */
	int64_t   res2;  /* secondary result */
};

/* Linux specific io calls */
static int
io_setup (guint nr_reqs, aio_context_t *ctx)
{
    return syscall (SYS_io_setup, nr_reqs, ctx);
}

static int
io_destroy (aio_context_t ctx)
{
    return syscall (SYS_io_destroy, ctx);
}

static int
io_getevents (aio_context_t ctx, long min_nr, long nr, struct io_event *events, struct timespec *tmo)
{
	return syscall (SYS_io_getevents, ctx, min_nr, nr, events, tmo);
}

static int
io_submit (aio_context_t ctx, long n, struct iocb **paiocb)
{
    return syscall (SYS_io_submit, ctx, n, paiocb);
}

static int
io_cancel (aio_context_t ctx, struct iocb *iocb, struct io_event *result)
{
    return syscall (SYS_io_cancel, ctx, iocb, result);
}

# ifndef HAVE_SYS_EVENTFD_H
static int
eventfd(guint initval, guint flags)
{
	return syscall (SYS_eventfd, initval);
}
# endif

#endif

/**
 * AIO context
 */
struct aio_context {
	struct event_base *base;
	gboolean has_aio;		/**< Whether we have aio support on a system */
#ifdef LINUX
	/* Eventfd variant */
	gint event_fd;
	struct event eventfd_ev;
	aio_context_t io_ctx;
#elif defined(HAVE_AIO_H)
	/* POSIX aio */
	struct event rtsigs[SIGRTMAX - SIGRTMIN];
#endif
};

#ifdef LINUX
/* Eventfd read callback */
static void
rspamd_eventfdcb (gint fd, gshort what, gpointer ud)
{
	struct aio_context					*ctx = ud;
	guint64								 ready;
	gint								 done, i;
	struct io_event   					 event[64];
	struct timespec   					 ts;
	struct io_cbdata					*ev_data;

	/* Eventfd returns number of events ready got from kernel */
	if (read (fd, &ready, 8) != 8) {
		if (errno == EAGAIN) {
			return;
		}
		msg_err ("eventfd read returned error: %s", strerror (errno));
	}

	ts.tv_sec = 0;
	ts.tv_nsec = 0;

	while (ready) {
		/* Get events ready */
		done = io_getevents (ctx->io_ctx, 1, 64, event, &ts);

		if (done > 0) {
			ready -= done;

			for (i = 0; i < done; i ++) {
				ev_data = (struct io_cbdata *) (uintptr_t) event[i].data;
				/* Call this callback */
				ev_data->cb (event[i].res, ev_data->len, ev_data->buf, ev_data->ud);
			}
		}
		else if (done == 0) {
			/* No more events are ready */
			return;
		}
		else {
			msg_err ("io_getevents failed: %s", strerror (errno));
			return;
		}
	}
}

#endif

/**
 * Initialize aio with specified event base
 */
struct aio_context*
rspamd_aio_init (struct event_base *base)
{
	struct aio_context					*new;

	/* First of all we need to detect which type of aio we can try to use */
	new = g_malloc0 (sizeof (struct aio_context));
	new->base = base;

#ifdef LINUX
	/* On linux we are trying to use io (3) and eventfd for notifying */
	new->event_fd = eventfd (0, 0);
	if (new->event_fd == -1) {
		msg_err ("eventfd failed: %s", strerror (errno));
	}
	else {
		/* Set this socket non-blocking */
		if (make_socket_nonblocking (new->event_fd) == -1) {
			msg_err ("non blocking for eventfd failed: %s", strerror (errno));
			close (new->event_fd);
		}
		else {
			event_set (&new->eventfd_ev, new->event_fd, EV_READ|EV_PERSIST, rspamd_eventfdcb, new);
			event_base_set (new->base, &new->eventfd_ev);
			if (io_setup (MAX_AIO_EV, &new->io_ctx) == -1) {
				msg_err ("io_setup failed: %s", strerror (errno));
				close (new->event_fd);
			}
			else {
				new->has_aio = TRUE;
			}
		}
	}
#elif defined(HAVE_AIO_H)
	/* TODO: implement this */
#endif

	return new;
}

/**
 * Open file for aio
 */
gint
rspamd_aio_open (struct aio_context *ctx, const gchar *path, int flags)
{
	gint										fd = -1;
	/* Fallback */
	if (!ctx->has_aio) {
		return open (path, flags);
	}
#ifdef LINUX

	fd = open (path, flags | O_DIRECT | O_NONBLOCK);

	return fd;
#elif defined(HAVE_AIO_H)
	fd = open (path, flags | O_NONBLOCK);
#endif

	return fd;
}

/**
 * Asynchronous read of file
 */
gint
rspamd_aio_read (gint fd, gpointer buf, gsize len, struct aio_context *ctx, rspamd_aio_cb cb, gpointer ud)
{
	struct io_cbdata							*cbdata;
	gint										 r = -1;

	if (ctx->has_aio) {
#ifdef LINUX
		struct iocb								*iocb[1];

		cbdata = g_slice_alloc (sizeof (struct io_cbdata));
		cbdata->cb = cb;
		cbdata->buf = buf;
		cbdata->len = len;
		cbdata->ud = ud;

		iocb[0] = alloca (sizeof (struct iocb));
		memset (iocb[0], 0, sizeof (struct iocb));
		iocb[0]->aio_fildes = fd;
		iocb[0]->aio_lio_opcode = IO_CMD_PREAD;
		iocb[0]->aio_reqprio = 0;
		iocb[0]->u.c.buf = buf;
		iocb[0]->u.c.nbytes = len;
		iocb[0]->u.c.offset = 0;
		iocb[0]->u.c.flags |= (1 << 0) /* IOCB_FLAG_RESFD */;
		iocb[0]->u.c.resfd = ctx->event_fd;
		iocb[0]->data = cbdata;

		/* Iocb is copied to kernel internally, so it is safe to put it on stack */
		if (io_submit (ctx->io_ctx, 1, iocb) == 1) {
			return len;
		}
		else {
			if (errno == EAGAIN || errno == ENOSYS) {
				/* Fall back to sync read */
				goto blocking;
			}
			return -1;
		}

#elif defined(HAVE_AIO_H)
#endif
	}
	else {
		/* Blocking variant */
blocking:
		r = read (fd, buf, len);
		if (r >= 0) {
			cb (0, r, buf, ud);
		}
		else {
			cb (r, -1, buf, ud);
		}
	}

	return r;
}

/**
 * Asynchronous write of file
 */
gint
rspamd_aio_write (gint fd, gpointer buf, gsize len, struct aio_context *ctx, rspamd_aio_cb cb, gpointer ud)
{
	struct io_cbdata							*cbdata;
	gint										 r = -1;

	if (ctx->has_aio) {
#ifdef LINUX
		struct iocb								 *iocb[1];

		cbdata = g_slice_alloc (sizeof (struct io_cbdata));
		cbdata->cb = cb;
		cbdata->buf = buf;
		cbdata->len = len;
		cbdata->ud = ud;

		iocb[0] = alloca (sizeof (struct iocb));
		memset (iocb[0], 0, sizeof (struct iocb));
		iocb[0]->aio_fildes = fd;
		iocb[0]->aio_lio_opcode = IO_CMD_PWRITE;
		iocb[0]->aio_reqprio = 0;
		iocb[0]->u.c.buf = buf;
		iocb[0]->u.c.nbytes = len;
		iocb[0]->u.c.offset = 0;
		iocb[0]->u.c.flags |= (1 << 0) /* IOCB_FLAG_RESFD */;
		iocb[0]->u.c.resfd = ctx->event_fd;
		iocb[0]->data = cbdata;

		/* Iocb is copied to kernel internally, so it is safe to put it on stack */
		if (io_submit (ctx->io_ctx, 1, iocb) == 1) {
			return len;
		}
		else {
			if (errno == EAGAIN || errno == ENOSYS) {
				/* Fall back to sync read */
				goto blocking;
			}
			return -1;
		}

#elif defined(HAVE_AIO_H)
#endif
	}
	else {
		/* Blocking variant */
blocking:
		r = write (fd, buf, len);
		if (r >= 0) {
			cb (0, r, buf, ud);
		}
		else {
			cb (r, -1, buf, ud);
		}
	}

	return r;
}

/**
 * Close of aio operations
 */
gint
rspamd_aio_close (gint fd, struct aio_context *ctx)
{
	gint										 r = -1;

	if (ctx->has_aio) {
#ifdef LINUX
		struct iocb								 iocb;
		struct io_event							 ev;

		memset (&iocb, 0, sizeof (struct iocb));
		iocb.aio_fildes = fd;
		iocb.aio_lio_opcode = IO_CMD_NOOP;

		/* Iocb is copied to kernel internally, so it is safe to put it on stack */
		r = io_cancel (ctx->io_ctx, &iocb, &ev);
		close (fd);
		return r;

#elif defined(HAVE_AIO_H)
#endif
	}

	r = close (fd);

	return r;
}
