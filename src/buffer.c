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

#define G_DISPATCHER_ERROR dispatcher_error_quark()

static void dispatcher_cb (int fd, short what, void *arg);

static inline GQuark
dispatcher_error_quark (void)
{
  return g_quark_from_static_string ("g-dispatcher-error-quark");
}

#define BUFREMAIN(x) (x)->data->size - ((x)->pos - (x)->data->begin)

static void
write_buffers (int fd, rspamd_io_dispatcher_t *d)
{
	GList *cur;
	GError *err;
	rspamd_buffer_t *buf;
	ssize_t r;

	/* Fix order */
	if (d->out_buffers) {
		d->out_buffers = g_list_reverse (d->out_buffers);
	}
	cur = g_list_first (d->out_buffers);
	while (cur) {
		buf = (rspamd_buffer_t *)cur->data;
		if (BUFREMAIN (buf) == 0) {
			/* Skip empty buffers */
			cur = g_list_next (cur);
			continue;
		}

		r = write (fd, buf->pos, BUFREMAIN (buf));
		if (r == -1 && errno != EAGAIN) {
			if (d->err_callback) {
				err = g_error_new (G_DISPATCHER_ERROR, errno, "%s", strerror (errno));
				d->err_callback (err, d->user_data);
				return;
			}
		}
		else if (r > 0) {
			buf->pos += r;
			if (BUFREMAIN (buf) != 0) {
				/* Continue with this buffer */
				continue;
			}
		}
		else if (r == 0) {
			/* Got EOF while we wait for data */
			if (d->err_callback) {
				err = g_error_new (G_DISPATCHER_ERROR, EOF, "got EOF");
				d->err_callback (err, d->user_data);
				return;
			}
		}
		else if (errno == EAGAIN) {
			/* Wait for other event */
			return;
		}
		cur = g_list_next (cur);
	}

	if (cur == NULL) {
		/* Disable write event for this time */
		g_list_free (d->out_buffers);
		d->out_buffers = NULL;

		if (d->write_callback) {
			d->write_callback (d->user_data);
		}

		event_del (d->ev);
		event_set (d->ev, fd, EV_READ | EV_PERSIST, dispatcher_cb, (void *)d);
		event_add (d->ev, d->tv);
	}
}

static void
read_buffers (int fd, rspamd_io_dispatcher_t *d)
{
	ssize_t r, len;
	GError *err;
	f_str_t res;
	char *c;

	if (d->in_buf == NULL) {
		d->in_buf = memory_pool_alloc (d->pool, sizeof (rspamd_buffer_t));
		if (d->policy == BUFFER_LINE) {
			d->in_buf->data = fstralloc (d->pool, BUFSIZ);
		}
		else {
			d->in_buf->data = fstralloc (d->pool, d->nchars);
		}
		d->in_buf->pos = d->in_buf->data->begin;
	}
	
	if (BUFREMAIN (d->in_buf) == 0) {
		/* Buffer is full, try to call callback with overflow error */
		if (d->err_callback) {
			err = g_error_new (G_DISPATCHER_ERROR, E2BIG, "buffer overflow");
			d->err_callback (err, d->user_data);
			return;
		}
	}
	else {
		/* Try to read the whole buffer */
		r = read (fd, d->in_buf->pos, BUFREMAIN (d->in_buf));
		if (r == -1 && errno != EAGAIN) {
			if (d->err_callback) {
				err = g_error_new (G_DISPATCHER_ERROR, errno, "%s", strerror (errno));
				d->err_callback (err, d->user_data);
				return;
			}
		}
		else if (r == 0) {
			/* Got EOF while we wait for data */
			if (d->err_callback) {
				err = g_error_new (G_DISPATCHER_ERROR, EOF, "got EOF");
				d->err_callback (err, d->user_data);
				return;
			}
		}
		else if (errno == EAGAIN) {
			return;
		}
		else {
			d->in_buf->pos += r;
			d->in_buf->data->len += r;
		}
	
	}
	
	c = d->in_buf->data->begin;
	r = 0;
	len = d->in_buf->data->len;

	switch (d->policy) {
		case BUFFER_LINE:
			while (r < len) {
				if (*c == '\r' || *c == '\n') {
					res.begin = d->in_buf->data->begin;
					res.len = r;
					if (d->read_callback) {
						d->read_callback (&res, d->user_data);
						if (r < len - 1 && *(c + 1) == '\n') {
							r ++;
							c ++;
						}
						/* Move remaining string to begin of buffer (draining) */
						memmove (d->in_buf->data->begin, c, len - r);
						c = d->in_buf->data->begin;
						d->in_buf->data->len -= r + 1;
						d->in_buf->pos -= r + 1;
						r = 0;
						len = d->in_buf->data->len;
						continue;
					}
				}
				r ++;
				c ++;
			}
			break;
		case BUFFER_CHARACTER:
			while (r < len) {
				if (r == d->nchars) {
					res.begin = d->in_buf->data->begin;
					res.len = r;
					if (d->read_callback) {
						d->read_callback (&res, d->user_data);
						/* Move remaining string to begin of buffer (draining) */
						memmove (d->in_buf->data->begin, c, len - r);
						c = d->in_buf->data->begin;
						d->in_buf->data->len -= r;
						d->in_buf->pos -= r;
						r = 0;
						len = d->in_buf->data->len;
						continue;
					}
				
				}
				r ++;
				c ++;
			}
			break;
	}
}

#undef BUFREMAIN

static void
dispatcher_cb (int fd, short what, void *arg)
{
	rspamd_io_dispatcher_t *d = (rspamd_io_dispatcher_t *)arg;
	GError *err;

	switch (what) {
		case EV_TIMEOUT:
			if (d->err_callback) {
				err = g_error_new (G_DISPATCHER_ERROR, ETIMEDOUT, "IO timeout");
				d->err_callback (err, d->user_data);
			}
			break;
		case EV_WRITE:
			/* No data to write, disable further EV_WRITE to this fd */
			if (d->out_buffers == NULL) {
				event_del (d->ev);
				event_set (d->ev, fd, EV_READ | EV_PERSIST, dispatcher_cb, (void *)d);
				event_add (d->ev, d->tv);
			}
			else {
				write_buffers (fd, d);
			}
			break;
		case EV_READ:
			read_buffers (fd, d);
			break;
	}
}


rspamd_io_dispatcher_t* 
rspamd_create_dispatcher (int fd, enum io_policy policy,
							dispatcher_read_callback_t read_cb,
							dispatcher_write_callback_t write_cb,
							dispatcher_err_callback_t err_cb,
							struct timeval *tv, void *user_data)
{
	rspamd_io_dispatcher_t *new;

	if (fd == -1) {
		return NULL;
	}
	
	new = g_malloc (sizeof (rspamd_io_dispatcher_t));
	bzero (new, sizeof (rspamd_io_dispatcher_t));

	new->pool = memory_pool_new (memory_pool_get_size ());
	new->tv = memory_pool_alloc (new->pool, sizeof (struct timeval));
	memcpy (new->tv, tv, sizeof (struct timeval));
	new->policy = policy;
	new->read_callback = read_cb;
	new->write_callback = write_cb;
	new->err_callback = err_cb;
	new->user_data = user_data;

	new->ev = memory_pool_alloc0 (new->pool, sizeof (struct event));
	new->fd = fd;

	event_set (new->ev, fd, EV_READ | EV_WRITE | EV_PERSIST, dispatcher_cb, (void *)new);
	event_add (new->ev, new->tv);

	return new;
}

void 
rspamd_remove_dispatcher (rspamd_io_dispatcher_t *dispatcher)
{
	if (dispatcher != NULL) {
		event_del (dispatcher->ev);
		memory_pool_delete (dispatcher->pool);
		g_free (dispatcher);
	}
}

void 
rspamd_set_dispatcher_policy (rspamd_io_dispatcher_t *d, 
									enum io_policy policy,
									size_t nchars)
{
	f_str_t *tmp;

	if (d->policy != policy || d->nchars != nchars) {
		d->policy = policy;
		d->nchars = nchars ? nchars : BUFSIZ;
		/* Resize input buffer if needed */
		if (policy == BUFFER_CHARACTER && nchars != 0) {
			if (d->in_buf && d->in_buf->data->size < nchars) {
				tmp = fstralloc (d->pool, d->nchars);
				memcpy (tmp->begin, d->in_buf->data->begin, d->in_buf->data->len);
				tmp->len = d->in_buf->data->len;
				d->in_buf->data = tmp;
			}
		}
		else if (policy == BUFFER_LINE) {
			if (d->in_buf && d->nchars < BUFSIZ) {
				tmp = fstralloc (d->pool, BUFSIZ);
				memcpy (tmp->begin, d->in_buf->data->begin, d->in_buf->data->len);
				tmp->len = d->in_buf->data->len;
				d->in_buf->data = tmp;
			}
		}
	}
}

void 
rspamd_dispatcher_write (rspamd_io_dispatcher_t *d,
									void *data,
									size_t len, gboolean delayed)
{
	rspamd_buffer_t *newbuf;

	newbuf = memory_pool_alloc (d->pool, sizeof (rspamd_buffer_t));
	newbuf->data = memory_pool_alloc (d->pool, sizeof (f_str_t));

	newbuf->data->begin = memory_pool_alloc (d->pool, len);
	memcpy (newbuf->data->begin, data, len);
	newbuf->data->size = len;
	newbuf->pos = newbuf->data->begin;
	
	d->out_buffers = g_list_prepend (d->out_buffers, newbuf);

	if (!delayed) {
		event_del (d->ev);
		event_set (d->ev, d->fd, EV_READ | EV_WRITE | EV_PERSIST, dispatcher_cb, (void *)d);
		event_add (d->ev, d->tv);
	}
}

void 
rspamd_dispatcher_pause (rspamd_io_dispatcher_t *d)
{
	event_del (d->ev);
}

/* 
 * vi:ts=4 
 */
