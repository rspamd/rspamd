/*-
 * Copyright 2016 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "config.h"
#include "rspamd.h"
#include "proxy.h"
#include "unix-std.h"

static void rspamd_proxy_backend_handler (gint fd, gshort what, gpointer data);
static void rspamd_proxy_client_handler (gint fd, gshort what, gpointer data);

static inline GQuark
proxy_error_quark (void)
{
	return g_quark_from_static_string ("proxy-error");
}

void
rspamd_proxy_close (rspamd_proxy_t *proxy)
{
	if (!proxy->closed) {
		close (proxy->cfd);
		close (proxy->bfd);

		event_del (&proxy->client_ev);
		event_del (&proxy->backend_ev);
		proxy->closed = TRUE;
	}
}

static void
rspamd_proxy_client_handler (gint fd, gshort what, gpointer data)
{
	rspamd_proxy_t *proxy = data;
	gint r;
	GError *err = NULL;

	if (what == EV_READ) {
		/* Got data from client */
		event_del (&proxy->client_ev);
		r = read (proxy->cfd, proxy->buf, proxy->bufsize);
		if (r > 0) {
			/* Write this buffer to backend */
			proxy->read_len = r;
			proxy->buf_offset = 0;
			event_del (&proxy->backend_ev);
			event_set (&proxy->backend_ev,
				proxy->bfd,
				EV_WRITE,
				rspamd_proxy_backend_handler,
				proxy);
			event_add (&proxy->backend_ev, proxy->tv);
		}
		else {
			/* Error case or zero reply */
			if (r < 0) {
				/* Error case */
				g_set_error (&err,
					proxy_error_quark (), r, "Client read error: %s",
					strerror (errno));
				rspamd_proxy_close (proxy);
				proxy->err_cb (err, proxy->user_data);
			}
			else {
				/* Client closes connection */
				rspamd_proxy_close (proxy);
				proxy->err_cb (NULL, proxy->user_data);
			}
		}
	}
	else if (what == EV_WRITE) {
		/* Can write to client */
		r = write (proxy->cfd,
				proxy->buf + proxy->buf_offset,
				proxy->read_len - proxy->buf_offset);
		if (r > 0) {
			/* We wrote something */
			proxy->buf_offset += r;
			if (proxy->buf_offset == proxy->read_len) {
				/* We wrote everything */
				event_del (&proxy->client_ev);
				event_set (&proxy->client_ev,
					proxy->cfd,
					EV_READ,
					rspamd_proxy_client_handler,
					proxy);
				event_add (&proxy->client_ev, proxy->tv);
				event_del (&proxy->backend_ev);
				event_set (&proxy->backend_ev,
					proxy->bfd,
					EV_READ,
					rspamd_proxy_backend_handler,
					proxy);
				event_add (&proxy->backend_ev, proxy->tv);
			}
			else {
				/* Plan another write event */
				event_add (&proxy->backend_ev, proxy->tv);
			}
		}
		else {
			/* Error case or zero reply */
			if (r < 0) {
				/* Error case */
				g_set_error (&err,
					proxy_error_quark (), r, "Client write error: %s",
					strerror (errno));
				rspamd_proxy_close (proxy);
				proxy->err_cb (err, proxy->user_data);
			}
			else {
				/* Client closes connection */
				rspamd_proxy_close (proxy);
				proxy->err_cb (NULL, proxy->user_data);
			}
		}
	}
	else {
		/* Got timeout */
		g_set_error (&err, proxy_error_quark (), ETIMEDOUT, "Client timeout");
		rspamd_proxy_close (proxy);
		proxy->err_cb (err, proxy->user_data);
	}
}

static void
rspamd_proxy_backend_handler (gint fd, gshort what, gpointer data)
{
	rspamd_proxy_t *proxy = data;
	gint r;
	GError *err = NULL;

	if (what == EV_READ) {
		/* Got data from backend */
		event_del (&proxy->backend_ev);
		r = read (proxy->bfd, proxy->buf, proxy->bufsize);
		if (r > 0) {
			/* Write this buffer to client */
			proxy->read_len = r;
			proxy->buf_offset = 0;
			event_del (&proxy->client_ev);
			event_set (&proxy->client_ev,
				proxy->bfd,
				EV_WRITE,
				rspamd_proxy_client_handler,
				proxy);
			event_add (&proxy->client_ev, proxy->tv);
		}
		else {
			/* Error case or zero reply */
			if (r < 0) {
				/* Error case */
				g_set_error (&err,
					proxy_error_quark (), r, "Backend read error: %s",
					strerror (errno));
				rspamd_proxy_close (proxy);
				proxy->err_cb (err, proxy->user_data);
			}
			else {
				/* Client closes connection */
				rspamd_proxy_close (proxy);
				proxy->err_cb (NULL, proxy->user_data);
			}
		}
	}
	else if (what == EV_WRITE) {
		/* Can write to backend */
		r = write (proxy->bfd,
				proxy->buf + proxy->buf_offset,
				proxy->read_len - proxy->buf_offset);
		if (r > 0) {
			/* We wrote something */
			proxy->buf_offset += r;
			if (proxy->buf_offset == proxy->read_len) {
				/* We wrote everything */
				event_del (&proxy->backend_ev);
				event_set (&proxy->backend_ev,
					proxy->bfd,
					EV_READ,
					rspamd_proxy_backend_handler,
					proxy);
				event_add (&proxy->backend_ev, proxy->tv);
				event_del (&proxy->client_ev);
				event_set (&proxy->client_ev,
					proxy->cfd,
					EV_READ,
					rspamd_proxy_client_handler,
					proxy);
				event_add (&proxy->client_ev, proxy->tv);
			}
			else {
				/* Plan another write event */
				event_add (&proxy->backend_ev, proxy->tv);
			}
		}
		else {
			/* Error case or zero reply */
			if (r < 0) {
				/* Error case */
				g_set_error (&err,
					proxy_error_quark (), r, "Backend write error: %s",
					strerror (errno));
				rspamd_proxy_close (proxy);
				proxy->err_cb (err, proxy->user_data);
			}
			else {
				/* Client closes connection */
				rspamd_proxy_close (proxy);
				proxy->err_cb (NULL, proxy->user_data);
			}
		}
	}
	else {
		/* Got timeout */
		g_set_error (&err, proxy_error_quark (), ETIMEDOUT, "Client timeout");
		rspamd_proxy_close (proxy);
		proxy->err_cb (err, proxy->user_data);
	}
}

/**
 * Create new proxy between cfd and bfd
 * @param cfd client's socket
 * @param bfd backend's socket
 * @param bufsize size of exchange buffer
 * @param err_cb callback for erorrs or completing
 * @param ud user data for callback
 * @return new proxy object
 */
rspamd_proxy_t *
rspamd_create_proxy (gint cfd,
	gint bfd,
	rspamd_mempool_t *pool,
	struct event_base *base,
	gsize bufsize,
	struct timeval *tv,
	dispatcher_err_callback_t err_cb,
	gpointer ud)
{
	rspamd_proxy_t *new;

	new = rspamd_mempool_alloc0 (pool, sizeof (rspamd_proxy_t));

	new->cfd = dup (cfd);
	new->bfd = dup (bfd);
	new->pool = pool;
	new->base = base;
	new->bufsize = bufsize;
	new->buf = rspamd_mempool_alloc (pool, bufsize);
	new->err_cb = err_cb;
	new->user_data = ud;
	new->tv = tv;

	/* Set client's and backend's interfaces to read events */
	event_set (&new->client_ev,
		new->cfd,
		EV_READ,
		rspamd_proxy_client_handler,
		new);
	event_base_set (new->base, &new->client_ev);
	event_add (&new->client_ev, new->tv);

	event_set (&new->backend_ev,
		new->bfd,
		EV_READ,
		rspamd_proxy_backend_handler,
		new);
	event_base_set (new->base, &new->backend_ev);
	event_add (&new->backend_ev, new->tv);

	return new;
}
