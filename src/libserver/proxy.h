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
#ifndef PROXY_H_
#define PROXY_H_

#include "config.h"
#include "buffer.h"
#include <event.h>

/**
 * @file proxy.h
 * Direct asynchronous proxy implementation
 */

typedef struct rspamd_proxy_s {
	struct event client_ev;                 /**< event for client's communication */
	struct event backend_ev;                /**< event for backend communication */
	struct event_base *base;                /**< base for event operations */
	rspamd_mempool_t *pool;                 /**< memory pool */
	dispatcher_err_callback_t err_cb;       /**< error callback	*/
	struct event_base *ev_base;             /**< event base */
	gint cfd;                               /**< client's socket */
	gint bfd;                               /**< backend's socket */
	guint8 *buf;                            /**< exchange buffer */
	gsize bufsize;                          /**< buffer size */
	gint read_len;                          /**< read length */
	gint buf_offset;                        /**< offset to write */
	gpointer user_data;                     /**< user's data for callbacks */
	struct timeval *tv;                     /**< timeout for communications */
	gboolean closed;                        /**< whether descriptors are closed */
} rspamd_proxy_t;

/**
 * Create new proxy between cfd and bfd
 * @param cfd client's socket
 * @param bfd backend's socket
 * @param bufsize size of exchange buffer
 * @param err_cb callback for erorrs or completing
 * @param ud user data for callback
 * @return new proxy object
 */
rspamd_proxy_t * rspamd_create_proxy (gint cfd,
	gint bfd,
	rspamd_mempool_t *pool,
	struct event_base *base,
	gsize bufsize,
	struct timeval *tv,
	dispatcher_err_callback_t err_cb,
	gpointer ud);

void rspamd_proxy_close (rspamd_proxy_t *proxy);

#endif /* PROXY_H_ */
