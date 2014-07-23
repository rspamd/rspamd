/* Copyright (c) 2010-2012, Vsevolod Stakhov
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


#ifndef PROXY_H_
#define PROXY_H_

#include "config.h"
#include "buffer.h"

/**
 * @file proxy.h
 * Direct asynchronous proxy implementation
 */

typedef struct rspamd_proxy_s {
	struct event client_ev;					/**< event for client's communication */
	struct event backend_ev; 				/**< event for backend communication */
	struct event_base *base;				/**< base for event operations */
	rspamd_mempool_t *pool;					/**< memory pool */
	dispatcher_err_callback_t err_cb;		/**< error callback	*/
	struct event_base *ev_base;				/**< event base */
	gint cfd;								/**< client's socket */
	gint bfd;								/**< backend's socket */
	guint8 *buf;							/**< exchange buffer */
	gsize bufsize;							/**< buffer size */
	gint read_len;							/**< read length */
	gint buf_offset;						/**< offset to write */
	gpointer user_data;						/**< user's data for callbacks */
	struct timeval *tv;						/**< timeout for communications */
	gboolean closed;						/**< whether descriptors are closed */
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
rspamd_proxy_t* rspamd_create_proxy (gint cfd, gint bfd, rspamd_mempool_t *pool,
		struct event_base *base, gsize bufsize, struct timeval *tv,
		dispatcher_err_callback_t err_cb, gpointer ud);

void rspamd_proxy_close (rspamd_proxy_t *proxy);

#endif /* PROXY_H_ */
