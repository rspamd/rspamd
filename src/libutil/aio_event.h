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


#ifndef AIO_EVENT_H_
#define AIO_EVENT_H_

#include "config.h"

/**
 * AIO context
 */
struct aio_context;

/**
 * Callback for notifying
 */
typedef void (*rspamd_aio_cb) (gint fd, gint res, guint64 len, gpointer data, gpointer ud);

/**
 * Initialize aio with specified event base
 */
struct aio_context* rspamd_aio_init (struct event_base *base);

/**
 * Open file for aio
 */
gint rspamd_aio_open (struct aio_context *ctx, const gchar *path, int flags);

/**
 * Asynchronous read of file
 */
gint rspamd_aio_read (gint fd, gpointer buf, guint64 len, guint64 offset,
		struct aio_context *ctx, rspamd_aio_cb cb, gpointer ud);

/**
 * Asynchronous write of file
 */
gint rspamd_aio_write (gint fd, gpointer buf, guint64 len, guint64 offset,
		struct aio_context *ctx, rspamd_aio_cb cb, gpointer ud);

/**
 * Close of aio operations
 */
gint rspamd_aio_close (gint fd, struct aio_context *ctx);

#endif /* AIO_EVENT_H_ */
