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
typedef void (*rspamd_aio_cb) (gint fd, gint res, guint64 len, gpointer data,
	gpointer ud);

/**
 * Initialize aio with specified event base
 */
struct aio_context * rspamd_aio_init (struct event_base *base);

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
