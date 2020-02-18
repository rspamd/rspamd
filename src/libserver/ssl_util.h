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
#ifndef SRC_LIBUTIL_SSL_UTIL_H_
#define SRC_LIBUTIL_SSL_UTIL_H_

#include "config.h"
#include "libutil/addr.h"
#include "libutil/libev_helper.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct rspamd_ssl_connection;

typedef void (*rspamd_ssl_handler_t) (gint fd, short what, gpointer d);

typedef void (*rspamd_ssl_error_handler_t) (gpointer d, GError *err);

/**
 * Creates a new ssl connection data structure
 * @param ssl_ctx initialized SSL_CTX structure
 * @return opaque connection data
 */
struct rspamd_ssl_connection *rspamd_ssl_connection_new (gpointer ssl_ctx,
														 struct ev_loop *ev_base,
														 gboolean verify_peer,
														 const gchar *log_tag);

/**
 * Connects SSL session using the specified (connected) FD
 * @param conn connection
 * @param fd fd to use
 * @param hostname hostname for SNI
 * @param ev event to use
 * @param tv timeout for connection
 * @param handler connected session handler
 * @param handler_data opaque data
 * @return TRUE if a session has been connected
 */
gboolean rspamd_ssl_connect_fd (struct rspamd_ssl_connection *conn, gint fd,
								const gchar *hostname, struct rspamd_io_ev *ev, ev_tstamp timeout,
								rspamd_ssl_handler_t handler, rspamd_ssl_error_handler_t err_handler,
								gpointer handler_data);

/**
 * Perform async read from SSL socket
 * @param conn
 * @param buf
 * @param buflen
 * @return
 */
gssize rspamd_ssl_read (struct rspamd_ssl_connection *conn, gpointer buf,
						gsize buflen);

/**
 * Perform async write to ssl buffer
 * @param conn
 * @param buf
 * @param buflen
 * @param ev
 * @param tv
 * @return
 */
gssize rspamd_ssl_write (struct rspamd_ssl_connection *conn, gconstpointer buf,
						 gsize buflen);

/**
 * Emulate writev by copying iovec to a temporary buffer
 * @param conn
 * @param buf
 * @param buflen
 * @return
 */
gssize rspamd_ssl_writev (struct rspamd_ssl_connection *conn, struct iovec *iov,
						  gsize iovlen);

/**
 * Removes connection data
 * @param conn
 */
void rspamd_ssl_connection_free (struct rspamd_ssl_connection *conn);

gpointer rspamd_init_ssl_ctx (void);
gpointer rspamd_init_ssl_ctx_noverify (void);
void rspamd_ssl_ctx_config (struct rspamd_config *cfg, gpointer ssl_ctx);
void rspamd_ssl_ctx_free (gpointer ssl_ctx);
void rspamd_openssl_maybe_init (void);

#ifdef  __cplusplus
}
#endif

#endif /* SRC_LIBUTIL_SSL_UTIL_H_ */
