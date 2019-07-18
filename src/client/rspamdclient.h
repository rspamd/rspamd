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
#ifndef RSPAMDCLIENT_H_
#define RSPAMDCLIENT_H_

#include "config.h"
#include "ucl.h"
#include "contrib/libev/ev.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct rspamd_client_connection;
struct rspamd_http_message;

struct rspamd_http_client_header {
	gchar *name;
	gchar *value;
};

/**
 * Callback is called on client connection completed
 * @param name name of server
 * @param port port for server
 * @param result result object
 * @param ud opaque user data
 * @param err error pointer
 */
typedef void (*rspamd_client_callback) (
		struct rspamd_client_connection *conn,
		struct rspamd_http_message *msg,
		const gchar *name,
		ucl_object_t *result,
		GString *input,
		gpointer ud,
		gdouble start_time,
		gdouble send_time,
		const gchar *body,
		gsize body_len,
		GError *err);

struct rspamd_http_context;

/**
 * Start rspamd worker or controller command
 * @param ev_base event base
 * @param name server name (hostname or unix socket)
 * @param port port number (in host order)
 * @param timeout timeout in seconds
 * @return
 */
struct rspamd_client_connection *rspamd_client_init (
		struct rspamd_http_context *http_ctx,
		struct ev_loop *ev_base,
		const gchar *name,
		guint16 port,
		gdouble timeout,
		const gchar *key);

/**
 *
 * @param conn connection object
 * @param command command name
 * @param attrs additional attributes
 * @param in input file or NULL if no input required
 * @param cb callback to be called on command completion
 * @param ud opaque user data
 * @return
 */
gboolean rspamd_client_command (
		struct rspamd_client_connection *conn,
		const gchar *command,
		GQueue *attrs,
		FILE *in,
		rspamd_client_callback cb,
		gpointer ud,
		gboolean compressed,
		const gchar *comp_dictionary,
		const gchar *filename,
		GError **err);

/**
 * Destroy a connection to rspamd
 * @param conn
 */
void rspamd_client_destroy (struct rspamd_client_connection *conn);

#ifdef  __cplusplus
}
#endif

#endif /* RSPAMDCLIENT_H_ */
