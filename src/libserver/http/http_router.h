/*-
 * Copyright 2019 Vsevolod Stakhov
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
#ifndef RSPAMD_HTTP_ROUTER_H
#define RSPAMD_HTTP_ROUTER_H

#include "config.h"
#include "http_connection.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct rspamd_http_connection_router;
struct rspamd_http_connection_entry;

typedef int (*rspamd_http_router_handler_t) (struct rspamd_http_connection_entry
											 *conn_ent,
											 struct rspamd_http_message *msg);

typedef void (*rspamd_http_router_error_handler_t) (struct rspamd_http_connection_entry *conn_ent,
													GError *err);

typedef void (*rspamd_http_router_finish_handler_t) (struct rspamd_http_connection_entry *conn_ent);


struct rspamd_http_connection_entry {
	struct rspamd_http_connection_router *rt;
	struct rspamd_http_connection *conn;
	gpointer ud;
	gboolean is_reply;
	gboolean support_gzip;
	struct rspamd_http_connection_entry *prev, *next;
};

struct rspamd_http_connection_router {
	struct rspamd_http_connection_entry *conns;
	GHashTable *paths;
	GHashTable *response_headers;
	GPtrArray *regexps;
	ev_tstamp timeout;
	struct ev_loop *event_loop;
	struct rspamd_http_context *ctx;
	gchar *default_fs_path;
	rspamd_http_router_handler_t unknown_method_handler;
	struct rspamd_cryptobox_keypair *key;
	rspamd_http_router_error_handler_t error_handler;
	rspamd_http_router_finish_handler_t finish_handler;
};

/**
 * Create new http connection router and the associated HTTP connection
 * @param eh error handler callback
 * @param fh finish handler callback
 * @param default_fs_path if not NULL try to serve static files from
 * the specified directory
 * @return
 */
struct rspamd_http_connection_router *rspamd_http_router_new (
		rspamd_http_router_error_handler_t eh,
		rspamd_http_router_finish_handler_t fh,
		ev_tstamp timeout,
		const char *default_fs_path,
		struct rspamd_http_context *ctx);

/**
 * Set encryption key for the HTTP router
 * @param router router structure
 * @param key opaque key structure
 */
void rspamd_http_router_set_key (struct rspamd_http_connection_router *router,
								 struct rspamd_cryptobox_keypair *key);

/**
 * Add new path to the router
 */
void rspamd_http_router_add_path (struct rspamd_http_connection_router *router,
								  const gchar *path, rspamd_http_router_handler_t handler);

/**
 * Add custom header to append to router replies
 * @param router
 * @param name
 * @param value
 */
void rspamd_http_router_add_header (struct rspamd_http_connection_router *router,
									const gchar *name, const gchar *value);

/**
 * Sets method to handle unknown request methods
 * @param router
 * @param handler
 */
void rspamd_http_router_set_unknown_handler (struct rspamd_http_connection_router *router,
											 rspamd_http_router_handler_t handler);

/**
 * Inserts router headers to the outbound message
 * @param router
 * @param msg
 */
void rspamd_http_router_insert_headers (struct rspamd_http_connection_router *router,
										struct rspamd_http_message *msg);

struct rspamd_regexp_s;

/**
 * Adds new pattern to router, regexp object is refcounted by this function
 * @param router
 * @param re
 * @param handler
 */
void rspamd_http_router_add_regexp (struct rspamd_http_connection_router *router,
									struct rspamd_regexp_s *re, rspamd_http_router_handler_t handler);

/**
 * Handle new accepted socket
 * @param router router object
 * @param fd server socket
 * @param ud opaque userdata
 */
void rspamd_http_router_handle_socket (
		struct rspamd_http_connection_router *router,
		gint fd,
		gpointer ud);

/**
 * Free router and all connections associated
 * @param router
 */
void rspamd_http_router_free (struct rspamd_http_connection_router *router);

#ifdef  __cplusplus
}
#endif

#endif
