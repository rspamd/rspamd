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

#ifndef RSPAMD_HTTP_CONTEXT_H
#define RSPAMD_HTTP_CONTEXT_H

#include "config.h"
#include "ucl.h"
#include "addr.h"

#include "contrib/libev/ev.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct rspamd_http_context;
struct rspamd_config;
struct rspamd_http_message;
struct upstream_ctx;

struct rspamd_http_context_cfg {
	guint kp_cache_size_client;
	guint kp_cache_size_server;
	guint ssl_cache_size;
	gdouble keepalive_interval;
	gdouble client_key_rotate_time;
	const gchar *user_agent;
	const gchar *http_proxy;
	const gchar *server_hdr;
};

/**
 * Creates and configures new HTTP context
 * @param root_conf configuration object
 * @param ev_base event base
 * @return new context used for both client and server HTTP connections
 */
struct rspamd_http_context *rspamd_http_context_create (struct rspamd_config *cfg,
														struct ev_loop *ev_base,
														struct upstream_ctx *ctx);

struct rspamd_http_context *rspamd_http_context_create_config (
		struct rspamd_http_context_cfg *cfg,
		struct ev_loop *ev_base,
		struct upstream_ctx *ctx);

/**
 * Destroys context
 * @param ctx
 */
void rspamd_http_context_free (struct rspamd_http_context *ctx);

struct rspamd_http_context *rspamd_http_context_default (void);

/**
 * Returns preserved keepalive connection if it's available.
 * Refcount is transferred to caller!
 * @param ctx
 * @param addr
 * @param host
 * @return
 */
struct rspamd_http_connection *rspamd_http_context_check_keepalive (
		struct rspamd_http_context *ctx, const rspamd_inet_addr_t *addr,
		const gchar *host);

/**
 * Prepares keepalive key for a connection by creating a new entry or by reusing existent
 * Bear in mind, that keepalive pool has currently no cleanup methods!
 * @param ctx
 * @param conn
 * @param addr
 * @param host
 */
void rspamd_http_context_prepare_keepalive (struct rspamd_http_context *ctx,
											struct rspamd_http_connection *conn,
											const rspamd_inet_addr_t *addr,
											const gchar *host);

/**
 * Pushes a connection to keepalive pool after client request is finished,
 * keepalive key *must* be prepared before using of this function
 * @param ctx
 * @param conn
 * @param msg
 */
void rspamd_http_context_push_keepalive (struct rspamd_http_context *ctx,
										 struct rspamd_http_connection *conn,
										 struct rspamd_http_message *msg,
										 struct ev_loop *ev_base);

#ifdef  __cplusplus
}
#endif

#endif
