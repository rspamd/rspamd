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

#include <event.h>

struct rspamd_http_context;
struct rspamd_config;

struct rspamd_http_context_cfg {
	guint kp_cache_size_client;
	guint kp_cache_size_server;
	guint ssl_cache_size;
	gdouble client_key_rotate_time;
	const gchar *user_agent;
};

/**
 * Creates and configures new HTTP context
 * @param root_conf configuration object
 * @param ev_base event base
 * @return new context used for both client and server HTTP connections
 */
struct rspamd_http_context* rspamd_http_context_create (struct rspamd_config *cfg,
		struct event_base *ev_base);

struct rspamd_http_context* rspamd_http_context_create_config (
		struct rspamd_http_context_cfg *cfg,
		struct event_base *ev_base);
/**
 * Destroys context
 * @param ctx
 */
void rspamd_http_context_free (struct rspamd_http_context *ctx);

struct rspamd_http_context* rspamd_http_context_default (void);

#endif
