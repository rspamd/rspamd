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
#ifndef SRC_LIBSERVER_MONITORED_H_
#define SRC_LIBSERVER_MONITORED_H_

#include "config.h"
#include "rdns.h"

struct rspamd_monitored;
struct rspamd_monitored_ctx;
struct rspamd_config;

enum rspamd_monitored_type {
	RSPAMD_MONITORED_DNS = 0,
};

enum rspamd_monitored_flags {
	RSPAMD_MONITORED_DEFAULT = 0,
	RSPAMD_MONITORED_RBL = (1 << 0),
};

/**
 * Initialize new monitored context
 * @return opaque context pointer (should be configured)
 */
struct rspamd_monitored_ctx *rspamd_monitored_ctx_init (void);

/**
 * Configure context for monitored objects
 * @param ctx context
 * @param cfg configuration
 * @param ev_base events base
 * @param resolver resolver object
 */
void rspamd_monitored_ctx_config (struct rspamd_monitored_ctx *ctx,
		struct rspamd_config *cfg,
		struct event_base *ev_base,
		struct rdns_resolver *resolver);

/**
 * Create monitored object
 * @param ctx context
 * @param line string definition (e.g. hostname)
 * @param type type of monitoring
 * @param flags specific flags for monitoring
 * @return new monitored object
 */
struct rspamd_monitored *rspamd_monitored_create (
		struct rspamd_monitored_ctx *ctx,
		const gchar *line,
		enum rspamd_monitored_type type,
		enum rspamd_monitored_flags flags,
		const ucl_object_t *opts);

/**
 * Return TRUE if monitored object is alive
 * @param m monitored object
 * @return TRUE or FALSE
 */
gboolean rspamd_monitored_alive (struct rspamd_monitored *m);

/**
 * Returns the current offline time for a monitored object
 * @param m
 * @return
 */
gdouble rspamd_monitored_offline_time (struct rspamd_monitored *m);

/**
 * Returns the total offline time for a monitored object
 * @param m
 * @return
 */
gdouble rspamd_monitored_total_offline_time (struct rspamd_monitored *m);

/**
 * Returns the latency for monitored object (in seconds)
 * @param m
 * @return
 */
gdouble rspamd_monitored_latency (struct rspamd_monitored *m);

/**
 * Explicitly disable monitored object
 * @param m
 */
void rspamd_monitored_stop (struct rspamd_monitored *m);
/**
 * Explicitly enable monitored object
 * @param m
 */
void rspamd_monitored_start (struct rspamd_monitored *m);

/**
 * Destroy monitored context and all monitored objects inside
 * @param ctx
 */
void rspamd_monitored_ctx_destroy (struct rspamd_monitored_ctx *ctx);

#endif /* SRC_LIBSERVER_MONITORED_H_ */
