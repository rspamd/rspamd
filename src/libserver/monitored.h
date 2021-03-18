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

#ifdef  __cplusplus
extern "C" {
#endif

struct rspamd_monitored;
struct rspamd_monitored_ctx;
struct rspamd_config;

#define RSPAMD_MONITORED_TAG_LEN 32

enum rspamd_monitored_type {
	RSPAMD_MONITORED_DNS = 0,
};

enum rspamd_monitored_flags {
	RSPAMD_MONITORED_DEFAULT = 0u,
	RSPAMD_MONITORED_RBL = (1u << 0u),
	RSPAMD_MONITORED_RANDOM = (1u << 1u)
};

/**
 * Initialize new monitored context
 * @return opaque context pointer (should be configured)
 */
struct rspamd_monitored_ctx *rspamd_monitored_ctx_init (void);

typedef void (*mon_change_cb) (struct rspamd_monitored_ctx *ctx,
							   struct rspamd_monitored *m, gboolean alive,
							   void *ud);

/**
 * Configure context for monitored objects
 * @param ctx context
 * @param cfg configuration
 * @param ev_base events base
 * @param resolver resolver object
 */
void rspamd_monitored_ctx_config (struct rspamd_monitored_ctx *ctx,
								  struct rspamd_config *cfg,
								  struct ev_loop *ev_base,
								  struct rdns_resolver *resolver,
								  mon_change_cb change_cb,
								  gpointer ud);

struct ev_loop *rspamd_monitored_ctx_get_ev_base (struct rspamd_monitored_ctx *ctx);

/**
 * Create monitored object
 * @param ctx context
 * @param line string definition (e.g. hostname)
 * @param type type of monitoring
 * @param flags specific flags for monitoring
 * @return new monitored object
 */
struct rspamd_monitored *rspamd_monitored_create_ (
		struct rspamd_monitored_ctx *ctx,
		const gchar *line,
		enum rspamd_monitored_type type,
		enum rspamd_monitored_flags flags,
		const ucl_object_t *opts,
		const gchar *loc);

#define rspamd_monitored_create(ctx, line, type, flags, opts) \
    rspamd_monitored_create_(ctx, line, type, flags, opts, G_STRFUNC)

/**
 * Return monitored by its tag
 * @param ctx
 * @param tag
 * @return
 */
struct rspamd_monitored *rspamd_monitored_by_tag (struct rspamd_monitored_ctx *ctx,
												  guchar tag[RSPAMD_MONITORED_TAG_LEN]);

/**
 * Sets `tag_out` to the monitored tag
 * @param m
 * @param tag_out
 */
void rspamd_monitored_get_tag (struct rspamd_monitored *m,
							   guchar tag_out[RSPAMD_MONITORED_TAG_LEN]);

/**
 * Return TRUE if monitored object is alive
 * @param m monitored object
 * @return TRUE or FALSE
 */
gboolean rspamd_monitored_alive (struct rspamd_monitored *m);

/**
 * Force alive flag for a monitored object
 * @param m monitored object
 * @return TRUE or FALSE
 */
gboolean rspamd_monitored_set_alive (struct rspamd_monitored *m, gboolean alive);

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

#ifdef  __cplusplus
}
#endif

#endif /* SRC_LIBSERVER_MONITORED_H_ */
