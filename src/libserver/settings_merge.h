/*
 * Copyright 2026 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef RSPAMD_SETTINGS_MERGE_H
#define RSPAMD_SETTINGS_MERGE_H

#include "config.h"
#include "mem_pool.h"
#include <ucl.h>

#ifdef __cplusplus
extern "C" {
#endif

struct rspamd_config;

/**
 * Settings layer hierarchy (lower value = lower priority)
 */
enum rspamd_settings_layer {
	RSPAMD_SETTINGS_LAYER_CONFIG = 0,   /* Global config defaults */
	RSPAMD_SETTINGS_LAYER_PROFILE = 1,  /* Fast settings ID (inbound/outbound/vip) */
	RSPAMD_SETTINGS_LAYER_RULE = 2,     /* Rule-matched settings from Lua plugin */
	RSPAMD_SETTINGS_LAYER_PER_USER = 3, /* Per-user from redis or external source */
	RSPAMD_SETTINGS_LAYER_HTTP = 4,     /* HTTP header per-request override */
};

/**
 * Opaque merge context
 */
struct rspamd_settings_merge_ctx;

/**
 * Create a new merge context allocated in the given memory pool
 * @param pool memory pool for allocations
 * @param cfg rspamd config (needed for group expansion)
 * @return new merge context
 */
struct rspamd_settings_merge_ctx *rspamd_settings_merge_ctx_create(
	rspamd_mempool_t *pool,
	struct rspamd_config *cfg);

/**
 * Add a settings layer to the merge context
 * @param ctx merge context
 * @param level layer priority level
 * @param name human-readable name of this layer source
 * @param settings_id numeric settings ID (0 if not ID-based)
 * @param settings UCL settings object (ref will be taken)
 */
void rspamd_settings_merge_add_layer(
	struct rspamd_settings_merge_ctx *ctx,
	enum rspamd_settings_layer level,
	const char *name,
	uint32_t settings_id,
	const ucl_object_t *settings);

/**
 * Perform the merge of all added layers and return the result
 * @param ctx merge context
 * @return merged UCL settings object (caller owns the ref), or NULL if no layers
 */
ucl_object_t *rspamd_settings_merge_finalize(
	struct rspamd_settings_merge_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* RSPAMD_SETTINGS_MERGE_H */
