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
#ifndef SRC_LIBSERVER_COMPOSITES_H_
#define SRC_LIBSERVER_COMPOSITES_H_

#include "config.h"
#include "contrib/libucl/ucl.h"

#ifdef __cplusplus
extern "C" {
#endif

struct rspamd_task;
struct rspamd_config;

/**
 * Process all results and form composite metrics from existent metrics as it is defined in config
 * @param task worker's task that present message from user
 */
void rspamd_composites_process_task(struct rspamd_task *task);

/**
 * Creates a composites manager
 * @param cfg
 * @return
 */
void *rspamd_composites_manager_create(struct rspamd_config *cfg);
/**
 * Returns number of elements in a composite manager
 * @return
 */
gsize rspamd_composites_manager_nelts(void *);
/**
 * Adds a composite from config
 * @return
 */
void *rspamd_composites_manager_add_from_ucl(void *, const char *, const ucl_object_t *);
void *rspamd_composites_manager_add_from_ucl_silent(void *, const char *, const ucl_object_t *);

/**
 * Adds a composite from config
 * @return
 */
void *rspamd_composites_manager_add_from_string(void *, const char *, const char *);
void *rspamd_composites_manager_add_from_string_silent(void *, const char *, const char *);

/**
 * Process composite dependencies to split into first/second pass
 * Should be called after symcache is finalized
 * @param cm_ptr composites manager pointer
 * @param cfg config structure
 */
void rspamd_composites_process_deps(void *cm_ptr, struct rspamd_config *cfg);

/**
 * Enable or disable inverted index for fast composite lookup
 * @param cm_ptr composites manager pointer
 * @param enabled true to enable, false to disable
 */
void rspamd_composites_set_inverted_index(void *cm_ptr, gboolean enabled);

/**
 * Get whether inverted index is enabled
 * @param cm_ptr composites manager pointer
 * @return true if enabled
 */
gboolean rspamd_composites_get_inverted_index(void *cm_ptr);

/**
 * Statistics structure for composite processing
 */
struct rspamd_composites_stats_export {
	uint64_t checked_slow;    /**< composites checked via slow path */
	uint64_t checked_fast;    /**< composites checked via inverted index */
	uint64_t matched;         /**< composites that matched */
	double time_slow_mean;    /**< EMA mean time in slow path (ms) */
	double time_slow_stddev;  /**< EMA stddev time in slow path (ms) */
	double time_fast_mean;    /**< EMA mean time in fast path (ms) */
	double time_fast_stddev;  /**< EMA stddev time in fast path (ms) */
	uint64_t time_slow_count; /**< number of slow path measurements */
	uint64_t time_fast_count; /**< number of fast path measurements */
};

/**
 * Get composite processing statistics
 * @param cm_ptr composites manager pointer
 * @param stats output structure
 */
void rspamd_composites_get_stats(void *cm_ptr, struct rspamd_composites_stats_export *stats);

/**
 * Mark symbols used in whitelist composites (negative score) with SYMBOL_TYPE_FINE
 * so they won't be skipped when reject threshold is reached. This ensures
 * whitelist composites can still evaluate correctly.
 *
 * Also performs the last step of static composites load — pinning the
 * static-config generation as the base and recording its names — so that
 * subsequent dynamic-map publishes can clone from a stable base. Safe to
 * call multiple times.
 *
 * @param cm_ptr composites manager pointer
 * @param cfg config structure
 */
void rspamd_composites_mark_whitelist_deps(void *cm_ptr, struct rspamd_config *cfg);

/**
 * Register a dynamic composites map. The map is read as a UCL object
 * mapping composite name → { expression, score, group, policy, description,
 * groups, enabled }. On every reload the manager builds a fresh staging
 * generation off the static base, layers the map's composites, materialises
 * disabled stubs for names this map previously published but no longer
 * mentions, and atomically swaps it in. In-flight tasks keep their
 * pinned snapshot and continue with the previous generation.
 *
 * @param cm_ptr composites manager pointer
 * @param obj UCL object describing the map (string URL, array of URLs,
 *            or full map UCL with backends/signature/etc.)
 * @param cfg config structure
 * @return true if the map was registered with the watcher
 */
bool rspamd_composites_add_dynamic_map(void *cm_ptr, const ucl_object_t *obj,
									   struct rspamd_config *cfg);

/**
 * Returns the current composites generation id (monotonically increasing
 * across publishes). 0 if the manager has not published anything yet.
 */
uint64_t rspamd_composites_current_generation(void *cm_ptr);

#ifdef __cplusplus
}
#endif

#endif /* SRC_LIBSERVER_COMPOSITES_H_ */
