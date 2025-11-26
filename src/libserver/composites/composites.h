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

#ifdef __cplusplus
}
#endif

#endif /* SRC_LIBSERVER_COMPOSITES_H_ */
