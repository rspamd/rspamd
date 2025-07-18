/*
 * Copyright 2023 Vsevolod Stakhov
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
#ifndef RSPAMD_SYMBOLS_CACHE_H
#define RSPAMD_SYMBOLS_CACHE_H

#include "config.h"
#include "ucl.h"
#include "cfg_file.h"
#include "contrib/libev/ev.h"

#include <lua.h>

#ifdef __cplusplus
extern "C" {
#endif

struct rspamd_task;
struct rspamd_config;
struct rspamd_symcache;
struct rspamd_worker;
struct rspamd_symcache_dynamic_item;
struct rspamd_symcache_item;
struct rspamd_config_settings_elt;

typedef void (*symbol_func_t)(struct rspamd_task *task,
							  struct rspamd_symcache_dynamic_item *item,
							  gpointer user_data);

enum rspamd_symbol_type {
	SYMBOL_TYPE_NORMAL = (1u << 0u),
	SYMBOL_TYPE_VIRTUAL = (1u << 1u),
	SYMBOL_TYPE_CALLBACK = (1u << 2u),
	SYMBOL_TYPE_GHOST = (1u << 3u),
	SYMBOL_TYPE_SKIPPED = (1u << 4u),
	SYMBOL_TYPE_COMPOSITE = (1u << 5u),
	SYMBOL_TYPE_CLASSIFIER = (1u << 6u),
	SYMBOL_TYPE_FINE = (1u << 7u),
	SYMBOL_TYPE_EMPTY = (1u << 8u),      /* Allow execution on empty tasks */
	SYMBOL_TYPE_CONNFILTER = (1u << 9u), /* Connection stage filter */
	SYMBOL_TYPE_PREFILTER = (1u << 10u),
	SYMBOL_TYPE_POSTFILTER = (1u << 11u),
	SYMBOL_TYPE_NOSTAT = (1u << 12u),             /* Skip as statistical symbol */
	SYMBOL_TYPE_IDEMPOTENT = (1u << 13u),         /* Symbol cannot change metric */
	SYMBOL_TYPE_TRIVIAL = (1u << 14u),            /* Symbol is trivial */
	SYMBOL_TYPE_MIME_ONLY = (1u << 15u),          /* Symbol is mime only */
	SYMBOL_TYPE_EXPLICIT_DISABLE = (1u << 16u),   /* Symbol should be disabled explicitly only */
	SYMBOL_TYPE_IGNORE_PASSTHROUGH = (1u << 17u), /* Symbol ignores passthrough result */
	SYMBOL_TYPE_EXPLICIT_ENABLE = (1u << 18u),    /* Symbol should be enabled explicitly only */
	SYMBOL_TYPE_USE_CORO = (1u << 19u),           /* Symbol uses lua coroutines */
};

/**
 * Abstract structure for saving callback data for symbols
 */
struct rspamd_abstract_callback_data {
	uint64_t magic;
	char data[];
};

/**
 * Shared memory block specific for each symbol
 */
struct rspamd_symcache_item_stat {
	struct rspamd_counter_data time_counter;
	double avg_time;
	double weight;
	unsigned int hits;
	uint64_t total_hits;
	struct rspamd_counter_data frequency_counter;
	double avg_frequency;
	double stddev_frequency;
};

/**
 * Creates new cache structure
 * @return
 */
struct rspamd_symcache *rspamd_symcache_new(struct rspamd_config *cfg);

/**
 * Remove the cache structure syncing data if needed
 * @param cache
 */
void rspamd_symcache_destroy(struct rspamd_symcache *cache);

/**
 * Saves symbols cache to disk if possible
 * @param cache
 */
void rspamd_symcache_save(struct rspamd_symcache *cache);

/**
 * Load symbols cache from file, must be called _after_ init_symbols_cache
 */
gboolean rspamd_symcache_init(struct rspamd_symcache *cache);

/**
 * Generic function to register a symbol
 * @param cache
 * @param name
 * @param weight
 * @param priority
 * @param func
 * @param user_data
 * @param type
 * @param parent
 */
int rspamd_symcache_add_symbol(struct rspamd_symcache *cache,
							   const char *name,
							   int priority,
							   symbol_func_t func,
							   gpointer user_data,
							   int type,
							   int parent);

/**
 * Adds augmentation to the symbol
 * @param cache
 * @param sym_id
 * @param augmentation
 * @return
 */
bool rspamd_symcache_add_symbol_augmentation(struct rspamd_symcache *cache,
											 int sym_id,
											 const char *augmentation,
											 const char *value);

/**
 * Add callback to be executed whenever symbol has peak value
 * @param cache
 * @param cbref
 */
void rspamd_symcache_set_peak_callback(struct rspamd_symcache *cache,
									   int cbref);

/**
 * Add delayed condition to the specific symbol in cache. So symbol can be absent
 * to the moment of addition
 * @param cache
 * @param id id of symbol
 * @param L lua state pointer
 * @param cbref callback reference (returned by luaL_ref)
 * @return TRUE if condition has been added
 */
gboolean rspamd_symcache_add_condition_delayed(struct rspamd_symcache *cache,
											   const char *sym,
											   lua_State *L, int cbref);

/**
 * Find symbol in cache by id and returns its id resolving virtual symbols if
 * applicable
 * @param cache
 * @param name
 * @return id of symbol or (-1) if a symbol has not been found
 */
int rspamd_symcache_find_symbol(struct rspamd_symcache *cache,
								const char *name);

/**
 * Get statistics for a specific symbol
 * @param cache
 * @param name
 * @param frequency
 * @param tm
 * @return
 */
gboolean rspamd_symcache_stat_symbol(struct rspamd_symcache *cache,
									 const char *name,
									 double *frequency,
									 double *freq_stddev,
									 double *tm,
									 unsigned int *nhits);

/**
 * Returns number of symbols registered in symbols cache
 * @param cache
 * @return number of symbols in the cache
 */
unsigned int rspamd_symcache_stats_symbols_count(struct rspamd_symcache *cache);

/**
 * Validate cache items against theirs weights defined in metrics
 * @param cache symbols cache
 * @param cfg configuration
 * @param strict do strict checks - symbols MUST be described in metrics
 */
gboolean rspamd_symcache_validate(struct rspamd_symcache *cache,
								  struct rspamd_config *cfg,
								  gboolean strict);

/**
 * Call function for cached symbol using saved callback
 * @param task task object
 * @param cache symbols cache
 * @param saved_item pointer to currently saved item
 */
gboolean rspamd_symcache_process_symbols(struct rspamd_task *task,
										 struct rspamd_symcache *cache,
										 unsigned int stage);

/**
 * Return statistics about the cache as ucl object (array of objects one per item)
 * @param cache
 * @return
 */
ucl_object_t *rspamd_symcache_counters(struct rspamd_symcache *cache);

/**
 * Start cache reloading
 * @param cache
 * @param ev_base
 */
void *rspamd_symcache_start_refresh(struct rspamd_symcache *cache,
									struct ev_loop *ev_base,
									struct rspamd_worker *w);

/**
 * Increases counter for a specific symbol
 * @param cache
 * @param symbol
 */
void rspamd_symcache_inc_frequency(struct rspamd_symcache *_cache,
								   struct rspamd_symcache_item *item,
								   const char *sym_name);

/**
 * Add delayed dependency that is resolved on cache post-load routine
 * @param cache
 * @param from
 * @param to
 */
void rspamd_symcache_add_delayed_dependency(struct rspamd_symcache *cache,
											const char *from, const char *to);

/**
 * Get abstract callback data for a symbol (or its parent symbol)
 * @param cache cache object
 * @param symbol symbol name
 * @return abstract callback data or NULL if symbol is absent or has no data attached
 */
struct rspamd_abstract_callback_data *rspamd_symcache_get_cbdata(
	struct rspamd_symcache *cache, const char *symbol);

/**
 * Returns symbol's parent name (or symbol name itself)
 * @param cache
 * @param symbol
 * @return
 */
const char *rspamd_symcache_get_parent(struct rspamd_symcache *cache,
									   const char *symbol);

unsigned int rspamd_symcache_get_symbol_flags(struct rspamd_symcache *cache,
											  const char *symbol);

void rspamd_symcache_get_symbol_details(struct rspamd_symcache *cache,
										const char *symbol,
										ucl_object_t *this_sym_ucl);


/**
 * Process settings for task
 * @param task
 * @param cache
 * @return
 */
gboolean rspamd_symcache_process_settings(struct rspamd_task *task,
										  struct rspamd_symcache *cache);


/**
 * Checks if a symbol specified has been checked (or disabled)
 * @param task
 * @param cache
 * @param symbol
 * @return
 */
gboolean rspamd_symcache_is_checked(struct rspamd_task *task,
									struct rspamd_symcache *cache,
									const char *symbol);

/**
 * Returns checksum for all cache items
 * @param cache
 * @return
 */
uint64_t rspamd_symcache_get_cksum(struct rspamd_symcache *cache);

/**
 * Checks if a symbols is enabled (not checked and conditions return true if present)
 * @param task
 * @param cache
 * @param symbol
 * @return
 */
gboolean rspamd_symcache_is_symbol_enabled(struct rspamd_task *task,
										   struct rspamd_symcache *cache,
										   const char *symbol);

/**
 * Enable this symbol for task
 * @param task
 * @param cache
 * @param symbol
 * @return TRUE if a symbol has been enabled (not executed before)
 */
gboolean rspamd_symcache_enable_symbol(struct rspamd_task *task,
									   struct rspamd_symcache *cache,
									   const char *symbol);

/**
 * Enable this symbol for task
 * @param task
 * @param cache
 * @param symbol
 * @return TRUE if a symbol has been disabled (not executed before)
 */
gboolean rspamd_symcache_disable_symbol(struct rspamd_task *task,
										struct rspamd_symcache *cache,
										const char *symbol);

/**
 * Disable execution of a symbol or a pattern (a string enclosed in `//`) permanently
 * @param task
 * @param cache
 * @param symbol
 * @return
 */
void rspamd_symcache_disable_symbol_static(struct rspamd_symcache *cache,
										   const char *symbol);
/**
 * Add a symbol or a pattern to the list of explicitly and statically enabled symbols
 * @param cache
 * @param symbol
 * @return
 */
void rspamd_symcache_enable_symbol_static(struct rspamd_symcache *cache,
										  const char *symbol);

/**
 * Process specific function for each cache element (in order they are added)
 * @param cache
 * @param func
 * @param ud
 */
void rspamd_symcache_foreach(struct rspamd_symcache *cache,
							 void (*func)(struct rspamd_symcache_item *item, gpointer /* userdata */),
							 gpointer ud);

/**
 * Returns the current item being processed (if any)
 * @param task
 * @return
 */
struct rspamd_symcache_dynamic_item *rspamd_symcache_get_cur_item(struct rspamd_task *task);

/**
 * Replaces the current item being processed.
 * Returns the current item being processed (if any)
 * @param task
 * @param item
 * @return
 */
struct rspamd_symcache_dynamic_item *rspamd_symcache_set_cur_item(struct rspamd_task *task,
																  struct rspamd_symcache_dynamic_item *item);


/**
 * Finalize the current async element potentially calling its deps
 */
void rspamd_symcache_finalize_item(struct rspamd_task *task,
								   struct rspamd_symcache_dynamic_item *item);

/*
 * Increase number of async events pending for an item
 */
unsigned int rspamd_symcache_item_async_inc_full(struct rspamd_task *task,
												 struct rspamd_symcache_dynamic_item *item,
												 const char *subsystem,
												 const char *loc);

#define rspamd_symcache_item_async_inc(task, item, subsystem) \
	rspamd_symcache_item_async_inc_full(task, item, subsystem, G_STRLOC)

/*
 * Decrease number of async events pending for an item, asserts if no events pending
 */
unsigned int rspamd_symcache_item_async_dec_full(struct rspamd_task *task,
												 struct rspamd_symcache_dynamic_item *item,
												 const char *subsystem,
												 const char *loc);

#define rspamd_symcache_item_async_dec(task, item, subsystem) \
	rspamd_symcache_item_async_dec_full(task, item, subsystem, G_STRLOC)

/**
 * Decrease number of async events pending for an item, asserts if no events pending
 * If no events are left, this function calls `rspamd_symbols_cache_finalize_item` and returns TRUE
 * @param task
 * @param item
 * @return
 */
gboolean rspamd_symcache_item_async_dec_check_full(struct rspamd_task *task,
												   struct rspamd_symcache_dynamic_item *item,
												   const char *subsystem,
												   const char *loc);

#define rspamd_symcache_item_async_dec_check(task, item, subsystem) \
	rspamd_symcache_item_async_dec_check_full(task, item, subsystem, G_STRLOC)

/**
 * Disables execution of all symbols, excluding those specified in `skip_mask`
 * @param task
 * @param cache
 * @param skip_mask
 */
void rspamd_symcache_disable_all_symbols(struct rspamd_task *task,
										 struct rspamd_symcache *cache,
										 unsigned int skip_mask);

/**
 * Iterates over the list of the enabled composites calling specified function
 * @param task
 * @param cache
 * @param func
 * @param fd
 */
void rspamd_symcache_composites_foreach(struct rspamd_task *task,
										struct rspamd_symcache *cache,
										GHFunc func,
										gpointer fd);

/**
 * Sets allowed settings ids for a symbol
 * @param cache
 * @param symbol
 * @param ids
 * @param nids
 */
bool rspamd_symcache_set_allowed_settings_ids(struct rspamd_symcache *cache,
											  const char *symbol,
											  const uint32_t *ids,
											  unsigned int nids);
/**
 * Sets denied settings ids for a symbol
 * @param cache
 * @param symbol
 * @param ids
 * @param nids
 */
bool rspamd_symcache_set_forbidden_settings_ids(struct rspamd_symcache *cache,
												const char *symbol,
												const uint32_t *ids,
												unsigned int nids);

/**
 * Returns allowed ids for a symbol as a constant array
 * @param cache
 * @param symbol
 * @param nids
 * @return
 */
const uint32_t *rspamd_symcache_get_allowed_settings_ids(struct rspamd_symcache *cache,
														 const char *symbol,
														 unsigned int *nids);

/**
 * Returns denied ids for a symbol as a constant array
 * @param cache
 * @param symbol
 * @param nids
 * @return
 */
const uint32_t *rspamd_symcache_get_forbidden_settings_ids(struct rspamd_symcache *cache,
														   const char *symbol,
														   unsigned int *nids);


/**
 * Processes settings_elt in cache and converts it to a set of
 * adjustments for forbidden/allowed settings_ids for each symbol
 * @param cache
 * @param elt
 */
void rspamd_symcache_process_settings_elt(struct rspamd_symcache *cache,
										  struct rspamd_config_settings_elt *elt);

/**
 * Check if a symbol is allowed for execution/insertion, this does not involve
 * condition scripts to be checked (so it is intended to be fast).
 * @param task
 * @param item
 * @param exec_only
 * @return
 */
gboolean rspamd_symcache_is_item_allowed(struct rspamd_task *task,
										 struct rspamd_symcache_item *item,
										 gboolean exec_only);

/**
 * Returns symcache item flags
 * @param item
 * @return
 */
int rspamd_symcache_dyn_item_flags(struct rspamd_task *task,
								   struct rspamd_symcache_dynamic_item *dyn_item);
int rspamd_symcache_item_flags(struct rspamd_symcache_item *item);

/**
 * Returns cache item name
 * @param item
 * @return
 */
const char *rspamd_symcache_dyn_item_name(struct rspamd_task *task,
										  struct rspamd_symcache_dynamic_item *dyn_item);
const char *rspamd_symcache_item_name(struct rspamd_symcache_item *item);

/**
 * Returns the current item stat
 * @param item
 * @return
 */
const struct rspamd_symcache_item_stat *
rspamd_symcache_item_stat(struct rspamd_symcache_item *item);

/**
 * Enable profiling for task (e.g. when a slow rule has been found)
 * @param task
 */
void rspamd_symcache_enable_profile(struct rspamd_task *task);

struct rspamd_symcache_timeout_item {
	double timeout;
	const struct rspamd_symcache_item *item;
};

struct rspamd_symcache_timeout_result {
	double max_timeout;
	struct rspamd_symcache_timeout_item *items;
	size_t nitems;
};
/**
 * Gets maximum timeout announced by symbols cache
 * @param cache
 * @return new symcache timeout_result structure, that should be freed by call
 * `rspamd_symcache_timeout_result_free`
 */
struct rspamd_symcache_timeout_result *rspamd_symcache_get_max_timeout(struct rspamd_symcache *cache);

/**
 * Frees results obtained from the previous function
 * @param res
 */
void rspamd_symcache_timeout_result_free(struct rspamd_symcache_timeout_result *res);

/**
 * Destroy internal state of the symcache runtime
 * @param task
 */
void rspamd_symcache_runtime_destroy(struct rspamd_task *task);

/**
 * Promote symbols cache resort (typically after dynamic symbol registration)
 * @param cache
 */
void rspamd_symcache_promote_resort(struct rspamd_symcache *cache);

#ifdef __cplusplus
}
#endif

#endif
