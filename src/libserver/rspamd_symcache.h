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
#ifndef RSPAMD_SYMBOLS_CACHE_H
#define RSPAMD_SYMBOLS_CACHE_H

#include "config.h"
#include "ucl.h"
#include <lua.h>
#include <event.h>

struct rspamd_task;
struct rspamd_config;
struct rspamd_symcache;
struct rspamd_worker;
struct rspamd_symcache_item;

typedef void (*symbol_func_t)(struct rspamd_task *task,
							  struct rspamd_symcache_item *item,
							  gpointer user_data);

enum rspamd_symbol_type {
	SYMBOL_TYPE_NORMAL = (1 << 0),
	SYMBOL_TYPE_VIRTUAL = (1 << 1),
	SYMBOL_TYPE_CALLBACK = (1 << 2),
	SYMBOL_TYPE_GHOST = (1 << 3),
	SYMBOL_TYPE_SKIPPED = (1 << 4),
	SYMBOL_TYPE_COMPOSITE = (1 << 5),
	SYMBOL_TYPE_CLASSIFIER = (1 << 6),
	SYMBOL_TYPE_FINE = (1 << 7),
	SYMBOL_TYPE_EMPTY = (1 << 8), /* Allow execution on empty tasks */
	SYMBOL_TYPE_PREFILTER = (1 << 9),
	SYMBOL_TYPE_POSTFILTER = (1 << 10),
	SYMBOL_TYPE_NOSTAT = (1 << 11), /* Skip as statistical symbol */
	SYMBOL_TYPE_IDEMPOTENT = (1 << 12), /* Symbol cannot change metric */
	SYMBOL_TYPE_SQUEEZED = (1 << 13), /* Symbol is squeezed inside Lua */
	SYMBOL_TYPE_TRIVIAL = (1 << 14), /* Symbol is trivial */
	SYMBOL_TYPE_MIME_ONLY = (1 << 15), /* Symbol is mime only */
};

/**
 * Abstract structure for saving callback data for symbols
 */
struct rspamd_abstract_callback_data {
	guint64 magic;
	char data[];
};

/**
 * Creates new cache structure
 * @return
 */
struct rspamd_symcache* rspamd_symcache_new (struct rspamd_config *cfg);

/**
 * Remove the cache structure syncing data if needed
 * @param cache
 */
void rspamd_symcache_destroy (struct rspamd_symcache *cache);

/**
 * Saves symbols cache to disk if possible
 * @param cache
 */
void rspamd_symcache_save (struct rspamd_symcache *cache);

/**
 * Load symbols cache from file, must be called _after_ init_symbols_cache
 */
gboolean rspamd_symcache_init (struct rspamd_symcache *cache);

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
gint rspamd_symcache_add_symbol (struct rspamd_symcache *cache,
								 const gchar *name,
								 gint priority,
								 symbol_func_t func,
								 gpointer user_data,
								 enum rspamd_symbol_type type,
								 gint parent);

/**
 * Add callback to be executed whenever symbol has peak value
 * @param cache
 * @param cbref
 */
void rspamd_symcache_set_peak_callback (struct rspamd_symcache *cache,
										gint cbref);
/**
 * Add delayed condition to the specific symbol in cache. So symbol can be absent
 * to the moment of addition
 * @param cache
 * @param id id of symbol
 * @param L lua state pointer
 * @param cbref callback reference (returned by luaL_ref)
 * @return TRUE if condition has been added
 */
gboolean rspamd_symcache_add_condition_delayed (struct rspamd_symcache *cache,
												const gchar *sym,
												lua_State *L, gint cbref);

/**
 * Find symbol in cache by id and returns its id resolving virtual symbols if
 * applicable
 * @param cache
 * @param name
 * @return id of symbol or (-1) if a symbol has not been found
 */
gint rspamd_symcache_find_symbol (struct rspamd_symcache *cache,
								  const gchar *name);

/**
 * Get statistics for a specific symbol
 * @param cache
 * @param name
 * @param frequency
 * @param tm
 * @return
 */
gboolean rspamd_symcache_stat_symbol (struct rspamd_symcache *cache,
									  const gchar *name,
									  gdouble *frequency,
									  gdouble *freq_stddev,
									  gdouble *tm,
									  guint *nhits);
/**
 * Find symbol in cache by its id
 * @param cache
 * @param id
 * @return symbol's name or NULL
 */
const gchar * rspamd_symcache_symbol_by_id (struct rspamd_symcache *cache,
											gint id);

/**
 * Returns number of symbols registered in symbols cache
 * @param cache
 * @return number of symbols in the cache
 */
guint rspamd_symcache_stats_symbols_count (struct rspamd_symcache *cache);

/**
 * Call function for cached symbol using saved callback
 * @param task task object
 * @param cache symbols cache
 * @param saved_item pointer to currently saved item
 */
gboolean rspamd_symcache_process_symbols (struct rspamd_task *task,
										  struct rspamd_symcache *cache,
										  gint stage);

/**
 * Validate cache items against theirs weights defined in metrics
 * @param cache symbols cache
 * @param cfg configuration
 * @param strict do strict checks - symbols MUST be described in metrics
 */
gboolean rspamd_symcache_validate (struct rspamd_symcache *cache,
								   struct rspamd_config *cfg,
								   gboolean strict);

/**
 * Return statistics about the cache as ucl object (array of objects one per item)
 * @param cache
 * @return
 */
ucl_object_t *rspamd_symcache_counters (struct rspamd_symcache *cache);

/**
 * Start cache reloading
 * @param cache
 * @param ev_base
 */
void rspamd_symcache_start_refresh (struct rspamd_symcache *cache,
									struct event_base *ev_base,
									struct rspamd_worker *w);

/**
 * Increases counter for a specific symbol
 * @param cache
 * @param symbol
 */
void rspamd_symcache_inc_frequency (struct rspamd_symcache *cache,
									const gchar *symbol);

/**
 * Add dependency relation between two symbols identified by id (source) and
 * a symbolic name (destination). Destination could be virtual or real symbol.
 * Callback destinations are not yet supported.
 * @param id_from source symbol
 * @param to destination name
 */
void rspamd_symcache_add_dependency (struct rspamd_symcache *cache,
									 gint id_from, const gchar *to);

/**
 * Add delayed dependency that is resolved on cache post-load routine
 * @param cache
 * @param from
 * @param to
 */
void rspamd_symcache_add_delayed_dependency (struct rspamd_symcache *cache,
											 const gchar *from, const gchar *to);

/**
 * Disable specific symbol in the cache
 * @param cache
 * @param symbol
 */
void rspamd_symcache_disable_symbol_perm (struct rspamd_symcache *cache,
										  const gchar *symbol);

/**
 * Enable specific symbol in the cache
 * @param cache
 * @param symbol
 */
void rspamd_symcache_enable_symbol_perm (struct rspamd_symcache *cache,
										 const gchar *symbol);
/**
 * Get abstract callback data for a symbol (or its parent symbol)
 * @param cache cache object
 * @param symbol symbol name
 * @return abstract callback data or NULL if symbol is absent or has no data attached
 */
struct rspamd_abstract_callback_data* rspamd_symcache_get_cbdata (
		struct rspamd_symcache *cache, const gchar *symbol);


/**
 * Process settings for task
 * @param task
 * @param cache
 * @return
 */
gboolean rspamd_symcache_process_settings (struct rspamd_task *task,
										   struct rspamd_symcache *cache);


/**
 * Checks if a symbol specified has been checked (or disabled)
 * @param task
 * @param cache
 * @param symbol
 * @return
 */
gboolean rspamd_symcache_is_checked (struct rspamd_task *task,
									 struct rspamd_symcache *cache,
									 const gchar *symbol);

/**
 * Returns checksum for all cache items
 * @param cache
 * @return
 */
guint64 rspamd_symcache_get_cksum (struct rspamd_symcache *cache);

/**
 * Checks if a symbols is enabled (not checked and conditions return true if present)
 * @param task
 * @param cache
 * @param symbol
 * @return
 */
gboolean rspamd_symcache_is_symbol_enabled (struct rspamd_task *task,
											struct rspamd_symcache *cache,
											const gchar *symbol);

/**
 * Enable this symbol for task
 * @param task
 * @param cache
 * @param symbol
 * @return TRUE if a symbol has been enabled (not executed before)
 */
gboolean rspamd_symcache_enable_symbol (struct rspamd_task *task,
										struct rspamd_symcache *cache,
										const gchar *symbol);

/**
 * Enable this symbol for task
 * @param task
 * @param cache
 * @param symbol
 * @return TRUE if a symbol has been disabled (not executed before)
 */
gboolean rspamd_symcache_disable_symbol (struct rspamd_task *task,
										 struct rspamd_symcache *cache,
										 const gchar *symbol);
/**
 * Process specific function for each cache element (in order they are added)
 * @param cache
 * @param func
 * @param ud
 */
void rspamd_symcache_foreach (struct rspamd_symcache *cache,
							  void (*func) (gint /* id */, const gchar * /* name */,
											gint /* flags */, gpointer /* userdata */),
							  gpointer ud);

/**
 * Returns the current item being processed (if any)
 * @param task
 * @return
 */
struct rspamd_symcache_item *rspamd_symcache_get_cur_item (struct rspamd_task *task);

/**
 * Replaces the current item being processed.
 * Returns the current item being processed (if any)
 * @param task
 * @param item
 * @return
 */
struct rspamd_symcache_item *rspamd_symcache_set_cur_item (struct rspamd_task *task,
														   struct rspamd_symcache_item *item);


/**
 * Finalize the current async element potentially calling its deps
 */
void rspamd_symcache_finalize_item (struct rspamd_task *task,
									struct rspamd_symcache_item *item);

/*
 * Increase number of async events pending for an item
 */
guint rspamd_symcache_item_async_inc_full (struct rspamd_task *task,
									  struct rspamd_symcache_item *item,
									  const gchar *subsystem,
									  const gchar *loc);
#define rspamd_symcache_item_async_inc(task, item, subsystem) \
	rspamd_symcache_item_async_inc_full(task, item, subsystem, G_STRLOC)
/*
 * Decrease number of async events pending for an item, asserts if no events pending
 */
guint rspamd_symcache_item_async_dec_full (struct rspamd_task *task,
									  struct rspamd_symcache_item *item,
									  const gchar *subsystem,
									  const gchar *loc);
#define rspamd_symcache_item_async_dec(task, item, subsystem) \
	rspamd_symcache_item_async_dec_full(task, item, subsystem, G_STRLOC)
/**
 * Decrease number of async events pending for an item, asserts if no events pending
 * If no events are left, this function calls `rspamd_symbols_cache_finalize_item` and returns TRUE
 * @param task
 * @param item
 * @return
 */
gboolean rspamd_symcache_item_async_dec_check_full (struct rspamd_task *task,
											   struct rspamd_symcache_item *item,
											   const gchar *subsystem,
											   const gchar *loc);
#define rspamd_symcache_item_async_dec_check(task, item, subsystem) \
	rspamd_symcache_item_async_dec_check_full(task, item, subsystem, G_STRLOC)
#endif
