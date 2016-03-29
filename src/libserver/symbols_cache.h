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
struct symbols_cache;

typedef void (*symbol_func_t)(struct rspamd_task *task, gpointer user_data);

enum rspamd_symbol_type {
	SYMBOL_TYPE_NORMAL = (1 << 0),
	SYMBOL_TYPE_VIRTUAL = (1 << 1),
	SYMBOL_TYPE_CALLBACK = (1 << 2),
	SYMBOL_TYPE_GHOST = (1 << 3),
	SYMBOL_TYPE_SKIPPED = (1 << 4),
	SYMBOL_TYPE_COMPOSITE = (1 << 5),
	SYMBOL_TYPE_CLASSIFIER = (1 << 6),
	SYMBOL_TYPE_FINE = (1 << 7)
};

/**
 * Creates new cache structure
 * @return
 */
struct symbols_cache* rspamd_symbols_cache_new (struct rspamd_config *cfg);

/**
 * Remove the cache structure syncing data if needed
 * @param cache
 */
void rspamd_symbols_cache_destroy (struct symbols_cache *cache);

/**
 * Load symbols cache from file, must be called _after_ init_symbols_cache
 */
gboolean rspamd_symbols_cache_init (struct symbols_cache* cache);

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
gint rspamd_symbols_cache_add_symbol (struct symbols_cache *cache,
	const gchar *name,
	gint priority,
	symbol_func_t func,
	gpointer user_data,
	enum rspamd_symbol_type type,
	gint parent);

/**
 * Add condition to the specific symbol in cache
 * @param cache
 * @param id id of symbol
 * @param L lua state pointer
 * @param cbref callback reference (returned by luaL_ref)
 * @return TRUE if condition has been added
 */
gboolean rspamd_symbols_cache_add_condition (struct symbols_cache *cache,
		gint id, lua_State *L, gint cbref);


/**
 * Add delayed condition to the specific symbol in cache. So symbol can be absent
 * to the moment of addition
 * @param cache
 * @param id id of symbol
 * @param L lua state pointer
 * @param cbref callback reference (returned by luaL_ref)
 * @return TRUE if condition has been added
 */
gboolean rspamd_symbols_cache_add_condition_delayed (struct symbols_cache *cache,
		const gchar *sym, lua_State *L, gint cbref);

/**
 * Find symbol in cache by id and returns its id resolving virtual symbols if
 * applicable
 * @param cache
 * @param name
 * @return id of symbol or (-1) if a symbol has not been found
 */
gint rspamd_symbols_cache_find_symbol (struct symbols_cache *cache, const gchar *name);

/**
 * Call function for cached symbol using saved callback
 * @param task task object
 * @param cache symbols cache
 * @param saved_item pointer to currently saved item
 */
gboolean rspamd_symbols_cache_process_symbols (struct rspamd_task *task,
	struct symbols_cache *cache);

/**
 * Validate cache items agains theirs weights defined in metrics
 * @param cache symbols cache
 * @param cfg configuration
 * @param strict do strict checks - symbols MUST be described in metrics
 */
gboolean rspamd_symbols_cache_validate (struct symbols_cache *cache,
	struct rspamd_config *cfg,
	gboolean strict);

/**
 * Return statistics about the cache as ucl object (array of objects one per item)
 * @param cache
 * @return
 */
ucl_object_t *rspamd_symbols_cache_counters (struct symbols_cache * cache);

/**
 * Start cache reloading
 * @param cache
 * @param ev_base
 */
void rspamd_symbols_cache_start_refresh (struct symbols_cache * cache,
		struct event_base *ev_base);

/**
 * Increases counter for a specific symbol
 * @param cache
 * @param symbol
 */
void rspamd_symbols_cache_inc_frequency (struct symbols_cache *cache,
		const gchar *symbol);

/**
 * Add dependency relation between two symbols identified by id (source) and
 * a symbolic name (destination). Destination could be virtual or real symbol.
 * Callback destinations are not yet supported.
 * @param id_from source symbol
 * @param to destination name
 */
void rspamd_symbols_cache_add_dependency (struct symbols_cache *cache,
		gint id_from, const gchar *to);

/**
 * Add delayed dependency that is resolved on cache post-load routine
 * @param cache
 * @param from
 * @param to
 */
void rspamd_symbols_cache_add_delayed_dependency (struct symbols_cache *cache,
		const gchar *from, const gchar *to);

/**
 * Disable some symbols from execution in the cache
 */
void rspamd_symbols_cache_disable_symbol (struct rspamd_task *task,
		struct symbols_cache *cache, const gchar *symbol);

#endif
