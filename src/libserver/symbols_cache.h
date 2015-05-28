/*
 * Copyright (c) 2009-2015, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef RSPAMD_SYMBOLS_CACHE_H
#define RSPAMD_SYMBOLS_CACHE_H

#include "config.h"
#include "ucl.h"

#define MAX_SYMBOL 128

struct rspamd_task;
struct rspamd_config;
struct symbols_cache;

typedef void (*symbol_func_t)(struct rspamd_task *task, gpointer user_data);

enum rspamd_symbol_type {
	SYMBOL_TYPE_NORMAL,
	SYMBOL_TYPE_VIRTUAL,
	SYMBOL_TYPE_CALLBACK,
	SYMBOL_TYPE_GHOST,
	SYMBOL_TYPE_SKIPPED,
	SYMBOL_TYPE_COMPOSITE
};

/**
 * Creates new cache structure
 * @return
 */
struct symbols_cache* rspamd_symbols_cache_new (void);

/**
 * Remove the cache structure syncing data if needed
 * @param cache
 */
void rspamd_symbols_cache_destroy (struct symbols_cache *cache);

/**
 * Load symbols cache from file, must be called _after_ init_symbols_cache
 */
gboolean rspamd_symbols_cache_init (struct symbols_cache* cache,
	struct rspamd_config *cfg);

/**
 * Register function for symbols parsing
 * @param name name of symbol
 * @param func pointer to handler
 * @param user_data pointer to user_data
 */
gint rspamd_symbols_cache_add_symbol_normal (struct symbols_cache *cache,
	const gchar *name,
	double weight,
	symbol_func_t func,
	gpointer user_data);


/**
 * Register virtual symbol
 * @param name name of symbol
 * @param weight initial weight
 * @param parent associated callback parent
 */
gint rspamd_symbols_cache_add_symbol_virtual (struct symbols_cache *cache,
	const gchar *name,
	double weight,
	gint parent);

/**
 * Register callback function for symbols parsing
 * @param name name of symbol
 * @param func pointer to handler
 * @param user_data pointer to user_data
 */
gint rspamd_symbols_cache_add_symbol_callback (struct symbols_cache *cache,
	double weight,
	symbol_func_t func,
	gpointer user_data);

/**
 * Register function for symbols parsing with strict priority
 * @param name name of symbol
 * @param func pointer to handler
 * @param user_data pointer to user_data
 */
gint rspamd_symbols_cache_add_symbol_callback_prio (struct symbols_cache *cache,
	double weight,
	gint priority,
	symbol_func_t func,
	gpointer user_data);

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
	double weight,
	gint priority,
	symbol_func_t func,
	gpointer user_data,
	enum rspamd_symbol_type type,
	gint parent);

/**
 * Call function for cached symbol using saved callback
 * @param task task object
 * @param cache symbols cache
 * @param saved_item pointer to currently saved item
 */
gboolean rspamd_symbols_cache_process_symbol (struct rspamd_task *task,
	struct symbols_cache *cache,
	gpointer *save);

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

#endif
