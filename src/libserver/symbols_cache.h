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

#define MAX_SYMBOL 128

struct rspamd_task;
struct rspamd_config;
struct symbols_cache;

typedef void (*symbol_func_t)(struct rspamd_task *task, gpointer user_data);

enum rspamd_symbol_type {
	SYMBOL_TYPE_NORMAL,
	SYMBOL_TYPE_VIRTUAL,
	SYMBOL_TYPE_CALLBACK
};

struct symbols_cache* rspamd_symbols_cache_new (void);

/**
 * Load symbols cache from file, must be called _after_ init_symbols_cache
 */
gboolean init_symbols_cache (struct symbols_cache* cache,
	struct rspamd_config *cfg);

/**
 * Register function for symbols parsing
 * @param name name of symbol
 * @param func pointer to handler
 * @param user_data pointer to user_data
 */
void register_symbol (struct symbols_cache **cache,
	const gchar *name,
	double weight,
	symbol_func_t func,
	gpointer user_data);


/**
 * Register virtual symbol
 * @param name name of symbol
 */
void register_virtual_symbol (struct symbols_cache **cache,
	const gchar *name,
	double weight);

/**
 * Register callback function for symbols parsing
 * @param name name of symbol
 * @param func pointer to handler
 * @param user_data pointer to user_data
 */
void register_callback_symbol (struct symbols_cache **cache,
	const gchar *name,
	double weight,
	symbol_func_t func,
	gpointer user_data);

/**
 * Register function for symbols parsing with strict priority
 * @param name name of symbol
 * @param func pointer to handler
 * @param user_data pointer to user_data
 */
void register_callback_symbol_priority (struct symbols_cache **cache,
	const gchar *name,
	double weight,
	gint priority,
	symbol_func_t func,
	gpointer user_data);

/**
 * Register function for dynamic symbols parsing
 * @param name name of symbol
 * @param func pointer to handler
 * @param user_data pointer to user_data
 */
void register_dynamic_symbol (rspamd_mempool_t *pool,
	struct symbols_cache **cache,
	const gchar *name,
	double weight,
	symbol_func_t func,
	gpointer user_data,
	GList *networks);

/**
 * Generic function to register a symbol
 * @param cache
 * @param name
 * @param weight
 * @param priority
 * @param func
 * @param user_data
 * @param type
 */
void
register_symbol_common (struct symbols_cache **cache,
	const gchar *name,
	double weight,
	gint priority,
	symbol_func_t func,
	gpointer user_data,
	enum rspamd_symbol_type type);

/**
 * Call function for cached symbol using saved callback
 * @param task task object
 * @param cache symbols cache
 * @param saved_item pointer to currently saved item
 */
gboolean call_symbol_callback (struct rspamd_task *task,
	struct symbols_cache *cache,
	gpointer *save);

/**
 * Remove all dynamic rules from cache
 * @param cache symbols cache
 */
void remove_dynamic_rules (struct symbols_cache *cache);

/**
 * Validate cache items agains theirs weights defined in metrics
 * @param cache symbols cache
 * @param cfg configuration
 * @param strict do strict checks - symbols MUST be described in metrics
 */
gboolean validate_cache (struct symbols_cache *cache,
	struct rspamd_config *cfg,
	gboolean strict);


#endif
