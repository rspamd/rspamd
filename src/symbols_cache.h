#ifndef RSPAMD_SYMBOLS_CACHE_H
#define RSPAMD_SYMBOLS_CACHE_H

#include "config.h"

#define MAX_SYMBOL 128

struct worker_task;

typedef void (*symbol_func_t)(struct worker_task *task, gpointer user_data);

struct saved_cache_item {
	char symbol[MAX_SYMBOL];
	double weight;
	uint32_t frequency;
	double avg_time;
};

struct cache_item {
	struct saved_cache_item *s;
	symbol_func_t func;
	gpointer user_data;
};

struct symbols_cache {
	struct cache_item *items;
	guint cur_items;
	guint used_items;
	guint uses;
	memory_pool_rwlock_t *lock;
};

/**
 * Load symbols cache from file, must be called _after_ init_symbols_cache
 */
gboolean init_symbols_cache (memory_pool_t *pool, struct symbols_cache *cache, const char *filename);

/**
 * Register function for symbols parsing
 * @param name name of symbol
 * @param func pointer to handler
 * @param user_data pointer to user_data
 */
void register_symbol (struct symbols_cache *cache, const char *name, double weight, symbol_func_t func, gpointer user_data);

/**
 * Call function for cached symbol using saved callback
 * @param task task object
 * @param cache symbols cache
 * @param saved_item pointer to currently saved item
 */
gboolean call_symbol_callback (struct worker_task *task, struct symbols_cache *cache, struct cache_item **saved_item);

#endif
