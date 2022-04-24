/*-
 * Copyright 2022 Vsevolod Stakhov
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

#include "symcache_internal.hxx"
#include "symcache_periodic.hxx"
#include "symcache_item.hxx"
#include "symcache_runtime.hxx"

/**
 * C API for symcache
 */

#define C_API_SYMCACHE(ptr) (reinterpret_cast<rspamd::symcache::symcache *>(ptr))
#define C_API_SYMCACHE_RUNTIME(ptr) (reinterpret_cast<rspamd::symcache::symcache_runtime *>(ptr))
#define C_API_SYMCACHE_ITEM(ptr) (reinterpret_cast<rspamd::symcache::cache_item *>(ptr))

void
rspamd_symcache_destroy(struct rspamd_symcache *cache)
{
	auto *real_cache = C_API_SYMCACHE(cache);

	delete real_cache;
}

struct rspamd_symcache *
rspamd_symcache_new(struct rspamd_config *cfg)
{
	auto *ncache = new rspamd::symcache::symcache(cfg);

	return (struct rspamd_symcache *) ncache;
}

gboolean
rspamd_symcache_init(struct rspamd_symcache *cache)
{
	auto *real_cache = C_API_SYMCACHE(cache);

	return real_cache->init();
}

void
rspamd_symcache_save(struct rspamd_symcache *cache)
{
	auto *real_cache = C_API_SYMCACHE(cache);

	real_cache->save_items();
}

gint
rspamd_symcache_add_symbol(struct rspamd_symcache *cache,
						   const gchar *name,
						   gint priority,
						   symbol_func_t func,
						   gpointer user_data,
						   enum rspamd_symbol_type type,
						   gint parent)
{
	auto *real_cache = C_API_SYMCACHE(cache);

	if (func) {
		g_assert (parent == -1);

		return real_cache->add_symbol_with_callback(name, priority, func, user_data, type);
	}
	else {
		return real_cache->add_virtual_symbol(name, parent, type);
	}
}

void
rspamd_symcache_set_peak_callback(struct rspamd_symcache *cache, gint cbref)
{
	auto *real_cache = C_API_SYMCACHE(cache);

	real_cache->set_peak_cb(cbref);
}

gboolean
rspamd_symcache_add_condition_delayed(struct rspamd_symcache *cache,
									  const gchar *sym, lua_State *L, gint cbref)
{
	auto *real_cache = C_API_SYMCACHE(cache);

	real_cache->add_delayed_condition(sym, cbref);

	return TRUE;
}

gint rspamd_symcache_find_symbol(struct rspamd_symcache *cache,
								 const gchar *name)
{
	auto *real_cache = C_API_SYMCACHE(cache);

	auto sym_maybe = real_cache->get_item_by_name(name, false);

	if (sym_maybe != nullptr) {
		return sym_maybe->id;
	}

	return -1;
}

gboolean rspamd_symcache_stat_symbol(struct rspamd_symcache *cache,
									 const gchar *name,
									 gdouble *frequency,
									 gdouble *freq_stddev,
									 gdouble *tm,
									 guint *nhits)
{
	auto *real_cache = C_API_SYMCACHE(cache);

	auto sym_maybe = real_cache->get_item_by_name(name, false);

	if (sym_maybe != nullptr) {
		*frequency = sym_maybe->st->avg_frequency;
		*freq_stddev = sqrt(sym_maybe->st->stddev_frequency);
		*tm = sym_maybe->st->time_counter.mean;

		if (nhits) {
			*nhits = sym_maybe->st->hits;
		}

		return TRUE;
	}

	return FALSE;
}


guint
rspamd_symcache_stats_symbols_count(struct rspamd_symcache *cache)
{
	auto *real_cache = C_API_SYMCACHE(cache);
	return real_cache->get_stats_symbols_count();
}

guint64
rspamd_symcache_get_cksum(struct rspamd_symcache *cache)
{
	auto *real_cache = C_API_SYMCACHE(cache);
	return real_cache->get_cksum();
}

gboolean
rspamd_symcache_validate(struct rspamd_symcache *cache,
						 struct rspamd_config *cfg,
						 gboolean strict)
{
	auto *real_cache = C_API_SYMCACHE(cache);

	return real_cache->validate(strict);
}

ucl_object_t *
rspamd_symcache_counters(struct rspamd_symcache *cache)
{
	auto *real_cache = C_API_SYMCACHE(cache);
	return real_cache->counters();
}

void *
rspamd_symcache_start_refresh(struct rspamd_symcache *cache,
							  struct ev_loop *ev_base, struct rspamd_worker *w)
{
	auto *real_cache = C_API_SYMCACHE(cache);
	return new rspamd::symcache::cache_refresh_cbdata{real_cache, ev_base, w};
}

void
rspamd_symcache_inc_frequency(struct rspamd_symcache *_cache, struct rspamd_symcache_item *item)
{
	auto *real_item = C_API_SYMCACHE_ITEM(item);
	real_item->inc_frequency();
}

void
rspamd_symcache_add_delayed_dependency(struct rspamd_symcache *cache,
									   const gchar *from, const gchar *to)
{
	auto *real_cache = C_API_SYMCACHE(cache);
	real_cache->add_delayed_dependency(from, to);
}

const gchar *
rspamd_symcache_get_parent(struct rspamd_symcache *cache,
						   const gchar *symbol)
{
	auto *real_cache = C_API_SYMCACHE(cache);

	auto *sym = real_cache->get_item_by_name(symbol, false);

	if (sym && sym->is_virtual()) {
		auto *parent = sym->get_parent(*real_cache);

		if (parent) {
			return parent->get_name().c_str();
		}
	}

	return nullptr;
}

const gchar *
rspamd_symcache_item_name(struct rspamd_symcache_item *item)
{
	auto *real_item = C_API_SYMCACHE_ITEM(item);
	return real_item->get_name().c_str();
}

gint
rspamd_symcache_item_flags(struct rspamd_symcache_item *item)
{
	auto *real_item = C_API_SYMCACHE_ITEM(item);
	return real_item->get_flags();
}

guint
rspamd_symcache_get_symbol_flags(struct rspamd_symcache *cache,
								 const gchar *symbol)
{
	auto *real_cache = C_API_SYMCACHE(cache);

	auto *sym = real_cache->get_item_by_name(symbol, false);

	if (sym) {
		return sym->get_flags();
	}

	return 0;
}

const struct rspamd_symcache_item_stat *
rspamd_symcache_item_stat(struct rspamd_symcache_item *item)
{
	auto *real_item = C_API_SYMCACHE_ITEM(item);
	return real_item->st;
}

void
rspamd_symcache_get_symbol_details(struct rspamd_symcache *cache,
								   const gchar *symbol,
								   ucl_object_t *this_sym_ucl)
{
	auto *real_cache = C_API_SYMCACHE(cache);

	auto *sym = real_cache->get_item_by_name(symbol, false);

	if (sym) {
		ucl_object_insert_key(this_sym_ucl,
				ucl_object_fromstring(sym->get_type_str()),
				"type", strlen("type"), false);
	}
}

void
rspamd_symcache_foreach(struct rspamd_symcache *cache,
						void (*func)(struct rspamd_symcache_item *item, gpointer /* userdata */),
						gpointer ud)
{
	auto *real_cache = C_API_SYMCACHE(cache);

	real_cache->symbols_foreach([&](const rspamd::symcache::cache_item *item) {
		func((struct rspamd_symcache_item *) item, ud);
	});
}

void
rspamd_symcache_process_settings_elt(struct rspamd_symcache *cache,
									 struct rspamd_config_settings_elt *elt)
{
	auto *real_cache = C_API_SYMCACHE(cache);

	real_cache->process_settings_elt(elt);
}

void
rspamd_symcache_disable_all_symbols(struct rspamd_task *task,
									struct rspamd_symcache *_cache,
									guint skip_mask)
{
	auto *cache_runtime = C_API_SYMCACHE_RUNTIME(task->symcache_runtime);

	cache_runtime->disable_all_symbols(skip_mask);
}

gboolean
rspamd_symcache_disable_symbol(struct rspamd_task *task,
							   struct rspamd_symcache *cache,
							   const gchar *symbol)
{
	auto *cache_runtime = C_API_SYMCACHE_RUNTIME(task->symcache_runtime);
	auto *real_cache = C_API_SYMCACHE(cache);

	return cache_runtime->disable_symbol(task, *real_cache, symbol);
}

gboolean
rspamd_symcache_enable_symbol(struct rspamd_task *task,
							  struct rspamd_symcache *cache,
							  const gchar *symbol)
{
	auto *cache_runtime = C_API_SYMCACHE_RUNTIME(task->symcache_runtime);
	auto *real_cache = C_API_SYMCACHE(cache);

	return cache_runtime->enable_symbol(task, *real_cache, symbol);
}

gboolean
rspamd_symcache_is_checked(struct rspamd_task *task,
						   struct rspamd_symcache *cache,
						   const gchar *symbol)
{
	auto *cache_runtime = C_API_SYMCACHE_RUNTIME(task->symcache_runtime);
	auto *real_cache = C_API_SYMCACHE(cache);

	return cache_runtime->is_symbol_checked(*real_cache, symbol);
}

gboolean
rspamd_symcache_process_settings(struct rspamd_task *task,
								 struct rspamd_symcache *cache)
{
	auto *cache_runtime = C_API_SYMCACHE_RUNTIME(task->symcache_runtime);
	auto *real_cache = C_API_SYMCACHE(cache);

	return cache_runtime->process_settings(task, *real_cache);
}

gboolean
rspamd_symcache_is_item_allowed(struct rspamd_task *task,
								struct rspamd_symcache_item *item,
								gboolean exec_only)
{
	auto *real_item = C_API_SYMCACHE_ITEM(item);

	return real_item->is_allowed(task, exec_only);
}

gboolean
rspamd_symcache_is_symbol_enabled(struct rspamd_task *task,
								  struct rspamd_symcache *cache,
								  const gchar *symbol)
{
	auto *cache_runtime = C_API_SYMCACHE_RUNTIME(task->symcache_runtime);
	auto *real_cache = C_API_SYMCACHE(cache);

	return cache_runtime->is_symbol_enabled(task, *real_cache, symbol);
}

struct rspamd_symcache_item *
rspamd_symcache_get_cur_item(struct rspamd_task *task)
{
	auto *cache_runtime = C_API_SYMCACHE_RUNTIME(task->symcache_runtime);

	return (struct rspamd_symcache_item *) cache_runtime->get_cur_item();
}

struct rspamd_symcache_item *
rspamd_symcache_set_cur_item(struct rspamd_task *task, struct rspamd_symcache_item *item)
{
	auto *cache_runtime = C_API_SYMCACHE_RUNTIME(task->symcache_runtime);
	auto *real_item = C_API_SYMCACHE_ITEM(item);

	return (struct rspamd_symcache_item *) cache_runtime->set_cur_item(real_item);
}