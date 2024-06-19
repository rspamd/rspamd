/*
 * Copyright 2024 Vsevolod Stakhov
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
#define C_API_SYMCACHE_DYN_ITEM(ptr) (reinterpret_cast<rspamd::symcache::cache_dynamic_item *>(ptr))

void rspamd_symcache_destroy(struct rspamd_symcache *cache)
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

void rspamd_symcache_save(struct rspamd_symcache *cache)
{
	auto *real_cache = C_API_SYMCACHE(cache);

	real_cache->save_items();
}

int rspamd_symcache_add_symbol(struct rspamd_symcache *cache,
							   const char *name,
							   int priority,
							   symbol_func_t func,
							   gpointer user_data,
							   int type,
							   int parent)
{
	auto *real_cache = C_API_SYMCACHE(cache);

	/* Legacy stuff */
	if (name == nullptr) {
		name = "";
	}

	if (parent == -1) {
		return real_cache->add_symbol_with_callback(name, priority, func, user_data, type);
	}
	else {
		return real_cache->add_virtual_symbol(name, parent, type);
	}
}

bool rspamd_symcache_add_symbol_augmentation(struct rspamd_symcache *cache,
											 int sym_id,
											 const char *augmentation,
											 const char *value)
{
	auto *real_cache = C_API_SYMCACHE(cache);
	auto log_tag = [&]() { return real_cache->log_tag(); };

	if (augmentation == nullptr) {
		msg_err_cache("null augmentation is not allowed for item %d", sym_id);
		return false;
	}


	auto *item = real_cache->get_item_by_id_mut(sym_id, false);

	if (item == nullptr) {
		msg_err_cache("item %d is not found", sym_id);
		return false;
	}

	/* Handle empty or absent strings equally */
	if (value == nullptr || value[0] == '\0') {
		return item->add_augmentation(*real_cache, augmentation, std::nullopt);
	}

	return item->add_augmentation(*real_cache, augmentation, value);
}

void rspamd_symcache_set_peak_callback(struct rspamd_symcache *cache, int cbref)
{
	auto *real_cache = C_API_SYMCACHE(cache);

	real_cache->set_peak_cb(cbref);
}

gboolean
rspamd_symcache_add_condition_delayed(struct rspamd_symcache *cache,
									  const char *sym, lua_State *L, int cbref)
{
	auto *real_cache = C_API_SYMCACHE(cache);

	real_cache->add_delayed_condition(sym, cbref);

	return TRUE;
}

int rspamd_symcache_find_symbol(struct rspamd_symcache *cache,
								const char *name)
{
	auto *real_cache = C_API_SYMCACHE(cache);

	/* Legacy stuff but used */
	if (name == nullptr) {
		return -1;
	}

	auto sym_maybe = real_cache->get_item_by_name(name, false);

	if (sym_maybe != nullptr) {
		return sym_maybe->id;
	}

	return -1;
}

gboolean
rspamd_symcache_stat_symbol(struct rspamd_symcache *cache,
							const char *name,
							double *frequency,
							double *freq_stddev,
							double *tm,
							unsigned int *nhits)
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


unsigned int rspamd_symcache_stats_symbols_count(struct rspamd_symcache *cache)
{
	auto *real_cache = C_API_SYMCACHE(cache);
	return real_cache->get_stats_symbols_count();
}

uint64_t
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

void rspamd_symcache_inc_frequency(struct rspamd_symcache *cache, struct rspamd_symcache_item *item,
								   const char *sym_name)
{
	auto *real_item = C_API_SYMCACHE_ITEM(item);
	auto *real_cache = C_API_SYMCACHE(cache);

	if (real_item) {
		real_item->inc_frequency(sym_name, *real_cache);
	}
}

void rspamd_symcache_add_delayed_dependency(struct rspamd_symcache *cache,
											const char *from, const char *to)
{
	auto *real_cache = C_API_SYMCACHE(cache);
	real_cache->add_delayed_dependency(from, to);
}

const char *
rspamd_symcache_get_parent(struct rspamd_symcache *cache,
						   const char *symbol)
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

const char *
rspamd_symcache_item_name(struct rspamd_symcache_item *item)
{
	auto *real_item = C_API_SYMCACHE_ITEM(item);

	if (real_item == nullptr) {
		return nullptr;
	}

	return real_item->get_name().c_str();
}

int rspamd_symcache_item_flags(struct rspamd_symcache_item *item)
{
	auto *real_item = C_API_SYMCACHE_ITEM(item);

	if (real_item == nullptr) {
		return 0;
	}

	return real_item->get_flags();
}


const char *
rspamd_symcache_dyn_item_name(struct rspamd_task *task,
							  struct rspamd_symcache_dynamic_item *dyn_item)
{
	auto *cache_runtime = C_API_SYMCACHE_RUNTIME(task->symcache_runtime);
	auto *real_dyn_item = C_API_SYMCACHE_DYN_ITEM(dyn_item);

	if (cache_runtime == nullptr || real_dyn_item == nullptr) {
		return nullptr;
	}

	auto static_item = cache_runtime->get_item_by_dynamic_item(real_dyn_item);

	return static_item->get_name().c_str();
}

int rspamd_symcache_item_flags(struct rspamd_task *task,
							   struct rspamd_symcache_dynamic_item *dyn_item)
{
	auto *cache_runtime = C_API_SYMCACHE_RUNTIME(task->symcache_runtime);
	auto *real_dyn_item = C_API_SYMCACHE_DYN_ITEM(dyn_item);

	if (cache_runtime == nullptr || real_dyn_item == nullptr) {
		return 0;
	}

	auto static_item = cache_runtime->get_item_by_dynamic_item(real_dyn_item);

	return static_item->get_flags();
}

unsigned int rspamd_symcache_get_symbol_flags(struct rspamd_symcache *cache,
											  const char *symbol)
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

void rspamd_symcache_get_symbol_details(struct rspamd_symcache *cache,
										const char *symbol,
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

void rspamd_symcache_foreach(struct rspamd_symcache *cache,
							 void (*func)(struct rspamd_symcache_item *item, gpointer /* userdata */),
							 gpointer ud)
{
	auto *real_cache = C_API_SYMCACHE(cache);

	real_cache->symbols_foreach([&](const rspamd::symcache::cache_item *item) {
		func((struct rspamd_symcache_item *) item, ud);
	});
}

void rspamd_symcache_process_settings_elt(struct rspamd_symcache *cache,
										  struct rspamd_config_settings_elt *elt)
{
	auto *real_cache = C_API_SYMCACHE(cache);

	real_cache->process_settings_elt(elt);
}

bool rspamd_symcache_set_allowed_settings_ids(struct rspamd_symcache *cache,
											  const char *symbol,
											  const uint32_t *ids,
											  unsigned int nids)
{
	auto *real_cache = C_API_SYMCACHE(cache);

	auto *item = real_cache->get_item_by_name_mut(symbol, false);

	if (item == nullptr) {
		return false;
	}

	item->allowed_ids.set_ids(ids, nids);
	return true;
}

bool rspamd_symcache_set_forbidden_settings_ids(struct rspamd_symcache *cache,
												const char *symbol,
												const uint32_t *ids,
												unsigned int nids)
{
	auto *real_cache = C_API_SYMCACHE(cache);

	auto *item = real_cache->get_item_by_name_mut(symbol, false);

	if (item == nullptr) {
		return false;
	}

	item->forbidden_ids.set_ids(ids, nids);
	return true;
}

const uint32_t *
rspamd_symcache_get_allowed_settings_ids(struct rspamd_symcache *cache,
										 const char *symbol,
										 unsigned int *nids)
{
	auto *real_cache = C_API_SYMCACHE(cache);

	const auto *item = real_cache->get_item_by_name(symbol, false);
	return item->allowed_ids.get_ids(*nids);
}

const uint32_t *
rspamd_symcache_get_forbidden_settings_ids(struct rspamd_symcache *cache,
										   const char *symbol,
										   unsigned int *nids)
{
	auto *real_cache = C_API_SYMCACHE(cache);

	const auto *item = real_cache->get_item_by_name(symbol, false);
	return item->forbidden_ids.get_ids(*nids);
}

void rspamd_symcache_disable_all_symbols(struct rspamd_task *task,
										 struct rspamd_symcache *_cache,
										 unsigned int skip_mask)
{
	auto *cache_runtime = C_API_SYMCACHE_RUNTIME(task->symcache_runtime);

	cache_runtime->disable_all_symbols(skip_mask);
}

gboolean
rspamd_symcache_disable_symbol(struct rspamd_task *task,
							   struct rspamd_symcache *cache,
							   const char *symbol)
{
	auto *cache_runtime = C_API_SYMCACHE_RUNTIME(task->symcache_runtime);
	auto *real_cache = C_API_SYMCACHE(cache);

	if (cache_runtime == nullptr) {
		return FALSE;
	}

	return cache_runtime->disable_symbol(task, *real_cache, symbol);
}

gboolean
rspamd_symcache_enable_symbol(struct rspamd_task *task,
							  struct rspamd_symcache *cache,
							  const char *symbol)
{
	auto *cache_runtime = C_API_SYMCACHE_RUNTIME(task->symcache_runtime);
	auto *real_cache = C_API_SYMCACHE(cache);

	if (cache_runtime == nullptr) {
		return FALSE;
	}

	return cache_runtime->enable_symbol(task, *real_cache, symbol);
}

void rspamd_symcache_disable_symbol_static(struct rspamd_symcache *cache,
										   const char *symbol)
{
	auto *real_cache = C_API_SYMCACHE(cache);

	real_cache->disable_symbol_delayed(symbol);
}

void rspamd_symcache_enable_symbol_static(struct rspamd_symcache *cache,
										  const char *symbol)
{
	auto *real_cache = C_API_SYMCACHE(cache);

	real_cache->enable_symbol_delayed(symbol);
}

/* A real structure to match C results without extra copying */
struct rspamd_symcache_real_timeout_result {
	struct rspamd_symcache_timeout_result c_api_result;
	std::vector<std::pair<double, const rspamd::symcache::cache_item *>> elts;
};

struct rspamd_symcache_timeout_result *
rspamd_symcache_get_max_timeout(struct rspamd_symcache *cache)
{
	auto *real_cache = C_API_SYMCACHE(cache);
	auto *res = new rspamd_symcache_real_timeout_result;

	res->c_api_result.max_timeout = real_cache->get_max_timeout(res->elts);
	res->c_api_result.items = reinterpret_cast<struct rspamd_symcache_timeout_item *>(res->elts.data());
	res->c_api_result.nitems = res->elts.size();

	return &res->c_api_result;
}

void rspamd_symcache_timeout_result_free(struct rspamd_symcache_timeout_result *res)
{
	auto *real_result = reinterpret_cast<rspamd_symcache_real_timeout_result *>(res);
	delete real_result;
}

gboolean
rspamd_symcache_is_checked(struct rspamd_task *task,
						   struct rspamd_symcache *cache,
						   const char *symbol)
{
	auto *cache_runtime = C_API_SYMCACHE_RUNTIME(task->symcache_runtime);
	auto *real_cache = C_API_SYMCACHE(cache);

	if (cache_runtime == nullptr) {
		return FALSE;
	}

	return cache_runtime->is_symbol_checked(*real_cache, symbol);
}

gboolean
rspamd_symcache_process_settings(struct rspamd_task *task,
								 struct rspamd_symcache *cache)
{
	auto *cache_runtime = C_API_SYMCACHE_RUNTIME(task->symcache_runtime);
	auto *real_cache = C_API_SYMCACHE(cache);

	if (cache_runtime == nullptr) {
		return FALSE;
	}

	return cache_runtime->process_settings(task, *real_cache);
}

gboolean
rspamd_symcache_is_item_allowed(struct rspamd_task *task,
								struct rspamd_symcache_item *item,
								gboolean exec_only)
{
	auto *real_item = C_API_SYMCACHE_ITEM(item);

	if (real_item == nullptr) {
		return TRUE;
	}

	return real_item->is_allowed(task, exec_only);
}

gboolean
rspamd_symcache_is_symbol_enabled(struct rspamd_task *task,
								  struct rspamd_symcache *cache,
								  const char *symbol)
{
	auto *cache_runtime = C_API_SYMCACHE_RUNTIME(task->symcache_runtime);
	auto *real_cache = C_API_SYMCACHE(cache);

	if (!cache_runtime) {
		return TRUE;
	}

	return cache_runtime->is_symbol_enabled(task, *real_cache, symbol);
}

struct rspamd_symcache_dynamic_item *
rspamd_symcache_get_cur_item(struct rspamd_task *task)
{
	auto *cache_runtime = C_API_SYMCACHE_RUNTIME(task->symcache_runtime);

	if (!cache_runtime) {
		return nullptr;
	}

	return (struct rspamd_symcache_dynamic_item *) cache_runtime->get_cur_item();
}

struct rspamd_symcache_dynamic_item *
rspamd_symcache_set_cur_item(struct rspamd_task *task, struct rspamd_symcache_dynamic_item *item)
{
	auto *cache_runtime = C_API_SYMCACHE_RUNTIME(task->symcache_runtime);
	auto *real_dyn_item = C_API_SYMCACHE_DYN_ITEM(item);

	if (!cache_runtime || !real_dyn_item) {
		return nullptr;
	}

	return (struct rspamd_symcache_dynamic_item *) cache_runtime->set_cur_item(real_dyn_item);
}

void rspamd_symcache_enable_profile(struct rspamd_task *task)
{
	auto *cache_runtime = C_API_SYMCACHE_RUNTIME(task->symcache_runtime);
	if (!cache_runtime) {
		return;
	}

	cache_runtime->set_profile_mode(true);
}

unsigned int rspamd_symcache_item_async_inc_full(struct rspamd_task *task,
												 struct rspamd_symcache_dynamic_item *item,
												 const char *subsystem,
												 const char *loc)
{
	auto *cache_runtime = C_API_SYMCACHE_RUNTIME(task->symcache_runtime);
	auto *real_dyn_item = C_API_SYMCACHE_DYN_ITEM(item);

	auto *static_item = cache_runtime->get_item_by_dynamic_item(real_dyn_item);
	msg_debug_cache_task("increase async events counter for %s(%d) = %d + 1; "
						 "subsystem %s (%s)",
						 static_item->symbol.c_str(), static_item->id,
						 real_dyn_item->async_events, subsystem, loc);
	auto nevents = ++real_dyn_item->async_events;

	if (nevents > 1) {
		/* Item is async */
		static_item->internal_flags &= ~rspamd::symcache::cache_item::bit_sync;
	}

	return nevents;
}

unsigned int rspamd_symcache_item_async_dec_full(struct rspamd_task *task,
												 struct rspamd_symcache_dynamic_item *item,
												 const char *subsystem,
												 const char *loc)
{
	auto *cache_runtime = C_API_SYMCACHE_RUNTIME(task->symcache_runtime);
	auto *real_dyn_item = C_API_SYMCACHE_DYN_ITEM(item);

	auto *static_item = cache_runtime->get_item_by_dynamic_item(real_dyn_item);
	msg_debug_cache_task("decrease async events counter for %s(%d) = %d - 1; "
						 "subsystem %s (%s)",
						 static_item->symbol.c_str(), static_item->id,
						 real_dyn_item->async_events, subsystem, loc);

	if (G_UNLIKELY(real_dyn_item->async_events == 0)) {
		msg_err_cache_task("INTERNAL ERROR: trying decrease async events counter for %s(%d) that is already zero; "
						   "subsystem %s (%s)",
						   static_item->symbol.c_str(), static_item->id,
						   real_dyn_item->async_events, subsystem, loc);
		g_abort();
		g_assert_not_reached();
	}

	return --real_dyn_item->async_events;
}

gboolean
rspamd_symcache_item_async_dec_check_full(struct rspamd_task *task,
										  struct rspamd_symcache_dynamic_item *item,
										  const char *subsystem,
										  const char *loc)
{
	if (rspamd_symcache_item_async_dec_full(task, item, subsystem, loc) == 0) {
		rspamd_symcache_finalize_item(task, item);

		return TRUE;
	}

	return FALSE;
}

struct rspamd_abstract_callback_data *
rspamd_symcache_get_cbdata(struct rspamd_symcache *cache,
						   const char *symbol)
{
	auto *real_cache = C_API_SYMCACHE(cache);

	auto *item = real_cache->get_item_by_name(symbol, true);

	if (item) {
		return (struct rspamd_abstract_callback_data *) item->get_cbdata();
	}

	return nullptr;
}

void rspamd_symcache_composites_foreach(struct rspamd_task *task,
										struct rspamd_symcache *cache,
										GHFunc func,
										gpointer fd)
{
	auto *real_cache = C_API_SYMCACHE(cache);
	auto *cache_runtime = C_API_SYMCACHE_RUNTIME(task->symcache_runtime);

	real_cache->composites_foreach([&](const auto *item) {
		auto *dyn_item = cache_runtime->get_dynamic_item(item->id);

		if (dyn_item && dyn_item->status == rspamd::symcache::cache_item_status::not_started) {
			auto *old_item = cache_runtime->set_cur_item(dyn_item);
			func((void *) item->get_name().c_str(), item->get_cbdata(), fd);
			dyn_item->status = rspamd::symcache::cache_item_status::finished;
			cache_runtime->set_cur_item(old_item);
		}
	});

	cache_runtime->set_cur_item(nullptr);
}

gboolean
rspamd_symcache_process_symbols(struct rspamd_task *task,
								struct rspamd_symcache *cache,
								unsigned int stage)
{
	auto *real_cache = C_API_SYMCACHE(cache);

	if (task->symcache_runtime == nullptr) {
		task->symcache_runtime = rspamd::symcache::symcache_runtime::create(task, *real_cache);
	}

	auto *cache_runtime = C_API_SYMCACHE_RUNTIME(task->symcache_runtime);
	return cache_runtime->process_symbols(task, *real_cache, stage);
}

void rspamd_symcache_finalize_item(struct rspamd_task *task,
								   struct rspamd_symcache_dynamic_item *item)
{
	auto *cache_runtime = C_API_SYMCACHE_RUNTIME(task->symcache_runtime);
	auto *real_dyn_item = C_API_SYMCACHE_DYN_ITEM(item);

	cache_runtime->finalize_item(task, real_dyn_item);
}

void rspamd_symcache_runtime_destroy(struct rspamd_task *task)
{
	auto *cache_runtime = C_API_SYMCACHE_RUNTIME(task->symcache_runtime);
	cache_runtime->savepoint_dtor(task);
}