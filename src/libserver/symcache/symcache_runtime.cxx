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
#include "symcache_item.hxx"
#include "symcache_runtime.hxx"
#include "libutil/cxx/util.hxx"
#include "libserver/task.h"
#include "libmime/scan_result.h"
#include "utlist.h"
#include "libserver/worker_util.h"
#include <limits>
#include <cmath>

namespace rspamd::symcache {

/* At least once per minute */
constexpr static const auto PROFILE_MAX_TIME = 60.0;
/* For messages larger than 2Mb enable profiling */
constexpr static const auto PROFILE_MESSAGE_SIZE_THRESHOLD = 1024ul * 1024 * 2;
/* Enable profile at least once per this amount of messages processed */
constexpr static const auto PROFILE_PROBABILITY = 0.01;

auto symcache_runtime::create(struct rspamd_task *task, symcache &cache) -> symcache_runtime *
{
	cache.maybe_resort();

	auto cur_order = cache.get_cache_order();
	auto allocated_size = sizeof(symcache_runtime) +
						  sizeof(struct cache_dynamic_item) * cur_order->size();
	auto *checkpoint = (symcache_runtime *) rspamd_mempool_alloc0(task->task_pool,
																  allocated_size);
	msg_debug_cache_task("create symcache runtime for task: %d bytes, %d items", (int) allocated_size, (int) cur_order->size());
	checkpoint->order = std::move(cur_order);
	checkpoint->slow_status = slow_status::none;
	/* Calculate profile probability */
	ev_now_update_if_cheap(task->event_loop);
	ev_tstamp now = ev_now(task->event_loop);
	checkpoint->profile_start = now;
	checkpoint->lim = rspamd_task_get_required_score(task, task->result);

	/*
	 * We enable profiling if the following conditions are met:
	 * - we have not profiled for a long time
	 * - message is large
	 * - random probability
	 */
	if ((cache.get_last_profile() == 0.0 || now > cache.get_last_profile() + PROFILE_MAX_TIME) ||
		(task->msg.len >= PROFILE_MESSAGE_SIZE_THRESHOLD) ||
		(rspamd_random_double_fast() >= (1 - PROFILE_PROBABILITY))) {
		msg_debug_cache_task("enable profiling of symbols for task");
		checkpoint->profile = true;
		cache.set_last_profile(now);
	}

	task->symcache_runtime = (void *) checkpoint;

	return checkpoint;
}

auto symcache_runtime::process_settings(struct rspamd_task *task, const symcache &cache) -> bool
{
	if (!task->settings) {
		msg_err_task("`process_settings` is called with no settings");
		return false;
	}

	const auto *wl = ucl_object_lookup(task->settings, "whitelist");

	if (wl != nullptr) {
		msg_info_task("task is whitelisted");
		task->flags |= RSPAMD_TASK_FLAG_SKIP;
		return true;
	}

	auto already_disabled = false;

	auto process_group = [&](const ucl_object_t *gr_obj, auto functor) -> void {
		ucl_object_iter_t it = nullptr;
		const ucl_object_t *cur;

		if (gr_obj) {
			while ((cur = ucl_iterate_object(gr_obj, &it, true)) != nullptr) {
				if (ucl_object_type(cur) == UCL_STRING) {
					auto *gr = (struct rspamd_symbols_group *)
						g_hash_table_lookup(task->cfg->groups,
											ucl_object_tostring(cur));

					if (gr) {
						GHashTableIter gr_it;
						void *k, *v;
						g_hash_table_iter_init(&gr_it, gr->symbols);

						while (g_hash_table_iter_next(&gr_it, &k, &v)) {
							functor((const char *) k);
						}
					}
				}
			}
		}
	};

	ucl_object_iter_t it = nullptr;
	const ucl_object_t *cur;

	const auto *enabled = ucl_object_lookup(task->settings, "symbols_enabled");

	if (enabled) {
		msg_debug_cache_task("disable all symbols as `symbols_enabled` is found");
		/* Disable all symbols but selected */
		disable_all_symbols(SYMBOL_TYPE_EXPLICIT_DISABLE);
		already_disabled = true;
		it = nullptr;

		while ((cur = ucl_iterate_object(enabled, &it, true)) != nullptr) {
			enable_symbol(task, cache, ucl_object_tostring(cur));
		}
	}

	/* Enable groups of symbols */
	enabled = ucl_object_lookup(task->settings, "groups_enabled");
	if (enabled && !already_disabled) {
		disable_all_symbols(SYMBOL_TYPE_EXPLICIT_DISABLE);
	}
	process_group(enabled, [&](const char *sym) {
		enable_symbol(task, cache, sym);
	});

	const auto *disabled = ucl_object_lookup(task->settings, "symbols_disabled");

	if (disabled) {
		it = nullptr;

		while ((cur = ucl_iterate_object(disabled, &it, true)) != nullptr) {
			disable_symbol(task, cache, ucl_object_tostring(cur));
		}
	}

	/* Disable groups of symbols */
	disabled = ucl_object_lookup(task->settings, "groups_disabled");
	process_group(disabled, [&](const char *sym) {
		disable_symbol(task, cache, sym);
	});

	/* Update required limit */
	lim = rspamd_task_get_required_score(task, task->result);

	return false;
}

auto symcache_runtime::savepoint_dtor(struct rspamd_task *task) -> void
{
	msg_debug_cache_task("destroying savepoint");
	/* Drop shared ownership */
	order.reset();
}

auto symcache_runtime::disable_all_symbols(int skip_mask) -> void
{
	for (auto [i, item]: rspamd::enumerate(order->d)) {
		auto *dyn_item = &dynamic_items[i];

		if (!(item->get_flags() & skip_mask)) {
			dyn_item->status = cache_item_status::finished;
		}
	}
}

auto symcache_runtime::disable_symbol(struct rspamd_task *task, const symcache &cache, std::string_view name) -> bool
{
	const auto *item = cache.get_item_by_name(name, true);

	if (item != nullptr) {

		auto *dyn_item = get_dynamic_item(item->id);

		if (dyn_item) {
			dyn_item->status = cache_item_status::finished;
			msg_debug_cache_task("disable execution of %s", name.data());

			return true;
		}
		else {
			msg_debug_cache_task("cannot disable %s: id not found %d", name.data(), item->id);
		}
	}
	else {
		msg_debug_cache_task("cannot disable %s: symbol not found", name.data());
	}

	return false;
}

auto symcache_runtime::enable_symbol(struct rspamd_task *task, const symcache &cache, std::string_view name) -> bool
{
	const auto *item = cache.get_item_by_name(name, true);

	if (item != nullptr) {

		auto *dyn_item = get_dynamic_item(item->id);

		if (dyn_item) {
			dyn_item->status = cache_item_status::not_started;
			msg_debug_cache_task("enable execution of %s", name.data());

			return true;
		}
		else {
			msg_debug_cache_task("cannot enable %s: id not found %d", name.data(), item->id);
		}
	}
	else {
		msg_debug_cache_task("cannot enable %s: symbol not found", name.data());
	}

	return false;
}

auto symcache_runtime::is_symbol_checked(const symcache &cache, std::string_view name) -> bool
{
	const auto *item = cache.get_item_by_name(name, true);

	if (item != nullptr) {

		auto *dyn_item = get_dynamic_item(item->id);

		if (dyn_item) {
			return dyn_item->status != cache_item_status::not_started;
		}
	}

	return false;
}

auto symcache_runtime::is_symbol_enabled(struct rspamd_task *task, const symcache &cache, std::string_view name) -> bool
{

	const auto *item = cache.get_item_by_name(name, true);
	if (item) {

		if (!item->is_allowed(task, true)) {
			return false;
		}
		else {
			auto *dyn_item = get_dynamic_item(item->id);

			if (dyn_item) {
				if (dyn_item->status != cache_item_status::not_started) {
					/* Already started */
					return false;
				}

				if (!item->is_virtual()) {
					return std::get<normal_item>(item->specific).check_conditions(item->symbol, task);
				}
			}
			else {
				/* Unknown item */
				msg_debug_cache_task("cannot enable %s: symbol not found", name.data());
			}
		}
	}

	return true;
}

auto symcache_runtime::get_dynamic_item(int id) const -> cache_dynamic_item *
{

	/* Not found in the cache, do a hash lookup */
	auto our_id_maybe = rspamd::find_map(order->by_cache_id, id);

	if (our_id_maybe) {
		return &dynamic_items[our_id_maybe.value()];
	}

	return nullptr;
}

auto symcache_runtime::process_symbols(struct rspamd_task *task, symcache &cache, unsigned int stage) -> bool
{
	msg_debug_cache_task("symbols processing stage at pass: %d", stage);

	if (RSPAMD_TASK_IS_SKIPPED(task)) {
		return true;
	}

	switch (stage) {
	case RSPAMD_TASK_STAGE_CONNFILTERS:
	case RSPAMD_TASK_STAGE_PRE_FILTERS:
	case RSPAMD_TASK_STAGE_POST_FILTERS:
	case RSPAMD_TASK_STAGE_IDEMPOTENT:
		return process_pre_postfilters(task, cache,
									   rspamd_session_events_pending(task->s), stage);
		break;

	case RSPAMD_TASK_STAGE_FILTERS:
		return process_filters(task, cache, rspamd_session_events_pending(task->s));
		break;

	default:
		g_assert_not_reached();
	}
}

auto symcache_runtime::process_pre_postfilters(struct rspamd_task *task,
											   symcache &cache,
											   int start_events,
											   unsigned int stage) -> bool
{
	auto saved_priority = std::numeric_limits<int>::min();
	auto all_done = true;
	auto log_func = RSPAMD_LOG_FUNC;
	auto compare_functor = +[](int a, int b) { return a < b; };

	auto proc_func = [&](cache_item *item) {
		/*
		 * We can safely ignore all pre/postfilters except idempotent ones and
		 * those that are marked as ignore passthrough result
		 */
		if (stage != RSPAMD_TASK_STAGE_IDEMPOTENT &&
			!(item->flags & SYMBOL_TYPE_IGNORE_PASSTHROUGH)) {
			if (check_metric_limit(task)) {
				msg_debug_cache_task_lambda("task has already the result being set, ignore further checks");

				return true;
			}
		}

		auto dyn_item = get_dynamic_item(item->id);

		if (dyn_item->status == cache_item_status::not_started) {
			if (slow_status == slow_status::enabled) {
				return false;
			}

			if (saved_priority == std::numeric_limits<int>::min()) {
				saved_priority = item->priority;
			}
			else {
				if (compare_functor(item->priority, saved_priority) &&
					rspamd_session_events_pending(task->s) > start_events) {
					/*
					 * Delay further checks as we have higher
					 * priority filters to be processed
					 */
					return false;
				}
			}

			return process_symbol(task, cache, item, dyn_item);
		}

		/* Continue processing */
		return true;
	};

	switch (stage) {
	case RSPAMD_TASK_STAGE_CONNFILTERS:
		all_done = cache.connfilters_foreach(proc_func);
		break;
	case RSPAMD_TASK_STAGE_PRE_FILTERS:
		all_done = cache.prefilters_foreach(proc_func);
		break;
	case RSPAMD_TASK_STAGE_POST_FILTERS:
		compare_functor = +[](int a, int b) { return a > b; };
		all_done = cache.postfilters_foreach(proc_func);
		break;
	case RSPAMD_TASK_STAGE_IDEMPOTENT:
		compare_functor = +[](int a, int b) { return a > b; };
		all_done = cache.idempotent_foreach(proc_func);
		break;
	default:
		g_error("invalid invocation");
		break;
	}

	return all_done;
}

auto symcache_runtime::process_filters(struct rspamd_task *task, symcache &cache, int start_events) -> bool
{
	auto all_done = true;
	auto log_func = RSPAMD_LOG_FUNC;
	auto has_passtrough = false;

	for (const auto [idx, item]: rspamd::enumerate(order->d)) {
		/* Exclude all non filters */
		if (item->type != symcache_item_type::FILTER) {
			/*
			 * We use breaking the loop as we append non-filters to the end of the list
			 * so, it is safe to stop processing immediately
			 */
			break;
		}

		if (!(item->flags & (SYMBOL_TYPE_FINE | SYMBOL_TYPE_IGNORE_PASSTHROUGH))) {
			if (has_passtrough || check_metric_limit(task)) {
				msg_debug_cache_task_lambda("task has already the result being set, ignore further checks");
				has_passtrough = true;
				/* Skip this item */
				continue;
			}
		}

		auto dyn_item = &dynamic_items[idx];

		if (dyn_item->status == cache_item_status::not_started) {
			all_done = false;

			if (!check_item_deps(task, cache, item.get(),
								 dyn_item, false)) {
				msg_debug_cache_task("blocked execution of %d(%s) unless deps are "
									 "resolved",
									 item->id, item->symbol.c_str());

				continue;
			}

			process_symbol(task, cache, item.get(), dyn_item);

			if (slow_status == slow_status::enabled) {
				return false;
			}
		}
	}

	return all_done;
}

auto symcache_runtime::process_symbol(struct rspamd_task *task, symcache &cache, cache_item *item,
									  cache_dynamic_item *dyn_item) -> bool
{
	if (item->type == symcache_item_type::CLASSIFIER || item->type == symcache_item_type::COMPOSITE) {
		/* Classifiers are special :( */
		return true;
	}

	if (rspamd_session_blocked(task->s)) {
		/*
		 * We cannot add new events as session is either destroyed or
		 * being cleaned up.
		 */
		return true;
	}

	g_assert(!item->is_virtual());
	if (dyn_item->status != cache_item_status::not_started) {
		/*
		 * This can actually happen when deps span over different layers
		 */
		msg_debug_cache_task("skip already started %s(%d) symbol", item->symbol.c_str(), item->id);

		return dyn_item->status == cache_item_status::finished;
	}

	/* Check has been started */
	auto check = true;

	if (!item->is_allowed(task, true) || !item->check_conditions(task)) {
		check = false;
	}

	if (check) {
		dyn_item->status = cache_item_status::started;
		msg_debug_cache_task("execute %s, %d; symbol type = %s", item->symbol.data(),
							 item->id, item_type_to_str(item->type));

		if (profile) {
			ev_now_update_if_cheap(task->event_loop);
			dyn_item->start_msec = (ev_now(task->event_loop) -
									profile_start) *
								   1e3;
		}
		dyn_item->async_events = 0;
		cur_item = dyn_item;
		items_inflight++;
		/* Callback now must finalize itself */


		if (item->call(task, dyn_item)) {
			cur_item = nullptr;

			if (items_inflight == 0) {
				msg_debug_cache_task("item %s, %d is now finished (no async events)", item->symbol.data(),
									 item->id);
				dyn_item->status = cache_item_status::finished;
				return true;
			}

			if (dyn_item->async_events == 0 && dyn_item->status != cache_item_status::finished) {
				msg_err_cache_task("critical error: item %s has no async events pending, "
								   "but it is not finalised",
								   item->symbol.data());
				g_assert_not_reached();
			}
			else if (dyn_item->async_events > 0) {
				msg_debug_cache_task("item %s, %d is now pending with %d async events", item->symbol.data(),
									 item->id, dyn_item->async_events);
			}

			return false;
		}
		else {
			/* We were not able to call item, so we assume it is not callable */
			msg_debug_cache_task("cannot call %s, %d; symbol type = %s", item->symbol.data(),
								 item->id, item_type_to_str(item->type));
			dyn_item->status = cache_item_status::finished;
			return true;
		}
	}
	else {
		msg_debug_cache_task("do not check %s, %d", item->symbol.data(),
							 item->id);
		dyn_item->status = cache_item_status::finished;
	}

	return true;
}

auto symcache_runtime::check_metric_limit(struct rspamd_task *task) -> bool
{
	if (task->flags & RSPAMD_TASK_FLAG_PASS_ALL) {
		return false;
	}

	/* Check score limit */
	if (!std::isnan(lim)) {
		if (task->result->score > lim) {
			return true;
		}
	}

	if (task->result->passthrough_result != nullptr) {
		/* We also need to check passthrough results */
		auto *pr = task->result->passthrough_result;
		DL_FOREACH(task->result->passthrough_result, pr)
		{
			struct rspamd_action_config *act_config =
				rspamd_find_action_config_for_action(task->result, pr->action);

			/* Skip least results */
			if (pr->flags & RSPAMD_PASSTHROUGH_LEAST) {
				continue;
			}

			/* Skip disabled actions */
			if (act_config && (act_config->flags & RSPAMD_ACTION_RESULT_DISABLED)) {
				continue;
			}

			/* Immediately stop on non least passthrough action */
			return true;
		}
	}

	return false;
}

auto symcache_runtime::check_item_deps(struct rspamd_task *task, symcache &cache, cache_item *item,
									   cache_dynamic_item *dyn_item, bool check_only) -> bool
{
	constexpr const auto max_recursion = 20;
	auto log_func = RSPAMD_LOG_FUNC;

	auto inner_functor = [&](int recursion, cache_item *item, cache_dynamic_item *dyn_item, auto rec_functor) -> bool {
		msg_debug_cache_task_lambda("recursively (%d) check dependencies for %s(%d)", recursion,
									item->symbol.c_str(), item->id);

		if (recursion > max_recursion) {
			msg_err_task_lambda("cyclic dependencies: maximum check level %ud exceed when "
								"checking dependencies for %s",
								max_recursion, item->symbol.c_str());

			return true;
		}

		auto ret = true;

		for (const auto &[dest_id, dep]: item->deps) {
			if (!dep.item) {
				/* Assume invalid deps as done */
				msg_debug_cache_task_lambda("symbol %d(%s) has invalid dependencies on %d(%s)",
											item->id, item->symbol.c_str(), dest_id, dep.sym.c_str());
				continue;
			}

			auto *dep_dyn_item = get_dynamic_item(dep.item->id);

			if (dep_dyn_item->status != cache_item_status::finished) {
				if (dep_dyn_item->status == cache_item_status::not_started) {
					/* Not started */
					if (!check_only) {
						if (!rec_functor(recursion + 1,
										 dep.item,
										 dep_dyn_item,
										 rec_functor)) {

							ret = false;
							msg_debug_cache_task_lambda("delayed dependency %d(%s) for "
														"symbol %d(%s)",
														dest_id, dep.sym.c_str(), item->id, item->symbol.c_str());
						}
						else if (!process_symbol(task, cache, dep.item, dep_dyn_item)) {
							/* Now started, but has events pending */
							ret = false;
							msg_debug_cache_task_lambda("started check of %d(%s) symbol "
														"as dep for "
														"%d(%s)",
														dest_id, dep.sym.c_str(), item->id, item->symbol.c_str());
						}
						else {
							msg_debug_cache_task_lambda("dependency %d(%s) for symbol %d(%s) is "
														"already processed",
														dest_id, dep.sym.c_str(), item->id, item->symbol.c_str());
						}
					}
					else {
						msg_debug_cache_task_lambda("dependency %d(%s) for symbol %d(%s) "
													"cannot be started now",
													dest_id, dep.sym.c_str(), item->id, item->symbol.c_str());
						ret = false;
					}
				}
				else {
					/* Started but not finished */
					msg_debug_cache_task_lambda("dependency %d(%s) for symbol %d(%s) is "
												"still executing (%d events pending)",
												dest_id, dep.sym.c_str(),
												item->id, item->symbol.c_str(),
												dep_dyn_item->async_events);
					g_assert(dep_dyn_item->async_events > 0);
					ret = false;
				}
			}
			else {
				msg_debug_cache_task_lambda("dependency %d(%s) for symbol %d(%s) is already "
											"finished",
											dest_id, dep.sym.c_str(), item->id, item->symbol.c_str());
			}
		}

		return ret;
	};

	return inner_functor(0, item, dyn_item, inner_functor);
}


struct rspamd_symcache_delayed_cbdata {
	cache_item *item;
	struct rspamd_task *task;
	symcache_runtime *runtime;
	struct rspamd_async_event *event;
	struct ev_timer tm;
};

static void
rspamd_symcache_delayed_item_fin(gpointer ud)
{
	auto *cbd = (struct rspamd_symcache_delayed_cbdata *) ud;

	cbd->event = nullptr;
	cbd->runtime->unset_slow();
	ev_timer_stop(cbd->task->event_loop, &cbd->tm);
}

static void
rspamd_symcache_delayed_item_cb(EV_P_ ev_timer *w, int what)
{
	auto *cbd = (struct rspamd_symcache_delayed_cbdata *) w->data;

	if (cbd->event) {
		cbd->event = nullptr;

		/* Timer will be stopped here; `has_slow` is also reset there */
		rspamd_session_remove_event(cbd->task->s,
									rspamd_symcache_delayed_item_fin, cbd);

		cbd->runtime->process_item_rdeps(cbd->task, cbd->item);
	}
}

static void
rspamd_delayed_timer_dtor(gpointer d)
{
	auto *cbd = (struct rspamd_symcache_delayed_cbdata *) d;

	if (cbd->event) {
		/* Event has not been executed, this will also stop a timer */
		rspamd_session_remove_event(cbd->task->s,
									rspamd_symcache_delayed_item_fin, cbd);
		cbd->event = nullptr;
	}
}

auto symcache_runtime::finalize_item(struct rspamd_task *task, cache_dynamic_item *dyn_item) -> void
{
	/* Limit to consider a rule as slow (in milliseconds) */
	constexpr const double slow_diff_limit = 300;
	auto *item = get_item_by_dynamic_item(dyn_item);
	/* Sanity checks */
	g_assert(items_inflight > 0);
	g_assert(item != nullptr);

	if (dyn_item->async_events > 0) {
		/*
		 * XXX: Race condition
		 *
		 * It is possible that some async event is still in flight, but we
		 * already know its result, however, it is the responsibility of that
		 * event to decrease async events count and call this function
		 * one more time
		 */
		msg_debug_cache_task("postpone finalisation of %s(%d) as there are %d "
							 "async events pending",
							 item->symbol.c_str(), item->id, dyn_item->async_events);

		return;
	}

	msg_debug_cache_task("process finalize for item %s(%d)", item->symbol.c_str(), item->id);
	dyn_item->status = cache_item_status::finished;
	items_inflight--;
	cur_item = nullptr;

	auto enable_slow_timer = [&]() -> bool {
		auto *cbd = rspamd_mempool_alloc0_type(task->task_pool, rspamd_symcache_delayed_cbdata);
		/* Add timer to allow something else to be executed */
		ev_timer *tm = &cbd->tm;

		cbd->event = rspamd_session_add_event(task->s,
											  rspamd_symcache_delayed_item_fin, cbd,
											  "symcache");
		cbd->runtime = this;

		/*
		 * If no event could be added, then we are already in the destruction
		 * phase. So the main issue is to deal with has slow here
		 */
		if (cbd->event) {
			ev_timer_init(tm, rspamd_symcache_delayed_item_cb, 0.1, 0.0);
			ev_set_priority(tm, EV_MINPRI);
			rspamd_mempool_add_destructor(task->task_pool,
										  rspamd_delayed_timer_dtor, cbd);

			cbd->task = task;
			cbd->item = item;
			tm->data = cbd;
			ev_timer_start(task->event_loop, tm);
		}
		else {
			/* Just reset as no timer is added */
			slow_status = slow_status::none;
			return false;
		}

		return true;
	};

	/* Check if we need to profile symbol (always profile when we have seen this item to be slow */
	if (profile || item->flags & cache_item::bit_slow) {
		ev_now_update_if_cheap(task->event_loop);
		auto diff = ((ev_now(task->event_loop) - profile_start) * 1e3 -
					 dyn_item->start_msec);

		if (G_UNLIKELY(RSPAMD_TASK_IS_PROFILING(task))) {
			rspamd_task_profile_set(task, item->symbol.c_str(), diff);
		}

		if (rspamd_worker_is_scanner(task->worker)) {
			rspamd_set_counter(item->cd, diff);
		}

		if (diff > slow_diff_limit) {

			item->internal_flags |= cache_item::bit_slow;

			if (item->internal_flags & cache_item::bit_sync) {

				/*
				 * We also need to adjust start timer for all async rules that
				 * are started before this rule, as this rule could delay them
				 * on its own. Hence, we need to make some corrections for all
				 * rules pending
				 */

				for (const auto &[i, other_item]: rspamd::enumerate(order->d)) {
					auto *other_dyn_item = &dynamic_items[i];

					if (other_dyn_item->status == cache_item_status::pending && other_dyn_item->start_msec <= dyn_item->start_msec) {
						other_dyn_item->start_msec += diff;

						msg_debug_cache_task("adjust start time for %s(%d) by %.2fms to %dms",
											 other_item->symbol.c_str(),
											 other_item->id,
											 diff,
											 (int) other_dyn_item->start_msec);
					}
				}

				if (slow_status == slow_status::none) {
					slow_status = slow_status::enabled;

					msg_info_task("slow synchronous rule: %s(%d): %.2f ms; enable 100ms idle timer to allow other rules to be finished",
								  item->symbol.c_str(), item->id,
								  diff);
					if (enable_slow_timer()) {
						return;
					}
				}
				else {
					msg_info_task("slow synchronous rule: %s(%d): %.2f ms; idle timer has already been activated for this scan",
								  item->symbol.c_str(), item->id,
								  diff);
				}
			}
			else {
				msg_notice_task("slow asynchronous rule: %s(%d): %.2f ms; no idle timer is needed",
								item->symbol.c_str(), item->id,
								diff);
			}
		}
		else {
			item->internal_flags &= ~cache_item::bit_slow;
		}
	}

	process_item_rdeps(task, item);
}

auto symcache_runtime::process_item_rdeps(struct rspamd_task *task, cache_item *item) -> void
{
	auto *cache_ptr = reinterpret_cast<symcache *>(task->cfg->cache);

	// Avoid race condition with the runtime destruction and the delay timer
	if (!order) {
		return;
	}

	for (const auto &[id, rdep]: item->rdeps.values()) {
		if (rdep.item) {
			auto *dyn_item = get_dynamic_item(rdep.item->id);
			if (dyn_item->status == cache_item_status::not_started) {
				msg_debug_cache_task("check item %d(%s) rdep of %s ",
									 rdep.item->id, rdep.item->symbol.c_str(), item->symbol.c_str());

				if (!check_item_deps(task, *cache_ptr, rdep.item, dyn_item, false)) {
					msg_debug_cache_task("blocked execution of %d(%s) rdep of %s "
										 "unless deps are resolved",
										 rdep.item->id, rdep.item->symbol.c_str(), item->symbol.c_str());
				}
				else {
					process_symbol(task, *cache_ptr, rdep.item,
								   dyn_item);
				}
			}
		}
	}
}

auto symcache_runtime::get_item_by_dynamic_item(cache_dynamic_item *dyn_item) const -> cache_item *
{
	auto idx = dyn_item - dynamic_items;

	if (idx >= 0 && idx < order->size()) {
		return order->d[idx].get();
	}

	msg_err("internal error: invalid index to get: %d", (int) idx);

	return nullptr;
}

}// namespace rspamd::symcache
