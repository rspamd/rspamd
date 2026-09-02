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
						  sizeof(struct cache_dynamic_item) * cur_order->size() +
						  sizeof(std::uint32_t) * cur_order->buckets.size();
	auto *checkpoint = (symcache_runtime *) rspamd_mempool_alloc0(task->task_pool,
																  allocated_size);
	msg_debug_cache_task("create symcache runtime for task: %d bytes, %d items, %d buckets",
						 (int) allocated_size, (int) cur_order->size(), (int) cur_order->buckets.size());
	/* Buckets counters live right after the dynamic items */
	checkpoint->bucket_pending = reinterpret_cast<std::uint32_t *>(checkpoint->dynamic_items + cur_order->size());

	for (const auto [i, bucket]: rspamd::enumerate(cur_order->buckets)) {
		checkpoint->bucket_pending[i] = bucket.count;
	}

	checkpoint->cur_stage = exec_stage::none;
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

	/*
	 * Settings policy: with the default policy, `symbols_enabled` is a whitelist
	 * (disable everything, then enable listed symbols); with `implicit_allow`,
	 * it is additive: all symbols stay enabled and the listed ones are merely
	 * unlocked (this is the only way to run `explicit_enable` symbols without
	 * switching to the whitelist mode).
	 * The policy is read from the applied settings themselves, as the registered
	 * settings element might not be attached to the task at this point (the
	 * settings plugin applies settings before setting the id).
	 */
	auto implicit_allow = false;
	const auto *policy_obj = ucl_object_lookup(task->settings, "policy");

	if (policy_obj && ucl_object_type(policy_obj) == UCL_STRING) {
		const auto *policy_str = ucl_object_tostring(policy_obj);

		if (g_ascii_strcasecmp(policy_str, "implicit_allow") == 0) {
			implicit_allow = true;
		}
		else if (g_ascii_strcasecmp(policy_str, "default") != 0 &&
				 g_ascii_strcasecmp(policy_str, "implicit_deny") != 0) {
			msg_warn_task("unknown settings policy: %s; ignore it", policy_str);
		}
	}

	const auto *enabled = ucl_object_lookup(task->settings, "symbols_enabled");

	/*
	 * Track explicitly enabled symbols: they both override settings_elt
	 * forbidden_ids and unlock symbols with the `explicit_enable` flag
	 */
	auto force_enable = [&](const char *sym) {
		enable_symbol(task, cache, sym);

		const auto *item = cache.get_item_by_name(sym, true);
		if (item) {
			add_force_enabled(item->id);
			msg_debug_cache_task("force-enable %s (id=%d)", sym, item->id);
		}
	};

	if (enabled) {
		if (implicit_allow) {
			msg_debug_cache_task("enable symbols from `symbols_enabled` additively "
								 "as the policy is `implicit_allow`");
		}
		else {
			msg_debug_cache_task("disable all symbols as `symbols_enabled` is found");
			/* Disable all symbols but selected */
			disable_all_symbols(SYMBOL_TYPE_EXPLICIT_DISABLE);
			already_disabled = true;
		}
		it = nullptr;

		while ((cur = ucl_iterate_object(enabled, &it, true)) != nullptr) {
			force_enable(ucl_object_tostring(cur));
		}
	}

	/* Enable groups of symbols */
	enabled = ucl_object_lookup(task->settings, "groups_enabled");
	if (enabled && !already_disabled && !implicit_allow) {
		disable_all_symbols(SYMBOL_TYPE_EXPLICIT_DISABLE);
	}
	process_group(enabled, [&](const char *sym) {
		force_enable(sym);
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
	delete force_enabled_ids;
	force_enabled_ids = nullptr;
}

auto symcache_runtime::add_force_enabled(int id) -> void
{
	if (!force_enabled_ids) {
		force_enabled_ids = new id_list();
	}
	force_enabled_ids->add_id(id);
}

auto symcache_runtime::is_force_enabled(int id) const -> bool
{
	return force_enabled_ids && force_enabled_ids->check_id(id);
}

auto symcache_runtime::disable_all_symbols(int skip_mask) -> void
{
	for (auto [i, item]: rspamd::enumerate(order->d)) {
		auto *dyn_item = &dynamic_items[i];

		/*
		 * The mask is checked against the flags and the type: the type bit is
		 * stripped from the flags at registration, so `SYMBOL_TYPE_IDEMPOTENT`
		 * in the mask spares the idempotent symbols as intended
		 */
		if (item->get_flags() & skip_mask) {
			continue;
		}

		if ((skip_mask & SYMBOL_TYPE_IDEMPOTENT) && item->get_type() == symcache_item_type::IDEMPOTENT) {
			continue;
		}

		/*
		 * Use `suppressed` not `disabled`: this implements the "disable all,
		 * then enable some" pattern from symbols_enabled/groups_enabled.
		 * Using `disabled` would cascade-disable hard dependents, which is
		 * wrong when an enabled symbol depends on a non-enabled one.
		 * Items that are already running are finalised as usual.
		 */
		if (dyn_item->status == cache_item_status::not_started) {
			set_status(dyn_item, cache_item_status::suppressed);
		}
	}
}

auto symcache_runtime::disable_symbol(struct rspamd_task *task, const symcache &cache, std::string_view name) -> bool
{
	const auto *item = cache.get_item_by_name(name, true);

	if (item != nullptr) {

		auto *dyn_item = get_dynamic_item(item->id);

		if (dyn_item) {
			if (dyn_item->status == cache_item_status::started ||
				dyn_item->status == cache_item_status::pending) {
				/* The item is running: it is finalised as usual */
				msg_debug_cache_task("cannot disable %s: it is already running", name.data());

				return false;
			}

			set_status(dyn_item, cache_item_status::disabled);
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
			switch (dyn_item->status) {
			case cache_item_status::started:
			case cache_item_status::pending:
			case cache_item_status::finished:
				/* Already executed (or being executed): never run an item twice */
				msg_debug_cache_task("cannot enable %s: it is %s", name.data(),
									 item_status_to_str(dyn_item->status));
				return false;
			default:
				break;
			}

			if (cur_stage != exec_stage::none && item->get_stage() < cur_stage) {
				msg_debug_cache_task("cannot enable %s: its stage (%s) has already passed", name.data(),
									 exec_stage_to_str(item->get_stage()));
				return false;
			}

			set_status(dyn_item, cache_item_status::not_started);

			if (item->get_flags() & SYMBOL_TYPE_EXPLICIT_ENABLE) {
				/* An explicit enable call unlocks `explicit_enable` symbols */
				add_force_enabled(item->id);
			}

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

static auto exec_stage_from_task_stage(unsigned int stage) -> exec_stage
{
	switch (stage) {
	case RSPAMD_TASK_STAGE_CONNFILTERS:
		return exec_stage::connfilters;
	case RSPAMD_TASK_STAGE_PRE_FILTERS:
		return exec_stage::prefilters;
	case RSPAMD_TASK_STAGE_FILTERS:
		return exec_stage::filters;
	case RSPAMD_TASK_STAGE_POST_FILTERS:
		return exec_stage::postfilters;
	case RSPAMD_TASK_STAGE_IDEMPOTENT:
		return exec_stage::idempotent;
	default:
		g_assert_not_reached();
	}
}

auto symcache_runtime::process_symbols(struct rspamd_task *task, symcache &cache, unsigned int stage) -> bool
{
	msg_debug_cache_task("symbols processing stage at pass: %d", stage);

	if (RSPAMD_TASK_IS_SKIPPED(task)) {
		return true;
	}

	auto st = exec_stage_from_task_stage(stage);

	if (st != cur_stage) {
		/*
		 * Entering a new stage: whatever has not been started at the previous
		 * stages will never run (e.g. after a passthrough result or a timeout),
		 * so mark it as skipped to let the dependents proceed
		 */
		sweep_earlier_stages(task, st);
		cur_stage = st;
	}

	return process_stage(task, cache, st);
}

auto symcache_runtime::sweep_earlier_stages(struct rspamd_task *task, exec_stage stage) -> void
{
	for (const auto [i, bucket]: rspamd::enumerate(order->buckets)) {
		if (bucket.stage >= stage) {
			break;
		}

		if (bucket_pending[i] == 0) {
			continue;
		}

		for (auto idx = bucket.first; idx < bucket.first + bucket.count; idx++) {
			auto *dyn_item = &dynamic_items[idx];

			if (dyn_item->status == cache_item_status::not_started) {
				msg_debug_cache_task("skip %s(%d) as its stage (%s) has passed",
									 order->d[idx]->symbol.c_str(), order->d[idx]->id,
									 exec_stage_to_str(bucket.stage));
				set_status(dyn_item, cache_item_status::skipped);
			}
		}
	}
}

auto symcache_runtime::should_skip(const cache_item *item, check_status status) -> bool
{
	if (status == check_status::allow) {
		return false;
	}

	switch (item->get_type()) {
	case symcache_item_type::IDEMPOTENT:
		/* Idempotent symbols always run */
		return false;
	case symcache_item_type::FILTER:
		/* Filters (hoisted ones included) are also stopped by the score limit */
		if (item->get_flags() & (SYMBOL_TYPE_FINE | SYMBOL_TYPE_IGNORE_PASSTHROUGH)) {
			return false;
		}

		return true;
	default:
		/* Connfilters, prefilters and postfilters are stopped by passthrough results only */
		if (item->get_flags() & SYMBOL_TYPE_IGNORE_PASSTHROUGH) {
			return false;
		}

		return status == check_status::passthrough;
	}
}

auto symcache_runtime::may_start(const cache_item *item, const cache_dynamic_item *dyn_item) const -> bool
{
	if (item->get_stage() != cur_stage) {
		return false;
	}

	auto idx = dyn_item - dynamic_items;
	auto bucket = order->item_bucket[idx];

	return bucket != order_generation::no_bucket && is_bucket_open(bucket);
}

auto symcache_runtime::process_stage(struct rspamd_task *task, symcache &cache, exec_stage stage) -> bool
{
	auto log_func = RSPAMD_LOG_FUNC;
	const auto [first_bucket, last_bucket] = order->stage_buckets[static_cast<unsigned int>(stage)];

	for (auto b = first_bucket; b < last_bucket; b++) {
		const auto &bucket = order->buckets[b];

		msg_debug_cache_task_lambda("process bucket %d: stage %s, level %d, %d items, %d pending",
									(int) b, exec_stage_to_str(bucket.stage), bucket.level,
									(int) bucket.count, (int) bucket_pending[b]);

		for (auto idx = bucket.first; idx < bucket.first + bucket.count; idx++) {
			if (RSPAMD_TASK_IS_SKIPPED(task)) {
				/* E.g. whitelisted by settings */
				return true;
			}

			auto *item = order->d[idx].get();
			auto *dyn_item = &dynamic_items[idx];

			if (dyn_item->status != cache_item_status::not_started) {
				continue;
			}

			auto check_result = check_process_status(task);

			if (should_skip(item, check_result)) {
				msg_debug_cache_task_lambda("skip %s(%d): task has %s",
											item->symbol.c_str(), item->id,
											check_result == check_status::passthrough ? "the passthrough result" : "reached the score limit");
				set_status(dyn_item, cache_item_status::skipped);
				continue;
			}

			if (slow_status == slow_status::enabled) {
				/* Let the slow timer fire before starting anything else */
				return false;
			}

			if (!check_item_deps(task, cache, item, dyn_item, false)) {
				msg_debug_cache_task_lambda("blocked execution of %d(%s) unless deps are "
											"resolved",
											item->id, item->symbol.c_str());
				continue;
			}

			process_symbol(task, cache, item, dyn_item);
		}

		if (bucket_pending[b] > 0) {
			/* The next level may not start until this one is drained */
			msg_debug_cache_task_lambda("bucket %d is not drained: %d items pending",
										(int) b, (int) bucket_pending[b]);
			return false;
		}
	}

	return true;
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
		 * or when items are cascade-disabled
		 */
		msg_debug_cache_task("skip already started %s(%d) symbol", item->symbol.c_str(), item->id);

		return is_item_done(dyn_item->status);
	}

	if (!may_start(item, dyn_item)) {
		/*
		 * Reached from a reverse dependency or an eager dependency check:
		 * the item belongs to another stage or its level is not open yet,
		 * so the stage loop starts it when its turn comes
		 */
		msg_debug_cache_task("cannot start %s(%d) now: stage %s, level %d",
							 item->symbol.c_str(), item->id,
							 exec_stage_to_str(item->get_stage()), item->get_level());

		return false;
	}

	/* Check has been started */
	auto check = true;

	if (!item->is_allowed(task, true) || !item->check_conditions(task)) {
		check = false;
	}

	if (check) {
		set_status(dyn_item, cache_item_status::started);
		msg_debug_cache_task("execute %s, %d; symbol type = %s, stage = %s, level = %d",
							 item->symbol.data(), item->id, item_type_to_str(item->type),
							 exec_stage_to_str(item->get_stage()), item->get_level());

		/*
		 * Stamp the start under the SAME condition finalize_item measures
		 * with (profile || bit_slow). Stamping under `profile` alone left
		 * start_msec at 0 on every non-profiled task once an item had been
		 * flagged slow: finalize then computed diff from the TASK start, so
		 * any DNS-bound or deadline-hitting scan was logged as a multi-second
		 * "slow synchronous rule" against that item — phantom slowness that
		 * also shifted pending items' start corrections by whole-scan
		 * amounts. One genuinely slow profiled call was enough to make the
		 * flagged rule blamed for every slow scan thereafter.
		 */
		if (profile || (item->flags & cache_item::bit_slow)) {
			ev_now_update_if_cheap(task->event_loop);
			dyn_item->start_msec = (ev_now(task->event_loop) -
									profile_start) *
								   1e3;
		}
		dyn_item->async_events = 0;
		/* Nested starts (from finalisation of another item) must not clobber the caller's item */
		auto *saved_cur_item = cur_item;
		cur_item = dyn_item;
		items_inflight++;
		/* Callback now must finalize itself */


		if (item->call(task, dyn_item)) {
			cur_item = saved_cur_item;

			if (is_item_done(dyn_item->status)) {
				/* Finalised synchronously */
				msg_debug_cache_task("item %s, %d is now finished (no async events)", item->symbol.data(),
									 item->id);
				return true;
			}

			if (dyn_item->async_events == 0) {
				msg_err_cache_task("critical error: item %s has no async events pending, "
								   "but it is not finalised",
								   item->symbol.data());
				g_assert_not_reached();
			}

			msg_debug_cache_task("item %s, %d is now pending with %d async events", item->symbol.data(),
								 item->id, dyn_item->async_events);

			return false;
		}
		else {
			/* We were not able to call item, so we assume it is not callable */
			msg_debug_cache_task("cannot call %s, %d; symbol type = %s", item->symbol.data(),
								 item->id, item_type_to_str(item->type));
			cur_item = saved_cur_item;
			items_inflight--;
			set_status(dyn_item, cache_item_status::finished);
			return true;
		}
	}
	else {
		msg_debug_cache_task("do not check %s, %d", item->symbol.data(),
							 item->id);
		set_status(dyn_item, cache_item_status::finished);
	}

	return true;
}

auto symcache_runtime::check_process_status(struct rspamd_task *task) -> symcache_runtime::check_status
{
	/* Stop on a passthrough result (least and process_all results do not count) */
	if (rspamd_scan_result_has_passthrough(task->result)) {
		return check_status::passthrough;
	}

	if (task->flags & RSPAMD_TASK_FLAG_PASS_ALL) {
		return check_status::allow;
	}

	/* Check score limit */
	if (!std::isnan(lim)) {
		if (task->result->score > lim) {
			return check_status::limit_reached;
		}
	}

	return check_status::allow;
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

			if (dep_dyn_item == nullptr) {
				/* Composites and classifiers of another order generation, or virtual */
				msg_debug_cache_task_lambda("symbol %d(%s) has a dependency %d(%s) without a dynamic item",
											item->id, item->symbol.c_str(), dest_id, dep.sym.c_str());
				continue;
			}

			if (dep_dyn_item->status == cache_item_status::not_started &&
				dep.item->get_stage() < cur_stage) {
				/*
				 * The dependency stage has passed (e.g. it was enabled too late),
				 * so it will never run
				 */
				msg_debug_cache_task_lambda("dependency %d(%s) for symbol %d(%s) belongs to the "
											"passed stage %s: skip it",
											dest_id, dep.sym.c_str(), item->id, item->symbol.c_str(),
											exec_stage_to_str(dep.item->get_stage()));
				set_status(dep_dyn_item, cache_item_status::skipped);
			}

			/*
			 * Cascade `disabled` and `skipped` to the hard dependents: their
			 * dependency will never produce a result. `suppressed` (not enabled by
			 * settings) does not cascade, as an enabled symbol may legitimately
			 * depend on a non-enabled one.
			 */
			const auto cascade = [&](cache_item_status dep_status) -> bool {
				if (dep_status == cache_item_status::disabled || dep_status == cache_item_status::skipped) {
					if (dep.hard) {
						set_status(dyn_item, dep_status);
						msg_debug_cache_task_lambda("cascade %s %d(%s) because hard dependency "
													"%d(%s) is %s",
													item_status_to_str(dep_status),
													item->id, item->symbol.c_str(),
													dest_id, dep.sym.c_str(),
													item_status_to_str(dep_status));
						return true;
					}

					/* Normal (weak) dependency: proceed without it (backward compat) */
					msg_debug_cache_task_lambda("dependency %d(%s) for symbol %d(%s) is "
												"%s, proceeding (not a hard dep)",
												dest_id, dep.sym.c_str(), item->id, item->symbol.c_str(),
												item_status_to_str(dep_status));
				}

				return false;
			};

			if (cascade(dep_dyn_item->status)) {
				return true; /* Item is "done" */
			}

			if (!is_item_done(dep_dyn_item->status)) {
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
						else if (cascade(dep_dyn_item->status)) {
							/* Dep was cascade-disabled or skipped during recursive check */
							return true;
						}
						else if (is_item_done(dep_dyn_item->status)) {
							msg_debug_cache_task_lambda("dependency %d(%s) for symbol %d(%s) is "
														"%s",
														dest_id, dep.sym.c_str(), item->id, item->symbol.c_str(),
														item_status_to_str(dep_dyn_item->status));
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
	set_status(dyn_item, cache_item_status::finished);
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
				bool need_slow = false;
				for (const auto &[i, other_item]: rspamd::enumerate(order->d)) {
					auto *other_dyn_item = &dynamic_items[i];

					if (other_dyn_item->status == cache_item_status::pending && other_dyn_item->start_msec <= dyn_item->start_msec) {
						other_dyn_item->start_msec += diff;

						msg_debug_cache_task("slow sync rule %s(%d); adjust start time for pending rule %s(%d) by %.2fms to %dms",
											 item->symbol.c_str(), item->id,
											 other_item->symbol.c_str(),
											 other_item->id,
											 diff,
											 (int) other_dyn_item->start_msec);
						/* We have something pending, so we need to enable slow timer */
						need_slow = true;
					}
				}

				if (need_slow && slow_status != slow_status::enabled) {
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
			if (rdep.item->get_stage() != cur_stage) {
				/* The stage loop deals with it when its stage comes */
				continue;
			}

			auto *dyn_item = get_dynamic_item(rdep.item->id);
			if (dyn_item && dyn_item->status == cache_item_status::not_started) {
				msg_debug_cache_task("check item %d(%s) rdep of %s ",
									 rdep.item->id, rdep.item->symbol.c_str(), item->symbol.c_str());

				if (should_skip(rdep.item, check_process_status(task))) {
					/* The same rule as in the stage loop: e.g. the score limit has been reached */
					msg_debug_cache_task("skip %d(%s) rdep of %s: passthrough or limit",
										 rdep.item->id, rdep.item->symbol.c_str(), item->symbol.c_str());
					set_status(dyn_item, cache_item_status::skipped);
					continue;
				}

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

auto symcache_runtime::describe_inflight_symbols() const -> GString *
{
	GString *out = nullptr;
	unsigned int nshown = 0;
	unsigned int nsuppressed = 0;
	constexpr unsigned int MAX_ITEMS_SHOWN = 32;

	if (items_inflight == 0) {
		return nullptr;
	}

	for (auto [i, item]: rspamd::enumerate(order->d)) {
		auto *dyn_item = &dynamic_items[i];

		if (dyn_item->status != cache_item_status::started &&
			dyn_item->status != cache_item_status::pending) {
			continue;
		}

		if (nshown >= MAX_ITEMS_SHOWN) {
			nsuppressed++;
			continue;
		}

		if (out == nullptr) {
			out = g_string_sized_new(128);
		}
		else {
			g_string_append(out, ", ");
		}

		const auto &name = item->get_name();
		if (dyn_item->start_msec > 0) {
			rspamd_printf_gstring(out, "%*s (async=%ud, started=%ud ms)",
								  (int) name.size(), name.data(),
								  (unsigned int) dyn_item->async_events,
								  (unsigned int) dyn_item->start_msec);
		}
		else {
			rspamd_printf_gstring(out, "%*s (async=%ud)",
								  (int) name.size(), name.data(),
								  (unsigned int) dyn_item->async_events);
		}
		nshown++;
	}

	if (nsuppressed > 0 && out != nullptr) {
		rspamd_printf_gstring(out, " (+%ud more)", nsuppressed);
	}

	return out;
}

}// namespace rspamd::symcache
