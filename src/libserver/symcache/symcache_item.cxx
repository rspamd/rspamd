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

#include "lua/lua_common.h"
#include "symcache_internal.hxx"
#include "symcache_item.hxx"
#include "fmt/core.h"
#include "libserver/task.h"
#include "libutil/cxx/util.hxx"
#include <numeric>
#include <functional>

namespace rspamd::symcache {

/* A list of internal augmentations that are known to Rspamd with their weight */
static const auto known_augmentations =
		robin_hood::unordered_flat_map<std::string, int, rspamd::smart_str_hash, rspamd::smart_str_equal>{
				{"passthrough", 10},
				{"single_network", 1},
				{"no_network", 0},
				{"many_network", 1},
				{"important", 5},
		};

auto cache_item::get_parent(const symcache &cache) const -> const cache_item *
{
	if (is_virtual()) {
		const auto &virtual_sp = std::get<virtual_item>(specific);

		return virtual_sp.get_parent(cache);
	}

	return nullptr;
}

auto cache_item::get_parent_mut(const symcache &cache) -> cache_item *
{
	if (is_virtual()) {
		auto &virtual_sp = std::get<virtual_item>(specific);

		return virtual_sp.get_parent_mut(cache);
	}

	return nullptr;
}

auto cache_item::process_deps(const symcache &cache) -> void
{
	/* Allow logging macros to work */
	auto log_tag = [&]() { return cache.log_tag(); };

	for (auto &dep: deps) {
		msg_debug_cache ("process real dependency %s on %s", symbol.c_str(), dep.sym.c_str());
		auto *dit = cache.get_item_by_name_mut(dep.sym, true);

		if (dep.vid >= 0) {
			/* Case of the virtual symbol that depends on another (maybe virtual) symbol */
			const auto *vdit = cache.get_item_by_name(dep.sym, false);

			if (!vdit) {
				if (dit) {
					msg_err_cache("cannot add dependency from %s on %s: no dependency symbol registered",
							dep.sym.c_str(), dit->symbol.c_str());
				}
			}
			else {
				msg_debug_cache("process virtual dependency %s(%d) on %s(%d)", symbol.c_str(),
						dep.vid, vdit->symbol.c_str(), vdit->id);

				unsigned nids = 0;

				/* Propagate ids */
				msg_debug_cache("check id propagation for dependency %s from %s",
						symbol.c_str(), dit->symbol.c_str());

				const auto *ids = dit->allowed_ids.get_ids(nids);

				if (nids > 0) {
					msg_debug_cache("propagate allowed ids from %s to %s",
							dit->symbol.c_str(), symbol.c_str());

					allowed_ids.set_ids(ids, nids, cache.get_pool());
				}

				ids = dit->forbidden_ids.get_ids(nids);

				if (nids > 0) {
					msg_debug_cache("propagate forbidden ids from %s to %s",
							dit->symbol.c_str(), symbol.c_str());

					forbidden_ids.set_ids(ids, nids, cache.get_pool());
				}
			}
		}

		if (dit != nullptr) {
			if (!dit->is_filter()) {
				/*
				 * Check sanity:
				 * - filters -> prefilter dependency is OK and always satisfied
				 * - postfilter -> (filter, prefilter) dep is ok
				 * - idempotent -> (any) dep is OK
				 *
				 * Otherwise, emit error
				 * However, even if everything is fine this dep is useless ¯\_(ツ)_/¯
				 */
				auto ok_dep = false;

				if (dit->get_type() == type) {
					ok_dep = true;
				}
				else if (type < dit->get_type()) {
					ok_dep = true;
				}

				if (!ok_dep) {
					msg_err_cache ("cannot add dependency from %s on %s: invalid symbol types",
							dep.sym.c_str(), symbol.c_str());

					continue;
				}
			}
			else {
				if (dit->id == id) {
					msg_err_cache ("cannot add dependency on self: %s -> %s "
								   "(resolved to %s)",
							symbol.c_str(), dep.sym.c_str(), dit->symbol.c_str());
				}
				else {
					/* Create a reverse dep */
					if (is_virtual()) {
						auto *parent = get_parent_mut(cache);

						if (parent) {
							dit->rdeps.emplace_back(parent->getptr(), dep.sym, parent->id, -1);
							dep.item = dit->getptr();
							dep.id = dit->id;

							msg_debug_cache ("added reverse dependency from %d on %d", parent->id,
									dit->id);
						}
					}
					else {
						dep.item = dit->getptr();
						dep.id = dit->id;
						dit->rdeps.emplace_back(getptr(), dep.sym, id, -1);
						msg_debug_cache ("added reverse dependency from %d on %d", id,
								dit->id);
					}
				}
			}
		}
		else if (dep.id >= 0) {
			msg_err_cache ("cannot find dependency on symbol %s for symbol %s",
					dep.sym.c_str(), symbol.c_str());

			continue;
		}
	}

	// Remove empty deps
	deps.erase(std::remove_if(std::begin(deps), std::end(deps),
			[](const auto &dep) { return !dep.item; }), std::end(deps));
}

auto cache_item::resolve_parent(const symcache &cache) -> bool
{
	auto log_tag = [&]() { return cache.log_tag(); };

	if (is_virtual()) {
		auto &virt = std::get<virtual_item>(specific);

		if (virt.get_parent(cache)) {
			msg_warn_cache("trying to resolve parent twice for %s", symbol.c_str());

			return false;
		}

		return virt.resolve_parent(cache);
	}
	else {
		msg_warn_cache("trying to resolve a parent for non-virtual symbol %s", symbol.c_str());
	}

	return false;
}

auto cache_item::update_counters_check_peak(lua_State *L,
											struct ev_loop *ev_loop,
											double cur_time,
											double last_resort) -> bool
{
	auto ret = false;
	static const double decay_rate = 0.25;

	st->total_hits += st->hits;
	g_atomic_int_set(&st->hits, 0);

	if (last_count > 0) {
		auto cur_value = (st->total_hits - last_count) /
						 (cur_time - last_resort);
		rspamd_set_counter_ema(&st->frequency_counter,
				cur_value, decay_rate);
		st->avg_frequency = st->frequency_counter.mean;
		st->stddev_frequency = st->frequency_counter.stddev;

		auto cur_err = (st->avg_frequency - cur_value);
		cur_err *= cur_err;

		if (st->frequency_counter.number > 10 &&
			cur_err > ::sqrt(st->stddev_frequency) * 3) {
			frequency_peaks++;
			ret = true;
		}
	}

	last_count = st->total_hits;

	if (cd->number > 0) {
		if (!is_virtual()) {
			st->avg_time = cd->mean;
			rspamd_set_counter_ema(&st->time_counter,
					st->avg_time, decay_rate);
			st->avg_time = st->time_counter.mean;
			memset(cd, 0, sizeof(*cd));
		}
	}

	return ret;
}

auto cache_item::get_type_str() const -> const char *
{
	switch (type) {
	case symcache_item_type::CONNFILTER:
		return "connfilter";
	case symcache_item_type::FILTER:
		return "filter";
	case symcache_item_type::IDEMPOTENT:
		return "idempotent";
	case symcache_item_type::PREFILTER:
		return "prefilter";
	case symcache_item_type::POSTFILTER:
		return "postfilter";
	case symcache_item_type::COMPOSITE:
		return "composite";
	case symcache_item_type::CLASSIFIER:
		return "classifier";
	case symcache_item_type::VIRTUAL:
		return "virtual";
	}

	RSPAMD_UNREACHABLE;
}

auto cache_item::is_allowed(struct rspamd_task *task, bool exec_only) const -> bool
{
	const auto *what = "execution";

	if (!exec_only) {
		what = "symbol insertion";
	}

	/* Static checks */
	if (!enabled ||
		(RSPAMD_TASK_IS_EMPTY(task) && !(flags & SYMBOL_TYPE_EMPTY)) ||
		(flags & SYMBOL_TYPE_MIME_ONLY && !RSPAMD_TASK_IS_MIME(task))) {

		if (!enabled) {
			msg_debug_cache_task("skipping %s of %s as it is permanently disabled",
					what, symbol.c_str());

			return false;
		}
		else {
			/*
			 * If we check merely execution (not insertion), then we disallow
			 * mime symbols for non mime tasks and vice versa
			 */
			if (exec_only) {
				msg_debug_cache_task("skipping check of %s as it cannot be "
									 "executed for this task type",
						symbol.c_str());

				return FALSE;
			}
		}
	}

	/* Settings checks */
	if (task->settings_elt != nullptr) {
		if (forbidden_ids.check_id(task->settings_elt->id)) {
			msg_debug_cache_task ("deny %s of %s as it is forbidden for "
								  "settings id %ud",
					what,
					symbol.c_str(),
					task->settings_elt->id);

			return false;
		}

		if (!(flags & SYMBOL_TYPE_EXPLICIT_DISABLE)) {
			if (!allowed_ids.check_id(task->settings_elt->id)) {

				if (task->settings_elt->policy == RSPAMD_SETTINGS_POLICY_IMPLICIT_ALLOW) {
					msg_debug_cache_task("allow execution of %s settings id %ud "
										 "allows implicit execution of the symbols;",
							symbol.c_str(),
							id);

					return true;
				}

				if (exec_only) {
					/*
					 * Special case if any of our virtual children are enabled
					 */
					if (exec_only_ids.check_id(task->settings_elt->id)) {
						return true;
					}
				}

				msg_debug_cache_task ("deny %s of %s as it is not listed "
									  "as allowed for settings id %ud",
						what,
						symbol.c_str(),
						task->settings_elt->id);
				return false;
			}
		}
		else {
			msg_debug_cache_task ("allow %s of %s for "
								  "settings id %ud as it can be only disabled explicitly",
					what,
					symbol.c_str(),
					task->settings_elt->id);
		}
	}
	else if (flags & SYMBOL_TYPE_EXPLICIT_ENABLE) {
		msg_debug_cache_task ("deny %s of %s as it must be explicitly enabled",
				what,
				symbol.c_str());
		return false;
	}

	/* Allow all symbols with no settings id */
	return true;
}

auto
cache_item::add_augmentation(const symcache &cache, std::string_view augmentation) -> bool {
	auto log_tag = [&]() { return cache.log_tag(); };

	if (augmentations.contains(augmentation)) {
		msg_warn_cache("duplicate augmentation: %s", augmentation.data());
	}

	augmentations.insert(std::string(augmentation));

	return known_augmentations.contains(augmentation);
}

auto
cache_item::get_augmentation_weight() const -> int
{
	return std::accumulate(std::begin(augmentations), std::end(augmentations),
						  0, [](int acc, const std::string &augmentation) {
		int zero = 0; /* C++ limitation of the cref */
		return acc + rspamd::find_map(known_augmentations, augmentation).value_or(std::cref<int>(zero));
	});
}


auto virtual_item::get_parent(const symcache &cache) const -> const cache_item *
{
	if (parent) {
		return parent.get();
	}

	return cache.get_item_by_id(parent_id, false);
}

auto virtual_item::get_parent_mut(const symcache &cache) -> cache_item *
{
	if (parent) {
		return parent.get();
	}

	return const_cast<cache_item *>(cache.get_item_by_id(parent_id, false));
}

auto virtual_item::resolve_parent(const symcache &cache) -> bool
{
	if (parent) {
		return false;
	}

	auto item_ptr = cache.get_item_by_id(parent_id, true);

	if (item_ptr) {
		parent = const_cast<cache_item *>(item_ptr)->getptr();

		return true;
	}

	return false;
}

auto item_type_from_c(enum rspamd_symbol_type type) -> tl::expected<std::pair<symcache_item_type, int>, std::string>
{
	constexpr const auto trivial_types = SYMBOL_TYPE_CONNFILTER | SYMBOL_TYPE_PREFILTER
										 | SYMBOL_TYPE_POSTFILTER | SYMBOL_TYPE_IDEMPOTENT
										 | SYMBOL_TYPE_COMPOSITE | SYMBOL_TYPE_CLASSIFIER
										 | SYMBOL_TYPE_VIRTUAL;

	constexpr auto all_but_one_ty = [&](int type, int exclude_bit) -> auto {
		return (type & trivial_types) & (trivial_types & ~exclude_bit);
	};

	if (type & trivial_types) {
		auto check_trivial = [&](auto flag,
								 symcache_item_type ty) -> tl::expected<std::pair<symcache_item_type, int>, std::string> {
			if (all_but_one_ty(type, flag)) {
				return tl::make_unexpected(fmt::format("invalid flags for a symbol: {}", type));
			}

			return std::make_pair(ty, type & ~flag);
		};
		if (type & SYMBOL_TYPE_CONNFILTER) {
			return check_trivial(SYMBOL_TYPE_CONNFILTER, symcache_item_type::CONNFILTER);
		}
		else if (type & SYMBOL_TYPE_PREFILTER) {
			return check_trivial(SYMBOL_TYPE_PREFILTER, symcache_item_type::PREFILTER);
		}
		else if (type & SYMBOL_TYPE_POSTFILTER) {
			return check_trivial(SYMBOL_TYPE_POSTFILTER, symcache_item_type::POSTFILTER);
		}
		else if (type & SYMBOL_TYPE_IDEMPOTENT) {
			return check_trivial(SYMBOL_TYPE_IDEMPOTENT, symcache_item_type::IDEMPOTENT);
		}
		else if (type & SYMBOL_TYPE_COMPOSITE) {
			return check_trivial(SYMBOL_TYPE_COMPOSITE, symcache_item_type::COMPOSITE);
		}
		else if (type & SYMBOL_TYPE_CLASSIFIER) {
			return check_trivial(SYMBOL_TYPE_CLASSIFIER, symcache_item_type::CLASSIFIER);
		}
		else if (type & SYMBOL_TYPE_VIRTUAL) {
			return check_trivial(SYMBOL_TYPE_VIRTUAL, symcache_item_type::VIRTUAL);
		}

		return tl::make_unexpected(fmt::format("internal error: impossible flags combination", type));
	}

	/* Maybe check other flags combination here? */
	return std::make_pair(symcache_item_type::FILTER, type);
}

bool operator<(symcache_item_type lhs, symcache_item_type rhs)
{
	auto ret = false;
	switch (lhs) {
	case symcache_item_type::CONNFILTER:
		break;
	case symcache_item_type::PREFILTER:
		if (rhs == symcache_item_type::CONNFILTER) {
			ret = true;
		}
		break;
	case symcache_item_type::FILTER:
		if (rhs == symcache_item_type::CONNFILTER || rhs == symcache_item_type::PREFILTER) {
			ret = true;
		}
		break;
	case symcache_item_type::POSTFILTER:
		if (rhs != symcache_item_type::IDEMPOTENT) {
			ret = true;
		}
		break;
	case symcache_item_type::IDEMPOTENT:
	default:
		break;
	}

	return ret;
}

item_condition::~item_condition()
{
	if (cb != -1 && L != nullptr) {
		luaL_unref(L, LUA_REGISTRYINDEX, cb);
	}
}

auto item_condition::check(std::string_view sym_name, struct rspamd_task *task) const -> bool
{
	if (cb != -1 && L != nullptr) {
		auto ret = false;

		lua_pushcfunction (L, &rspamd_lua_traceback);
		auto err_idx = lua_gettop(L);

		lua_rawgeti(L, LUA_REGISTRYINDEX, cb);
		rspamd_lua_task_push(L, task);

		if (lua_pcall(L, 1, 1, err_idx) != 0) {
			msg_info_task("call to condition for %s failed: %s",
					sym_name.data(), lua_tostring(L, -1));
		}
		else {
			ret = lua_toboolean(L, -1);
		}

		lua_settop(L, err_idx - 1);

		return ret;
	}

	return true;
}

}
