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

#include "lua/lua_common.h"
#include "symcache_internal.hxx"
#include "symcache_item.hxx"
#include "fmt/base.h"
#include "libserver/task.h"
#include "libutil/cxx/util.hxx"
#include <numeric>
#include <functional>

namespace rspamd::symcache {

enum class augmentation_value_type {
	NO_VALUE,
	STRING_VALUE,
	NUMBER_VALUE,
};

struct augmentation_info {
	int weight = 0;
	int implied_flags = 0;
	augmentation_value_type value_type = augmentation_value_type::NO_VALUE;
};

/* A list of internal augmentations that are known to Rspamd with their weight */
static const auto known_augmentations =
	ankerl::unordered_dense::map<std::string, augmentation_info, rspamd::smart_str_hash, rspamd::smart_str_equal>{
		{"passthrough", {.weight = 10, .implied_flags = SYMBOL_TYPE_IGNORE_PASSTHROUGH}},
		{"single_network", {.weight = 1, .implied_flags = 0}},
		{"no_network", {.weight = 0, .implied_flags = 0}},
		{"many_network", {.weight = 1, .implied_flags = 0}},
		{"important", {.weight = 5, .implied_flags = SYMBOL_TYPE_FINE}},
		{"timeout", {
						.weight = 0,
						.implied_flags = 0,
						.value_type = augmentation_value_type::NUMBER_VALUE,
					}}};

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

	for (auto &[_id, dep]: deps) {
		msg_debug_cache("process real dependency %s on %s", symbol.c_str(), dep.sym.c_str());
		auto *dit = cache.get_item_by_name_mut(dep.sym, true);

		if (dep.virtual_source_id >= 0) {
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
								dep.virtual_source_id, vdit->symbol.c_str(), vdit->id);

				unsigned nids = 0;

				/* Propagate ids */
				msg_debug_cache("check id propagation for dependency %s from %s",
								symbol.c_str(), dit->symbol.c_str());

				const auto *ids = dit->allowed_ids.get_ids(nids);

				if (nids > 0) {
					msg_debug_cache("propagate allowed ids from %s to %s",
									dit->symbol.c_str(), symbol.c_str());

					allowed_ids.set_ids(ids, nids);
				}

				ids = dit->forbidden_ids.get_ids(nids);

				if (nids > 0) {
					msg_debug_cache("propagate forbidden ids from %s to %s",
									dit->symbol.c_str(), symbol.c_str());

					forbidden_ids.set_ids(ids, nids);
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
					msg_err_cache("cannot add dependency from %s on %s: invalid symbol types",
								  dep.sym.c_str(), symbol.c_str());

					continue;
				}

				dep.item = dit;
			}
			else {
				if (dit->id == id) {
					msg_err_cache("cannot add dependency on self: %s -> %s "
								  "(resolved to %s)",
								  symbol.c_str(), dep.sym.c_str(), dit->symbol.c_str());
				}
				else {
					/* Create a reverse dep */
					if (is_virtual()) {
						auto *parent = get_parent_mut(cache);

						if (parent) {
							if (!dit->rdeps.contains(parent->id)) {
								dit->rdeps.emplace(parent->id, cache_dependency{parent, parent->symbol, -1});
								msg_debug_cache("added reverse dependency from %d on %d", parent->id,
												dit->id);
							}
							else {
								msg_debug_cache("reverse dependency from %d on %d already exists",
												parent->id, dit->id);
							}
							dep.item = dit;
						}
						else {
							msg_err_cache("cannot find parent for virtual symbol %s, when resolving dependency %s",
										  symbol.c_str(), dep.sym.c_str());
						}
					}
					else {
						dep.item = dit;
						if (!dit->rdeps.contains(id)) {
							dit->rdeps.emplace(id, cache_dependency{this, symbol, -1});
							msg_debug_cache("added reverse dependency from %d on %d", id,
											dit->id);
						}
						else {
							msg_debug_cache("reverse dependency from %d on %d already exists",
											id, dit->id);
						}
					}
				}
			}
		}
		else {
			msg_err_cache("cannot find dependency named %s for symbol %s",
						  dep.sym.c_str(), symbol.c_str());
		}
	}

	// Remove empty deps
	for (auto it = deps.begin(); it != deps.end();) {
		if (it->second.item == nullptr) {
			msg_info_cache("remove empty dependency on %s for symbol %s",
						   it->second.sym.c_str(), symbol.c_str());
			it = deps.erase(it);
		}
		else {
			++it;
		}
	}
}

auto cache_item::resolve_parent(const symcache &cache) -> bool
{
	auto log_tag = [&]() { return cache.log_tag(); };

	if (is_virtual()) {
		auto &virt = std::get<virtual_item>(specific);

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

auto cache_item::inc_frequency(const char *sym_name, symcache &cache) -> void
{
	if (sym_name && symbol != sym_name) {
		if (is_filter()) {
			const auto *children = get_children();
			if (children) {
				/* Likely a callback symbol with some virtual symbol that needs to be adjusted */
				for (const auto &cld: *children) {
					if (cld->get_name() == sym_name) {
						cld->inc_frequency(sym_name, cache);
					}
				}
			}
		}
		else {
			/* Name not equal to symbol name, so we need to find the proper name */
			auto *another_item = cache.get_item_by_name_mut(sym_name, false);
			if (another_item != nullptr) {
				another_item->inc_frequency(sym_name, cache);
			}
		}
	}
	else {
		/* Symbol and sym name are the same */
		g_atomic_int_inc(&st->hits);
	}
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
	if (!(internal_flags & cache_item::bit_enabled) ||
		(RSPAMD_TASK_IS_EMPTY(task) && !(flags & SYMBOL_TYPE_EMPTY)) ||
		(flags & SYMBOL_TYPE_MIME_ONLY && !RSPAMD_TASK_IS_MIME(task))) {

		if (!(internal_flags & cache_item::bit_enabled)) {
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
			msg_debug_cache_task("deny %s of %s as it is forbidden for "
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

				msg_debug_cache_task("deny %s of %s as it is not listed "
									 "as allowed for settings id %ud",
									 what,
									 symbol.c_str(),
									 task->settings_elt->id);
				return false;
			}
		}
		else {
			msg_debug_cache_task("allow %s of %s for "
								 "settings id %ud as it can be only disabled explicitly",
								 what,
								 symbol.c_str(),
								 task->settings_elt->id);
		}
	}
	else if (flags & SYMBOL_TYPE_EXPLICIT_ENABLE) {
		msg_debug_cache_task("deny %s of %s as it must be explicitly enabled",
							 what,
							 symbol.c_str());
		return false;
	}

	/* Allow all symbols with no settings id */
	return true;
}

auto cache_item::add_augmentation(const symcache &cache, std::string_view augmentation,
								  std::optional<std::string_view> value) -> bool
{
	auto log_tag = [&]() { return cache.log_tag(); };

	if (augmentations.contains(augmentation)) {
		msg_warn_cache("duplicate augmentation: %s", augmentation.data());

		return false;
	}

	auto maybe_known = rspamd::find_map(known_augmentations, augmentation);

	if (maybe_known.has_value()) {
		auto &known_info = maybe_known.value().get();

		if (known_info.implied_flags) {
			if ((known_info.implied_flags & flags) == 0) {
				msg_info_cache("added implied flags (%bd) for symbol %s as it has %s augmentation",
							   known_info.implied_flags, symbol.data(), augmentation.data());
				flags |= known_info.implied_flags;
			}
		}

		if (known_info.value_type == augmentation_value_type::NO_VALUE) {
			if (value.has_value()) {
				msg_err_cache("value specified for augmentation %s, that has no value",
							  augmentation.data());

				return false;
			}
			return augmentations.try_emplace(augmentation, known_info.weight).second;
		}
		else {
			if (!value.has_value()) {
				msg_err_cache("value is not specified for augmentation %s, that requires explicit value",
							  augmentation.data());

				return false;
			}

			if (known_info.value_type == augmentation_value_type::STRING_VALUE) {
				return augmentations.try_emplace(augmentation, std::string{value.value()},
												 known_info.weight)
					.second;
			}
			else if (known_info.value_type == augmentation_value_type::NUMBER_VALUE) {
				/* I wish it was supported properly */
				//auto conv_res = std::from_chars(value->data(), value->size(), num);
				char numbuf[128], *endptr = nullptr;
				rspamd_strlcpy(numbuf, value->data(), MIN(value->size(), sizeof(numbuf)));
				auto num = g_ascii_strtod(numbuf, &endptr);

				if (fabs(num) >= G_MAXFLOAT || std::isnan(num)) {
					msg_err_cache("value for augmentation %s is not numeric: %*s",
								  augmentation.data(),
								  (int) value->size(), value->data());
					return false;
				}

				return augmentations.try_emplace(augmentation, num,
												 known_info.weight)
					.second;
			}
		}
	}
	else {
		msg_debug_cache("added unknown augmentation %s for symbol %s",
						"unknown", augmentation.data(), symbol.data());
		return augmentations.try_emplace(augmentation, 0).second;
	}

	// Should not be reached
	return false;
}

auto cache_item::get_augmentation_weight() const -> int
{
	return std::accumulate(std::begin(augmentations), std::end(augmentations),
						   0, [](int acc, const auto &map_pair) {
							   return acc + map_pair.second.weight;
						   });
}

auto cache_item::get_numeric_augmentation(std::string_view name) const -> std::optional<double>
{
	const auto augmentation_value_maybe = rspamd::find_map(this->augmentations, name);

	if (augmentation_value_maybe.has_value()) {
		const auto &augmentation = augmentation_value_maybe.value().get();

		if (std::holds_alternative<double>(augmentation.value)) {
			return std::get<double>(augmentation.value);
		}
	}

	return std::nullopt;
}


auto virtual_item::get_parent(const symcache &cache) const -> const cache_item *
{
	if (parent) {
		return parent;
	}

	return cache.get_item_by_id(parent_id, false);
}

auto virtual_item::get_parent_mut(const symcache &cache) -> cache_item *
{
	if (parent) {
		return parent;
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
		parent = const_cast<cache_item *>(item_ptr);

		return true;
	}

	return false;
}

auto item_type_from_c(int type) -> tl::expected<std::pair<symcache_item_type, int>, std::string>
{
	constexpr const auto trivial_types = SYMBOL_TYPE_CONNFILTER | SYMBOL_TYPE_PREFILTER | SYMBOL_TYPE_POSTFILTER | SYMBOL_TYPE_IDEMPOTENT | SYMBOL_TYPE_COMPOSITE | SYMBOL_TYPE_CLASSIFIER | SYMBOL_TYPE_VIRTUAL;

	constexpr auto all_but_one_ty = [&](int type, int exclude_bit) -> auto {
		return (type & trivial_types) & (trivial_types & ~exclude_bit);
	};

	if (type & trivial_types) {
		auto check_trivial = [&](auto flag,
								 symcache_item_type ty) -> tl::expected<std::pair<symcache_item_type, int>, std::string> {
			if (all_but_one_ty(type, flag)) {
				return tl::make_unexpected(fmt::format("invalid flags for a symbol: {}", (int) type));
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

		return tl::make_unexpected(fmt::format("internal error: impossible flags combination: {}", (int) type));
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

		lua_pushcfunction(L, &rspamd_lua_traceback);
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

}// namespace rspamd::symcache
