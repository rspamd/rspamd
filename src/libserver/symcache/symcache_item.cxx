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
#include "symcache_item.hxx"
#include "fmt/core.h"

namespace rspamd::symcache {

auto cache_item::get_parent(const symcache &cache) const -> const cache_item *
{
	if (is_virtual()) {
		const auto &virtual_sp = std::get<virtual_item>(specific);

		return virtual_sp.get_parent(cache);
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

				std::size_t nids = 0;

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
					dit->rdeps.emplace_back(getptr(), dep.sym, id, -1);
					dep.item = dit->getptr();
					dep.id = dit->id;

					msg_debug_cache ("add dependency from %d on %d", id,
							dit->id);
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
	switch(type) {
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

auto virtual_item::get_parent(const symcache &cache) const -> const cache_item *
{
	if (parent) {
		return parent.get();
	}

	return cache.get_item_by_id(parent_id, false);
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
		return type & (trivial_types & ~exclude_bit);
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

}
