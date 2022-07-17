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
#include "symcache_runtime.hxx"
#include "unix-std.h"
#include "libutil/cxx/locked_file.hxx"
#include "libutil/cxx/util.hxx"
#include "fmt/core.h"
#include "contrib/t1ha/t1ha.h"

#include <cmath>

namespace rspamd::symcache {

INIT_LOG_MODULE_PUBLIC(symcache)

auto symcache::init() -> bool
{
	auto res = true;
	reload_time = cfg->cache_reload_time;

	if (cfg->cache_filename != nullptr) {
		msg_debug_cache("loading symcache saved data from %s", cfg->cache_filename);
		res = load_items();
	}

	ankerl::unordered_dense::set<int> disabled_ids;
	/* Process enabled/disabled symbols */
	for (const auto &[id, it]: items_by_id) {
		if (disabled_symbols) {
			/*
			 * Due to the ability to add patterns, this is now O(N^2), but it is done
			 * once on configuration and the amount of static patterns is usually low
			 * The possible optimization is to store non patterns in a different set to check it
			 * quickly. However, it is unlikely that this would be used to something really heavy.
			 */
			for (const auto &disable_pat: *disabled_symbols) {
				if (disable_pat.matches(it->get_name())) {
					msg_debug_cache("symbol %s matches %*s disable pattern", it->get_name().c_str(),
						(int)disable_pat.to_string_view().size(), disable_pat.to_string_view().data());
					auto need_disable = true;

					if (enabled_symbols) {
						for (const auto &enable_pat: *enabled_symbols) {
							if (enable_pat.matches(it->get_name())) {
								msg_debug_cache("symbol %s matches %*s enable pattern; skip disabling", it->get_name().c_str(),
										(int)enable_pat.to_string_view().size(), enable_pat.to_string_view().data());
								need_disable = false;
								break;
							}
						}
					}

					if (need_disable) {
						disabled_ids.insert(it->id);

						if (it->is_virtual()) {
							auto real_elt = it->get_parent(*this);

							if (real_elt) {
								disabled_ids.insert(real_elt->id);

								for (const auto &cld : real_elt->get_children().value().get()) {
									msg_debug_cache("symbol %s is a virtual sibling of the disabled symbol %s",
											cld->get_name().c_str(), it->get_name().c_str());
									disabled_ids.insert(cld->id);
								}
							}
						}
						else {
							/* Also disable all virtual children of this element */
							for (const auto &cld : it->get_children().value().get()) {
								msg_debug_cache("symbol %s is a virtual child of the disabled symbol %s",
										cld->get_name().c_str(), it->get_name().c_str());
								disabled_ids.insert(cld->id);
							}
						}
					}
				}
			}
		}
	}

	/* Deal with the delayed dependencies */
	msg_debug_cache("resolving delayed dependencies: %d in list", (int)delayed_deps->size());
	for (const auto &delayed_dep: *delayed_deps) {
		auto virt_item = get_item_by_name(delayed_dep.from, false);
		auto real_item = get_item_by_name(delayed_dep.from, true);

		if (virt_item == nullptr || real_item == nullptr) {
			msg_err_cache("cannot register delayed dependency between %s and %s: "
						  "%s is missing",
					delayed_dep.from.data(),
					delayed_dep.to.data(), delayed_dep.from.data());
		}
		else {

			if (!disabled_ids.contains(real_item->id)) {
				msg_debug_cache("delayed between %s(%d:%d) -> %s",
						delayed_dep.from.data(),
						real_item->id, virt_item->id,
						delayed_dep.to.data());
				add_dependency(real_item->id, delayed_dep.to,
						virt_item != real_item ? virt_item->id : -1);
			}
			else {
				msg_debug_cache("no delayed between %s(%d:%d) -> %s; %s is disabled",
						delayed_dep.from.data(),
						real_item->id, virt_item->id,
						delayed_dep.to.data(),
						delayed_dep.from.data());
			}
		}
	}

	/* Remove delayed dependencies, as they are no longer needed at this point */
	delayed_deps.reset();

	/* Physically remove ids that are disabled statically */
	for (auto id_to_disable : disabled_ids) {
		/*
		 * This erasure is inefficient, we can swap the last element with the removed id
		 * But in this way, our ids are still sorted by addition
		 */

		/* Preserve refcount here */
		auto deleted_element_refcount = items_by_id[id_to_disable];
		items_by_id.erase(id_to_disable);
		items_by_symbol.erase(deleted_element_refcount->get_name());

		auto &additional_vec = get_item_specific_vector(*deleted_element_refcount);
		std::erase_if(additional_vec, [id_to_disable](const cache_item_ptr &elt) {
			return elt->id == id_to_disable;
		});

		/* Refcount is dropped, so the symbol should be freed, ensure that nothing else owns this symbol */
		g_assert(deleted_element_refcount.use_count() == 1);
	}

	/* Remove no longer used stuff */
	enabled_symbols.reset();
	disabled_symbols.reset();

	/* Deal with the delayed conditions */
	msg_debug_cache("resolving delayed conditions: %d in list", (int)delayed_conditions->size());
	for (const auto &delayed_cond: *delayed_conditions) {
		auto it = get_item_by_name_mut(delayed_cond.sym, true);

		if (it == nullptr) {
			msg_err_cache (
					"cannot register delayed condition for %s",
					delayed_cond.sym.c_str());
			luaL_unref(delayed_cond.L, LUA_REGISTRYINDEX, delayed_cond.cbref);
		}
		else {
			if (!it->add_condition(delayed_cond.L, delayed_cond.cbref)) {
				msg_err_cache (
						"cannot register delayed condition for %s: virtual parent; qed",
						delayed_cond.sym.c_str());
				g_abort();
			}

			msg_debug_cache("added a condition to the symbol %s", it->symbol.c_str());
		}
	}
	delayed_conditions.reset();

	msg_debug_cache("process dependencies");
	for (const auto &[_id, it]: items_by_id) {
		it->process_deps(*this);
	}

	/* Sorting stuff */
	constexpr auto postfilters_cmp = [](const auto &it1, const auto &it2) -> bool {
		return it1->priority < it2->priority;
	};
	constexpr auto prefilters_cmp = [](const auto &it1, const auto &it2) -> bool {
		return it1->priority > it2->priority;
	};

	msg_debug_cache("sorting stuff");
	std::stable_sort(std::begin(connfilters), std::end(connfilters), prefilters_cmp);
	std::stable_sort(std::begin(prefilters), std::end(prefilters), prefilters_cmp);
	std::stable_sort(std::begin(postfilters), std::end(postfilters), postfilters_cmp);
	std::stable_sort(std::begin(idempotent), std::end(idempotent), postfilters_cmp);

	resort();

	/* Connect metric symbols with symcache symbols */
	if (cfg->symbols) {
		msg_debug_cache("connect metrics");
		g_hash_table_foreach(cfg->symbols,
				symcache::metric_connect_cb,
				(void *) this);
	}

	return res;
}

auto symcache::load_items() -> bool
{
	auto cached_map = util::raii_mmaped_locked_file::mmap_shared(cfg->cache_filename,
			O_RDONLY, PROT_READ);

	if (!cached_map.has_value()) {
		msg_info_cache("%s", cached_map.error().c_str());
		return false;
	}


	if (cached_map->get_size() < (gint) sizeof(symcache_header)) {
		msg_info_cache("cannot use file %s, truncated: %z", cfg->cache_filename,
				errno, strerror(errno));
		return false;
	}

	const auto *hdr = (struct symcache_header *) cached_map->get_map();

	if (memcmp(hdr->magic, symcache_magic,
			sizeof(symcache_magic)) != 0) {
		msg_info_cache("cannot use file %s, bad magic", cfg->cache_filename);

		return false;
	}

	auto *parser = ucl_parser_new(0);
	const auto *p = (const std::uint8_t *) (hdr + 1);

	if (!ucl_parser_add_chunk(parser, p, cached_map->get_size() - sizeof(*hdr))) {
		msg_info_cache ("cannot use file %s, cannot parse: %s", cfg->cache_filename,
				ucl_parser_get_error(parser));
		ucl_parser_free(parser);

		return false;
	}

	auto *top = ucl_parser_get_object(parser);
	ucl_parser_free(parser);

	if (top == nullptr || ucl_object_type(top) != UCL_OBJECT) {
		msg_info_cache ("cannot use file %s, bad object", cfg->cache_filename);
		ucl_object_unref(top);

		return false;
	}

	auto it = ucl_object_iterate_new(top);
	const ucl_object_t *cur;
	while ((cur = ucl_object_iterate_safe(it, true)) != nullptr) {
		auto item_it = items_by_symbol.find(ucl_object_key(cur));

		if (item_it != items_by_symbol.end()) {
			auto item = item_it->second;
			/* Copy saved info */
			/*
			 * XXX: don't save or load weight, it should be obtained from the
			 * metric
			 */
#if 0
			elt = ucl_object_lookup (cur, "weight");

			if (elt) {
				w = ucl_object_todouble (elt);
				if (w != 0) {
					item->weight = w;
				}
			}
#endif
			const auto *elt = ucl_object_lookup(cur, "time");
			if (elt) {
				item->st->avg_time = ucl_object_todouble(elt);
			}

			elt = ucl_object_lookup(cur, "count");
			if (elt) {
				item->st->total_hits = ucl_object_toint(elt);
				item->last_count = item->st->total_hits;
			}

			elt = ucl_object_lookup(cur, "frequency");
			if (elt && ucl_object_type(elt) == UCL_OBJECT) {
				const ucl_object_t *freq_elt;

				freq_elt = ucl_object_lookup(elt, "avg");

				if (freq_elt) {
					item->st->avg_frequency = ucl_object_todouble(freq_elt);
				}
				freq_elt = ucl_object_lookup(elt, "stddev");

				if (freq_elt) {
					item->st->stddev_frequency = ucl_object_todouble(freq_elt);
				}
			}

			if (item->is_virtual() && !item->is_ghost()) {
				const auto &parent = item->get_parent(*this);

				if (parent) {
					if (parent->st->weight < item->st->weight) {
						parent->st->weight = item->st->weight;
					}
				}
				/*
				 * We maintain avg_time for virtual symbols equal to the
				 * parent item avg_time
				 */
				item->st->avg_time = parent->st->avg_time;
			}

			total_weight += fabs(item->st->weight);
			total_hits += item->st->total_hits;
		}
	}

	ucl_object_iterate_free(it);
	ucl_object_unref(top);

	return true;
}

template<typename T>
static constexpr auto round_to_hundreds(T x)
{
	return (::floor(x) * 100.0) / 100.0;
}

bool symcache::save_items() const
{
	if (cfg->cache_filename == nullptr) {
		return false;
	}

	auto file_sink = util::raii_file_sink::create(cfg->cache_filename,
			O_WRONLY | O_TRUNC, 00644);

	if (!file_sink.has_value()) {
		if (errno == EEXIST) {
			/* Some other process is already writing data, give up silently */
			return false;
		}

		msg_err_cache("%s", file_sink.error().c_str());

		return false;
	}

	struct symcache_header hdr;
	memset(&hdr, 0, sizeof(hdr));
	memcpy(hdr.magic, symcache_magic, sizeof(symcache_magic));

	if (write(file_sink->get_fd(), &hdr, sizeof(hdr)) == -1) {
		msg_err_cache("cannot write to file %s, error %d, %s", cfg->cache_filename,
				errno, strerror(errno));

		return false;
	}

	auto *top = ucl_object_typed_new(UCL_OBJECT);

	for (const auto &it: items_by_symbol) {
		auto item = it.second;
		auto elt = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(elt,
				ucl_object_fromdouble(round_to_hundreds(item->st->weight)),
				"weight", 0, false);
		ucl_object_insert_key(elt,
				ucl_object_fromdouble(round_to_hundreds(item->st->time_counter.mean)),
				"time", 0, false);
		ucl_object_insert_key(elt, ucl_object_fromint(item->st->total_hits),
				"count", 0, false);

		auto *freq = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(freq,
				ucl_object_fromdouble(round_to_hundreds(item->st->frequency_counter.mean)),
				"avg", 0, false);
		ucl_object_insert_key(freq,
				ucl_object_fromdouble(round_to_hundreds(item->st->frequency_counter.stddev)),
				"stddev", 0, false);
		ucl_object_insert_key(elt, freq, "frequency", 0, false);

		ucl_object_insert_key(top, elt, it.first.data(), 0, true);
	}

	auto fp = fdopen(file_sink->get_fd(), "a");
	auto *efunc = ucl_object_emit_file_funcs(fp);
	auto ret = ucl_object_emit_full(top, UCL_EMIT_JSON_COMPACT, efunc, nullptr);
	ucl_object_emit_funcs_free(efunc);
	ucl_object_unref(top);
	fclose(fp);

	return ret;
}

auto symcache::metric_connect_cb(void *k, void *v, void *ud) -> void
{
	auto *cache = (symcache *) ud;
	const auto *sym = (const char *) k;
	auto *s = (struct rspamd_symbol *) v;
	auto weight = *s->weight_ptr;
	auto *item = cache->get_item_by_name_mut(sym, false);

	if (item) {
		item->st->weight = weight;
		s->cache_item = (void *) item;
	}
}


auto symcache::get_item_by_id(int id, bool resolve_parent) const -> const cache_item *
{
	if (id < 0 || id >= items_by_id.size()) {
		msg_err_cache("internal error: requested item with id %d, when we have just %d items in the cache",
				id, (int) items_by_id.size());
		return nullptr;
	}

	const auto &maybe_item = rspamd::find_map(items_by_id, id);

	if (!maybe_item.has_value()) {
		msg_err_cache("internal error: requested item with id %d but it is empty; qed",
				id);
		return nullptr;
	}

	const auto &item = maybe_item.value().get();

	if (resolve_parent && item->is_virtual()) {
		return item->get_parent(*this);
	}

	return item.get();
}

auto symcache::get_item_by_id_mut(int id, bool resolve_parent) const -> cache_item *
{
	if (id < 0 || id >= items_by_id.size()) {
		msg_err_cache("internal error: requested item with id %d, when we have just %d items in the cache",
				id, (int) items_by_id.size());
		return nullptr;
	}

	const auto &maybe_item = rspamd::find_map(items_by_id, id);

	if (!maybe_item.has_value()) {
		msg_err_cache("internal error: requested item with id %d but it is empty; qed",
				id);
		return nullptr;
	}

	const auto &item = maybe_item.value().get();

	if (resolve_parent && item->is_virtual()) {
		return const_cast<cache_item *>(item->get_parent(*this));
	}

	return item.get();
}

auto symcache::get_item_by_name(std::string_view name, bool resolve_parent) const -> const cache_item *
{
	auto it = items_by_symbol.find(name);

	if (it == items_by_symbol.end()) {
		return nullptr;
	}

	if (resolve_parent && it->second->is_virtual()) {
		return it->second->get_parent(*this);
	}

	return it->second.get();
}

auto symcache::get_item_by_name_mut(std::string_view name, bool resolve_parent) const -> cache_item *
{
	auto it = items_by_symbol.find(name);

	if (it == items_by_symbol.end()) {
		return nullptr;
	}

	if (resolve_parent && it->second->is_virtual()) {
		return (cache_item *) it->second->get_parent(*this);
	}

	return it->second.get();
}

auto symcache::add_dependency(int id_from, std::string_view to, int virtual_id_from) -> void
{
	g_assert (id_from >= 0 && id_from < (gint) items_by_id.size());
	const auto &source = items_by_id[id_from];
	g_assert (source.get() != nullptr);

	source->deps.emplace_back(cache_item_ptr{nullptr},
			std::string(to),
			id_from,
			-1);


	if (virtual_id_from >= 0) {
		g_assert (virtual_id_from < (gint) items_by_id.size());
		/* We need that for settings id propagation */
		const auto &vsource = items_by_id[virtual_id_from];
		g_assert (vsource.get() != nullptr);
		vsource->deps.emplace_back(cache_item_ptr{nullptr},
				std::string(to),
				-1,
				virtual_id_from);
	}
}

auto symcache::resort() -> void
{
	auto log_func = RSPAMD_LOG_FUNC;
	auto ord = std::make_shared<order_generation>(filters.size() +
			prefilters.size() +
			composites.size() +
			postfilters.size() +
			idempotent.size() +
			connfilters.size() +
			classifiers.size(), cur_order_gen);

	for (auto &it: filters) {
		if (it) {
			total_hits += it->st->total_hits;
			/* Unmask topological order */
			it->order = 0;
			ord->d.emplace_back(it);
		}
	}

	enum class tsort_mask {
		PERM,
		TEMP
	};

	constexpr auto tsort_unmask = [](cache_item *it) -> auto {
		return (it->order & ~((1u << 31) | (1u << 30)));
	};

	/* Recursive topological sort helper */
	const auto tsort_visit = [&](cache_item *it, unsigned cur_order, auto &&rec) {
		constexpr auto tsort_mark = [](cache_item *it, tsort_mask how) {
			switch (how) {
			case tsort_mask::PERM:
				it->order |= (1u << 31);
				break;
			case tsort_mask::TEMP:
				it->order |= (1u << 30);
				break;
			}
		};
		constexpr auto tsort_is_marked = [](cache_item *it, tsort_mask how) {
			switch (how) {
			case tsort_mask::PERM:
				return (it->order & (1u << 31));
			case tsort_mask::TEMP:
				return (it->order & (1u << 30));
			}

			return 100500u; /* Because fuck compilers, that's why */
		};

		if (tsort_is_marked(it, tsort_mask::PERM)) {
			if (cur_order > tsort_unmask(it)) {
				/* Need to recalculate the whole chain */
				it->order = cur_order; /* That also removes all masking */
			}
			else {
				/* We are fine, stop DFS */
				return;
			}
		}
		else if (tsort_is_marked(it, tsort_mask::TEMP)) {
			msg_err_cache_lambda("cyclic dependencies found when checking '%s'!",
					it->symbol.c_str());
			return;
		}

		tsort_mark(it, tsort_mask::TEMP);
		msg_debug_cache_lambda("visiting node: %s (%d)", it->symbol.c_str(), cur_order);

		for (const auto &dep: it->deps) {
			msg_debug_cache_lambda("visiting dep: %s (%d)", dep.item->symbol.c_str(), cur_order + 1);
			rec(dep.item.get(), cur_order + 1, rec);
		}

		it->order = cur_order;
		tsort_mark(it, tsort_mask::PERM);
	};
	/*
	 * Topological sort
	 */
	total_hits = 0;
	auto used_items = ord->d.size();

	for (const auto &it: ord->d) {
		if (it->order == 0) {
			tsort_visit(it.get(), 0, tsort_visit);
		}
	}


	/* Main sorting comparator */
	constexpr auto score_functor = [](auto w, auto f, auto t) -> auto {
		auto time_alpha = 1.0, weight_alpha = 0.1, freq_alpha = 0.01;

		return ((w > 0.0 ? w : weight_alpha) * (f > 0.0 ? f : freq_alpha) /
				(t > time_alpha ? t : time_alpha));
	};

	auto cache_order_cmp = [&](const auto &it1, const auto &it2) -> auto {
		constexpr const auto topology_mult = 1e7,
				priority_mult = 1e6,
				augmentations1_mult = 1e5;
		auto w1 = tsort_unmask(it1.get()) * topology_mult,
			w2 = tsort_unmask(it2.get()) * topology_mult;

		w1 += it1->priority * priority_mult;
		w2 += it2->priority * priority_mult;
		w1 += it1->get_augmentation_weight() * augmentations1_mult;
		w2 += it2->get_augmentation_weight() * augmentations1_mult;

		auto avg_freq = ((double) total_hits / used_items);
		auto avg_weight = (total_weight / used_items);
		auto f1 = (double) it1->st->total_hits / avg_freq;
		auto f2 = (double) it2->st->total_hits / avg_freq;
		auto weight1 = std::fabs(it1->st->weight) / avg_weight;
		auto weight2 = std::fabs(it2->st->weight) / avg_weight;
		auto t1 = it1->st->avg_time;
		auto t2 = it2->st->avg_time;
		w1 += score_functor(weight1, f1, t1);
		w2 += score_functor(weight2, f2, t2);

		return w1 > w2;
	};

	std::stable_sort(std::begin(ord->d), std::end(ord->d), cache_order_cmp);
	/*
	 * Here lives some ugly legacy!
	 * We have several filters classes, connfilters, prefilters, filters... etc
	 *
	 * Our order is meaningful merely for filters, but we have to add other classes
	 * to understand if those symbols are checked or disabled.
	 * We can disable symbols for almost everything but not for virtual symbols.
	 * The rule of thumb is that if a symbol has explicit parent, then it is a
	 * virtual symbol that follows it's special rules
	 */

	/*
	 * We enrich ord with all other symbol types without any sorting,
	 * as it is done in another place
	 */
	constexpr auto append_items_vec = [](const auto &vec, auto &out) {
		for (const auto &it: vec) {
			if (it) {
				out.emplace_back(it);
			}
		}
	};

	append_items_vec(connfilters, ord->d);
	append_items_vec(prefilters, ord->d);
	append_items_vec(postfilters, ord->d);
	append_items_vec(idempotent, ord->d);
	append_items_vec(composites, ord->d);
	append_items_vec(classifiers, ord->d);

	/* After sorting is done, we can assign all elements in the by_symbol hash */
	for (const auto [i, it] : rspamd::enumerate(ord->d)) {
		ord->by_symbol[it->get_name()] = i;
		ord->by_cache_id[it->id] = i;
	}
	/* Finally set the current order */
	std::swap(ord, items_by_order);
}

auto symcache::add_symbol_with_callback(std::string_view name,
										int priority,
										symbol_func_t func,
										void *user_data,
										enum rspamd_symbol_type flags_and_type) -> int
{
	auto real_type_pair_maybe = item_type_from_c(flags_and_type);

	if (!real_type_pair_maybe.has_value()) {
		msg_err_cache("incompatible flags when adding %s: %s", name.data(),
				real_type_pair_maybe.error().c_str());
		return -1;
	}

	auto real_type_pair = real_type_pair_maybe.value();

	if (real_type_pair.first != symcache_item_type::FILTER) {
		real_type_pair.second |= SYMBOL_TYPE_NOSTAT;
	}
	if (real_type_pair.second & (SYMBOL_TYPE_GHOST | SYMBOL_TYPE_CALLBACK)) {
		real_type_pair.second |= SYMBOL_TYPE_NOSTAT;
	}

	if (real_type_pair.first == symcache_item_type::VIRTUAL) {
		msg_err_cache("trying to add virtual symbol %s as real (no parent)", name.data());
		return -1;
	}

	if ((real_type_pair.second & SYMBOL_TYPE_FINE) && priority == 0) {
		/* Adjust priority for negative weighted symbols */
		priority = 1;
	}

	std::string static_string_name;

	if (name.empty()) {
		static_string_name = fmt::format("AUTO_{}_{}", (void *)func, user_data);
		msg_warn_cache("trying to add an empty symbol name, convert it to %s",
				static_string_name.c_str());
	}
	else {
		static_string_name = name;
	}

	if (items_by_symbol.contains(static_string_name)) {
		msg_err_cache("duplicate symbol name: %s", static_string_name.data());
		return -1;
	}

	auto id = items_by_id.size();

	auto item = cache_item::create_with_function(static_pool, id,
			std::move(static_string_name),
			priority, func, user_data,
			real_type_pair.first, real_type_pair.second);

	items_by_symbol[item->get_name()] = item;
	get_item_specific_vector(*item).push_back(item);
	items_by_id.emplace(id, item);

	if (!(real_type_pair.second & SYMBOL_TYPE_NOSTAT)) {
		cksum = t1ha(name.data(), name.size(), cksum);
		stats_symbols_count++;
	}

	return id;
}

auto symcache::add_virtual_symbol(std::string_view name, int parent_id, enum rspamd_symbol_type flags_and_type) -> int
{
	if (name.empty()) {
		msg_err_cache("cannot register a virtual symbol with no name; qed");
		return -1;
	}

	auto real_type_pair_maybe = item_type_from_c(flags_and_type);

	if (!real_type_pair_maybe.has_value()) {
		msg_err_cache("incompatible flags when adding %s: %s", name.data(),
				real_type_pair_maybe.error().c_str());
		return -1;
	}

	auto real_type_pair = real_type_pair_maybe.value();

	if (items_by_symbol.contains(name)) {
		msg_err_cache("duplicate symbol name: %s", name.data());
		return -1;
	}

	if (items_by_id.size() < parent_id) {
		msg_err_cache("parent id %d is out of bounds for virtual symbol %s", parent_id, name.data());
		return -1;
	}

	auto id = items_by_id.size();

	auto item = cache_item::create_with_virtual(static_pool,
			id,
			std::string{name},
			parent_id, real_type_pair.first, real_type_pair.second);
	const auto &parent = items_by_id[parent_id];
	parent->add_child(item);
	items_by_symbol[item->get_name()] = item;
	get_item_specific_vector(*item).push_back(item);
	items_by_id.emplace(id, item);

	return id;
}

auto symcache::set_peak_cb(int cbref) -> void
{
	if (peak_cb != -1) {
		luaL_unref(L, LUA_REGISTRYINDEX, peak_cb);
	}

	peak_cb = cbref;
	msg_info_cache("registered peak callback");
}

auto symcache::add_delayed_condition(std::string_view sym, int cbref) -> void
{
	delayed_conditions->emplace_back(sym, cbref, (lua_State *) cfg->lua_state);
}

auto symcache::validate(bool strict) -> bool
{
	total_weight = 1.0;

	for (auto &pair: items_by_symbol) {
		auto &item = pair.second;
		auto ghost = item->st->weight == 0 ? true : false;
		auto skipped = !ghost;

		if (item->is_scoreable() && g_hash_table_lookup(cfg->symbols, item->symbol.c_str()) == nullptr) {
			if (!std::isnan(cfg->unknown_weight)) {
				item->st->weight = cfg->unknown_weight;
				auto *s = rspamd_mempool_alloc0_type(static_pool,
						struct rspamd_symbol);
				/* Legit as we actually never modify this data */
				s->name = (char *) item->symbol.c_str();
				s->weight_ptr = &item->st->weight;
				g_hash_table_insert(cfg->symbols, (void *) s->name, (void *) s);

				msg_info_cache ("adding unknown symbol %s with weight: %.2f",
						item->symbol.c_str(), cfg->unknown_weight);
				ghost = false;
				skipped = false;
			}
			else {
				skipped = true;
			}
		}
		else {
			skipped = false;
		}

		if (!ghost && skipped) {
			if (!(item->flags & SYMBOL_TYPE_SKIPPED)) {
				item->flags |= SYMBOL_TYPE_SKIPPED;
				msg_warn_cache("symbol %s has no score registered, skip its check",
						item->symbol.c_str());
			}
		}

		if (ghost) {
			msg_debug_cache ("symbol %s is registered as ghost symbol, it won't be inserted "
							 "to any metric", item->symbol.c_str());
		}

		if (item->st->weight < 0 && item->priority == 0) {
			item->priority++;
		}

		if (item->is_virtual()) {
			if (!(item->flags & SYMBOL_TYPE_GHOST)) {
				auto *parent = const_cast<cache_item *>(item->get_parent(*this));

				if (parent == nullptr) {
					item->resolve_parent(*this);
					parent = const_cast<cache_item *>(item->get_parent(*this));
				}

				if (::fabs(parent->st->weight) < ::fabs(item->st->weight)) {
					parent->st->weight = item->st->weight;
				}

				auto p1 = ::abs(item->priority);
				auto p2 = ::abs(parent->priority);

				if (p1 != p2) {
					parent->priority = MAX(p1, p2);
					item->priority = parent->priority;
				}
			}
		}

		total_weight += fabs(item->st->weight);
	}

	/* Now check each metric item and find corresponding symbol in a cache */
	auto ret = true;
	GHashTableIter it;
	void *k, *v;
	g_hash_table_iter_init(&it, cfg->symbols);

	while (g_hash_table_iter_next(&it, &k, &v)) {
		auto ignore_symbol = false;
		auto sym_def = (struct rspamd_symbol *) v;

		if (sym_def && (sym_def->flags &
						(RSPAMD_SYMBOL_FLAG_IGNORE_METRIC | RSPAMD_SYMBOL_FLAG_DISABLED))) {
			ignore_symbol = true;
		}

		if (!ignore_symbol) {
			if (!items_by_symbol.contains((const char *) k)) {
				msg_debug_cache (
						"symbol '%s' has its score defined but there is no "
						"corresponding rule registered",
						k);
			}
		}
		else if (sym_def->flags & RSPAMD_SYMBOL_FLAG_DISABLED) {
			auto item = get_item_by_name_mut((const char *) k, false);

			if (item) {
				item->enabled = FALSE;
			}
		}
	}

	return ret;
}

auto symcache::counters() const -> ucl_object_t *
{
	auto *top = ucl_object_typed_new(UCL_ARRAY);
	constexpr const auto round_float = [](const auto x, const int digits) -> auto {
		const auto power10 = ::pow(10, digits);
		return (::floor(x * power10) / power10);
	};

	for (auto &pair: items_by_symbol) {
		auto &item = pair.second;
		auto symbol = pair.first;

		auto *obj = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(obj, ucl_object_fromlstring(symbol.data(), symbol.size()),
				"symbol", 0, false);

		if (item->is_virtual()) {
			if (!(item->flags & SYMBOL_TYPE_GHOST)) {
				const auto *parent = item->get_parent(*this);
				ucl_object_insert_key(obj,
						ucl_object_fromdouble(round_float(item->st->weight, 3)),
						"weight", 0, false);
				ucl_object_insert_key(obj,
						ucl_object_fromdouble(round_float(parent->st->avg_frequency, 3)),
						"frequency", 0, false);
				ucl_object_insert_key(obj,
						ucl_object_fromint(parent->st->total_hits),
						"hits", 0, false);
				ucl_object_insert_key(obj,
						ucl_object_fromdouble(round_float(parent->st->avg_time, 3)),
						"time", 0, false);
			}
			else {
				ucl_object_insert_key(obj,
						ucl_object_fromdouble(round_float(item->st->weight, 3)),
						"weight", 0, false);
				ucl_object_insert_key(obj,
						ucl_object_fromdouble(0.0),
						"frequency", 0, false);
				ucl_object_insert_key(obj,
						ucl_object_fromdouble(0.0),
						"hits", 0, false);
				ucl_object_insert_key(obj,
						ucl_object_fromdouble(0.0),
						"time", 0, false);
			}
		}
		else {
			ucl_object_insert_key(obj,
					ucl_object_fromdouble(round_float(item->st->weight, 3)),
					"weight", 0, false);
			ucl_object_insert_key(obj,
					ucl_object_fromdouble(round_float(item->st->avg_frequency, 3)),
					"frequency", 0, false);
			ucl_object_insert_key(obj,
					ucl_object_fromint(item->st->total_hits),
					"hits", 0, false);
			ucl_object_insert_key(obj,
					ucl_object_fromdouble(round_float(item->st->avg_time, 3)),
					"time", 0, false);
		}

		ucl_array_append(top, obj);
	}

	return top;
}

auto symcache::periodic_resort(struct ev_loop *ev_loop, double cur_time, double last_resort) -> void
{
	for (const auto &item: filters) {

		if (item->update_counters_check_peak(L, ev_loop, cur_time, last_resort)) {
			auto cur_value = (item->st->total_hits - item->last_count) /
							 (cur_time - last_resort);
			auto cur_err = (item->st->avg_frequency - cur_value);
			cur_err *= cur_err;
			msg_debug_cache ("peak found for %s is %.2f, avg: %.2f, "
							 "stddev: %.2f, error: %.2f, peaks: %d",
					item->symbol.c_str(), cur_value,
					item->st->avg_frequency,
					item->st->stddev_frequency,
					cur_err,
					item->frequency_peaks);

			if (peak_cb != -1) {
				struct ev_loop **pbase;

				lua_rawgeti(L, LUA_REGISTRYINDEX, peak_cb);
				pbase = (struct ev_loop **) lua_newuserdata(L, sizeof(*pbase));
				*pbase = ev_loop;
				rspamd_lua_setclass(L, "rspamd{ev_base}", -1);
				lua_pushlstring(L, item->symbol.c_str(), item->symbol.size());
				lua_pushnumber(L, item->st->avg_frequency);
				lua_pushnumber(L, ::sqrt(item->st->stddev_frequency));
				lua_pushnumber(L, cur_value);
				lua_pushnumber(L, cur_err);

				if (lua_pcall(L, 6, 0, 0) != 0) {
					msg_info_cache ("call to peak function for %s failed: %s",
							item->symbol.c_str(), lua_tostring(L, -1));
					lua_pop (L, 1);
				}
			}
		}
	}
}

symcache::~symcache()
{
	if (peak_cb != -1) {
		luaL_unref(L, LUA_REGISTRYINDEX, peak_cb);
	}
}

auto symcache::maybe_resort() -> bool
{
	if (items_by_order->generation_id != cur_order_gen) {
		/*
		 * Cache has been modified, need to resort it
		 */
		msg_info_cache("symbols cache has been modified since last check:"
					   " old id: %ud, new id: %ud",
				items_by_order->generation_id, cur_order_gen);
		resort();

		return true;
	}

	return false;
}

auto
symcache::get_item_specific_vector(const cache_item &it) -> symcache::items_ptr_vec &
{
	switch (it.get_type()) {
	case symcache_item_type::CONNFILTER:
		return connfilters;
	case symcache_item_type::FILTER:
		return filters;
	case symcache_item_type::IDEMPOTENT:
		return idempotent;
	case symcache_item_type::PREFILTER:
		return prefilters;
	case symcache_item_type::POSTFILTER:
		return postfilters;
	case symcache_item_type::COMPOSITE:
		return composites;
	case symcache_item_type::CLASSIFIER:
		return classifiers;
	case symcache_item_type::VIRTUAL:
		return virtual_symbols;
	}

	RSPAMD_UNREACHABLE;
}

auto
symcache::process_settings_elt(struct rspamd_config_settings_elt *elt) -> void
{

	auto id = elt->id;

	if (elt->symbols_disabled) {
		/* Process denied symbols */
		ucl_object_iter_t iter = nullptr;
		const ucl_object_t *cur;

		while ((cur = ucl_object_iterate(elt->symbols_disabled, &iter, true)) != NULL) {
			const auto *sym = ucl_object_key(cur);
			auto *item = get_item_by_name_mut(sym, false);

			if (item != nullptr) {
				if (item->is_virtual()) {
					/*
					 * Virtual symbols are special:
					 * we ignore them in symcache but prevent them from being
					 * inserted.
					 */
					item->forbidden_ids.add_id(id);
					msg_debug_cache("deny virtual symbol %s for settings %ud (%s); "
									"parent can still be executed",
							sym, id, elt->name);
				}
				else {
					/* Normal symbol, disable it */
					item->forbidden_ids.add_id(id);
					msg_debug_cache ("deny symbol %s for settings %ud (%s)",
							sym, id, elt->name);
				}
			}
			else {
				msg_warn_cache ("cannot find a symbol to disable %s "
								"when processing settings %ud (%s)",
						sym, id, elt->name);
			}
		}
	}

	if (elt->symbols_enabled) {
		ucl_object_iter_t iter = nullptr;
		const ucl_object_t *cur;

		while ((cur = ucl_object_iterate (elt->symbols_enabled, &iter, true)) != nullptr) {
			/* Here, we resolve parent and explicitly allow it */
			const auto *sym = ucl_object_key(cur);

			auto *item = get_item_by_name_mut(sym, false);

			if (item != nullptr) {
				if (item->is_virtual()) {
					auto *parent = get_item_by_name_mut(sym, true);

					if (parent) {
						if (elt->symbols_disabled &&
							ucl_object_lookup(elt->symbols_disabled, parent->symbol.data())) {
							msg_err_cache ("conflict in %s: cannot enable disabled symbol %s, "
										   "wanted to enable symbol %s",
									elt->name, parent->symbol.data(), sym);
							continue;
						}

						parent->exec_only_ids.add_id(id);
						msg_debug_cache ("allow just execution of symbol %s for settings %ud (%s)",
								parent->symbol.data(), id, elt->name);
					}
				}

				item->allowed_ids.add_id(id);
				msg_debug_cache ("allow execution of symbol %s for settings %ud (%s)",
						sym, id, elt->name);
			}
			else {
				msg_warn_cache ("cannot find a symbol to enable %s "
								"when processing settings %ud (%s)",
						sym, id, elt->name);
			}
		}
	}
}

}