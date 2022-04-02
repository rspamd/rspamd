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
#include "unix-std.h"
#include "libutil/cxx/locked_file.hxx"

namespace rspamd::symcache {

INIT_LOG_MODULE_PUBLIC(symcache)

auto symcache::init() -> bool
{
	auto res = true;
	reload_time = cfg->cache_reload_time;

	if (cfg->cache_filename != NULL) {
		res = load_items();
	}

	struct rspamd_symcache_item *it, *vit;
	struct cache_dependency *dep;
	struct delayed_cache_dependency *ddep;
	struct delayed_cache_condition *dcond;
	GList *cur;
	gint i, j;

	cur = cache->delayed_deps;
	while (cur) {
		ddep = cur->data;

		vit = rspamd_symcache_find_filter(cache, ddep->from, false);
		it = rspamd_symcache_find_filter(cache, ddep->from, true);

		if (it == NULL || vit == NULL) {
			msg_err_cache ("cannot register delayed dependency between %s and %s: "
						   "%s is missing", ddep->from, ddep->to, ddep->from);
		}
		else {
			msg_debug_cache ("delayed between %s(%d:%d) -> %s", ddep->from,
					it->id, vit->id, ddep->to);
			rspamd_symcache_add_dependency(cache, it->id, ddep->to, vit != it ?
																	vit->id : -1);
		}

		cur = g_list_next (cur);
	}

	cur = cache->delayed_conditions;
	while (cur) {
		dcond = cur->data;

		it = rspamd_symcache_find_filter(cache, dcond->sym, true);

		if (it == NULL) {
			msg_err_cache (
					"cannot register delayed condition for %s",
					dcond->sym);
			luaL_unref(dcond->L, LUA_REGISTRYINDEX, dcond->cbref);
		}
		else {
			struct rspamd_symcache_condition *ncond = rspamd_mempool_alloc0 (cache->static_pool,
					sizeof(*ncond));
			ncond->cb = dcond->cbref;
			DL_APPEND(it->specific.normal.conditions, ncond);
		}

		cur = g_list_next (cur);
	}

	PTR_ARRAY_FOREACH (cache->items_by_id, i, it) {

		PTR_ARRAY_FOREACH (it->deps, j, dep) {
			rspamd_symcache_process_dep(cache, it, dep);
		}

		if (it->deps) {
			/* Reversed loop to make removal safe */
			for (j = it->deps->len - 1; j >= 0; j--) {
				dep = g_ptr_array_index (it->deps, j);

				if (dep->item == NULL) {
					/* Remove useless dep */
					g_ptr_array_remove_index(it->deps, j);
				}
			}
		}
	}

	/* Special case for virtual symbols */
	PTR_ARRAY_FOREACH (cache->virtual, i, it) {

		PTR_ARRAY_FOREACH (it->deps, j, dep) {
			rspamd_symcache_process_dep(cache, it, dep);
		}
	}

	g_ptr_array_sort_with_data(cache->connfilters, prefilters_cmp, cache);
	g_ptr_array_sort_with_data(cache->prefilters, prefilters_cmp, cache);
	g_ptr_array_sort_with_data(cache->postfilters, postfilters_cmp, cache);
	g_ptr_array_sort_with_data(cache->idempotent, postfilters_cmp, cache);

	rspamd_symcache_resort(cache);

	/* Connect metric symbols with symcache symbols */
	if (cache->cfg->symbols) {
		g_hash_table_foreach(cache->cfg->symbols,
				rspamd_symcache_metric_connect_cb,
				cache);
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
		msg_info_cache("cannot use file %s, truncated: %z", cfg->cache_filename, ,
				errno, strerror(errno));
		return false;
	}

	const auto *hdr = (struct symcache_header *)cached_map->get_map();

	if (memcmp(hdr->magic, symcache_magic,
			sizeof(symcache_magic)) != 0) {
		msg_info_cache("cannot use file %s, bad magic", cfg->cache_filename);

		return false;
	}

	auto *parser = ucl_parser_new(0);
	const auto *p = (const std::uint8_t *)(hdr + 1);

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

			if (item->is_virtual() && !(item->type & SYMBOL_TYPE_GHOST)) {
				g_assert (item->specific.virtual.parent < (gint)cache->items_by_id->len);
				parent = g_ptr_array_index (cache->items_by_id,
						item->specific.virtual.parent);
				item->specific.virtual.parent_item = parent;

				if (parent->st->weight < item->st->weight) {
					parent->st->weight = item->st->weight;
				}

				/*
				 * We maintain avg_time for virtual symbols equal to the
				 * parent item avg_time
				 */
				item->st->avg_time = parent->st->avg_time;
			}

			cache->total_weight += fabs(item->st->weight);
			cache->total_hits += item->st->total_hits;
		}
	}

	ucl_object_iterate_free(it);
	ucl_object_unref(top);

	return true;
}

auto symcache::get_item_by_id(int id, bool resolve_parent) const -> const cache_item_ptr &
{
	if (id < 0 || id >= items_by_id.size()) {
		g_abort();
	}

	auto &ret = items_by_id[id];

	if (!ret) {
		g_abort();
	}

	if (resolve_parent && ret->is_virtual()) {
		return ret->get_parent(*this);
	}

	return ret;
}


auto cache_item::get_parent(const symcache &cache) const -> const cache_item_ptr &
{
	if (is_virtual()) {
		const auto &virtual_sp = std::get<virtual_item>(specific);

		return virtual_sp.get_parent()
	}

	return cache_item_ptr{nullptr};
}

auto virtual_item::get_parent(const symcache &cache) const -> const cache_item_ptr &
{
	if (parent) {
		return parent;
	}

	return cache.get_item_by_id(parent_id, false);
}

}