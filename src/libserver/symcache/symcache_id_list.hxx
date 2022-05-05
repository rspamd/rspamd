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

#ifndef RSPAMD_SYMCACHE_ID_LIST_HXX
#define RSPAMD_SYMCACHE_ID_LIST_HXX
#pragma once

#include <cstdint>
#include <cstring> // for memset
#include <algorithm> // for sort/bsearch

#include "config.h"
#include "libutil/mem_pool.h"

namespace rspamd::symcache {
/*
 * This structure is optimised to store ids list:
 * - If the first element is -1 then use dynamic part, else use static part
 * There is no std::variant to save space
 */
struct id_list {
	union {
		std::uint32_t st[4];
		struct {
			std::uint32_t e; /* First element */
			std::uint16_t len;
			std::uint16_t allocated;
			std::uint32_t *n;
		} dyn;
	} data;

	id_list() = default;

	auto reset()
	{
		std::memset(&data, 0, sizeof(data));
	}

	/**
	 * Returns ids from a compressed list, accepting a mutable reference for number of elements
	 * @param nids output of the number of elements
	 * @return
	 */
	auto get_ids(unsigned &nids) const -> const std::uint32_t *
	{
		if (data.dyn.e == -1) {
			/* Dynamic list */
			nids = data.dyn.len;

			return data.dyn.n;
		}
		else {
			auto cnt = 0;

			while (data.st[cnt] != 0 && cnt < G_N_ELEMENTS(data.st)) {
				cnt++;
			}

			nids = cnt;

			return data.st;
		}
	}

	auto add_id(std::uint32_t id, rspamd_mempool_t *pool) -> void
	{
		if (data.st[0] == -1) {
			/* Dynamic array */
			if (data.dyn.len < data.dyn.allocated) {
				/* Trivial, append + sort */
				data.dyn.n[data.dyn.len++] = id;
			}
			else {
				/* Reallocate */
				g_assert(data.dyn.allocated <= G_MAXINT16);
				data.dyn.allocated *= 2;

				auto *new_array = rspamd_mempool_alloc_array_type(pool,
						data.dyn.allocated, std::uint32_t);
				memcpy(new_array, data.dyn.n, data.dyn.len * sizeof(std::uint32_t));
				data.dyn.n = new_array;
				data.dyn.n[data.dyn.len++] = id;
			}

			std::sort(data.dyn.n, data.dyn.n + data.dyn.len);
		}
		else {
			/* Static part */
			auto cnt = 0u;
			while (data.st[cnt] != 0 && cnt < G_N_ELEMENTS(data.st)) {
				cnt++;
			}

			if (cnt < G_N_ELEMENTS(data.st)) {
				data.st[cnt] = id;
			}
			else {
				/* Switch to dynamic */
				data.dyn.allocated = G_N_ELEMENTS(data.st) * 2;
				auto *new_array = rspamd_mempool_alloc_array_type(pool,
						data.dyn.allocated, std::uint32_t);
				memcpy(new_array, data.st, sizeof(data.st));
				data.dyn.n = new_array;
				data.dyn.e = -1; /* Marker */
				data.dyn.len = G_N_ELEMENTS(data.st);

				/* Recursively jump to dynamic branch that will handle insertion + sorting */
				add_id(id, pool); // tail call
			}
		}
	}

	auto set_ids(const std::uint32_t *ids, std::size_t nids, rspamd_mempool_t *pool) -> void
	{
		if (nids <= G_N_ELEMENTS(data.st)) {
			/* Use static version */
			reset();

			for (auto i = 0; i < nids; i++) {
				data.st[i] = ids[i];
			}
		}
		else {
			/* Need to use a separate list */
			data.dyn.e = -1; /* Flag */
			data.dyn.n = rspamd_mempool_alloc_array_type(pool, nids, std::uint32_t);
			data.dyn.len = nids;
			data.dyn.allocated = nids;

			for (auto i = 0; i < nids; i++) {
				data.dyn.n[i] = ids[i];
			}

			/* Keep sorted */
			std::sort(data.dyn.n, data.dyn.n + data.dyn.len);
		}
	}

	auto check_id(unsigned int id) const -> bool
	{
		if (data.dyn.e == -1) {
			return std::binary_search(data.dyn.n, data.dyn.n + data.dyn.len, id);
		}
		else {
			for (auto elt: data.st) {
				if (elt == id) {
					return true;
				}
				else if (elt == 0) {
					return false;
				}
			}
		}

		return false;
	}
};

static_assert(std::is_trivial_v<id_list>);

}

#endif //RSPAMD_SYMCACHE_ID_LIST_HXX
