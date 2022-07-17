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
#include "contrib/ankerl/svector.h"

namespace rspamd::symcache {
/*
 * This structure is optimised to store ids list:
 * - If the first element is -1 then use dynamic part, else use static part
 * There is no std::variant to save space
 */

constexpr const auto id_capacity = 4;
constexpr const auto id_sort_threshold = 32;

struct id_list {
	ankerl::svector<std::uint32_t, id_capacity> data;

	id_list() = default;

	auto reset(){
		data.clear();
	}

	/**
	 * Returns ids from a compressed list, accepting a mutable reference for number of elements
	 * @param nids output of the number of elements
	 * @return
	 */
	auto get_ids(unsigned &nids) const -> const std::uint32_t *
	{
		nids = data.size();

		return data.data();
	}

	auto add_id(std::uint32_t id) -> void
	{
		data.push_back(id);

		/* Check sort threshold */
		if (data.size() > id_sort_threshold) {
			std::sort(data.begin(), data.end());
		}
	}

	auto set_ids(const std::uint32_t *ids, std::size_t nids) -> void {
		data.resize(nids);

		for (auto &id : data) {
			id = *ids++;
		}

		if (data.size() > id_sort_threshold) {
			std::sort(data.begin(), data.end());
		}
	}

	auto check_id(unsigned int id) const -> bool
	{
		if (data.size() > id_sort_threshold) {
			return std::binary_search(data.begin(), data.end(), id);
		}
		return std::find(data.begin(), data.end(), id) != data.end();
	}
};

}

#endif //RSPAMD_SYMCACHE_ID_LIST_HXX
