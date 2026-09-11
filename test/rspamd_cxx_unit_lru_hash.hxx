/*
 * Copyright 2026 Vsevolod Stakhov
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

#ifndef RSPAMD_RSPAMD_CXX_UNIT_LRU_HASH_HXX
#define RSPAMD_RSPAMD_CXX_UNIT_LRU_HASH_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

extern "C" {
#include "libutil/hash.h"
#include "libutil/str_util.h"
}

#include <string>
#include <vector>

TEST_SUITE("lru_hash")
{
	static int destroyed_values = 0;

	static void count_value_destroy(gpointer)
	{
		destroyed_values++;
	}

	static auto make_keys(int n) -> std::vector<std::string>
	{
		std::vector<std::string> keys;
		keys.reserve(n);
		for (int i = 0; i < n; i++) {
			keys.emplace_back("key" + std::to_string(i));
		}
		return keys;
	}

	TEST_CASE("sized constructor starts empty and grows on demand")
	{
		auto *h = rspamd_lru_hash_new_sized(64, 0, nullptr, nullptr,
											rspamd_strcase_hash, rspamd_strcase_equal);
		REQUIRE(h != nullptr);
		CHECK(rspamd_lru_hash_size(h) == 0);
		CHECK(rspamd_lru_hash_capacity(h) == 64);
		/* Lookup on a table with no buckets must not touch memory */
		CHECK(rspamd_lru_hash_lookup(h, "missing", -1) == nullptr);

		auto keys = make_keys(40);
		for (auto &k: keys) {
			rspamd_lru_hash_insert(h, (gpointer) k.c_str(), (gpointer) k.c_str(), -1, 0);
		}

		CHECK(rspamd_lru_hash_size(h) == 40);
		for (auto &k: keys) {
			auto *v = rspamd_lru_hash_lookup(h, k.c_str(), -1);
			REQUIRE(v != nullptr);
			CHECK(std::string((const char *) v) == k);
		}

		rspamd_lru_hash_destroy(h);
	}

	TEST_CASE("sized constructor keeps the element cap")
	{
		/* Under the eviction floor of 32 the cap is raised to that floor */
		auto *h = rspamd_lru_hash_new_sized(8, 0, nullptr, count_value_destroy,
											rspamd_strcase_hash, rspamd_strcase_equal);
		CHECK(rspamd_lru_hash_capacity(h) == 32);

		destroyed_values = 0;
		auto keys = make_keys(200);
		for (auto &k: keys) {
			rspamd_lru_hash_insert(h, (gpointer) k.c_str(), (gpointer) k.c_str(), -1, 0);
		}

		/*
		 * The cap is soft: eviction is probabilistic and the candidate pool
		 * is rebuilt after every rehash, so the table can sit a few entries
		 * above maxsize. It must stay in that neighbourhood though
		 */
		CHECK(rspamd_lru_hash_size(h) >= 32);
		CHECK(rspamd_lru_hash_size(h) < 32 + 16);
		CHECK(destroyed_values == 200 - (int) rspamd_lru_hash_size(h));

		rspamd_lru_hash_destroy(h);
		CHECK(destroyed_values == 200);
	}

	TEST_CASE("plain constructor still preallocates and behaves the same")
	{
		auto *h = rspamd_lru_hash_new_full(64, nullptr, nullptr,
										   rspamd_strcase_hash, rspamd_strcase_equal);
		auto keys = make_keys(200);
		for (int i = 0; i < 40; i++) {
			rspamd_lru_hash_insert(h, (gpointer) keys[i].c_str(), (gpointer) keys[i].c_str(), -1, 0);
		}
		CHECK(rspamd_lru_hash_size(h) == 40);
		CHECK(rspamd_lru_hash_lookup(h, "key7", -1) != nullptr);

		for (int i = 40; i < 200; i++) {
			rspamd_lru_hash_insert(h, (gpointer) keys[i].c_str(), (gpointer) keys[i].c_str(), -1, 0);
		}
		/* Same soft cap semantics as the sized constructor */
		CHECK(rspamd_lru_hash_size(h) >= 64);
		CHECK(rspamd_lru_hash_size(h) < 64 + 16);
		rspamd_lru_hash_destroy(h);
	}
}

#endif
