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
#include <utility>
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
		 * Eviction fires as soon as an insertion reaches maxsize, so the
		 * steady state is maxsize - 1
		 */
		CHECK(rspamd_lru_hash_size(h) == 32 - 1);
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
		/* Same cap semantics as the sized constructor */
		CHECK(rspamd_lru_hash_size(h) == 64 - 1);
		rspamd_lru_hash_destroy(h);
	}

	/*
	 * Inserts n distinct owned keys (each twice if asked) at a fixed time and
	 * returns the largest size the table reached
	 */
	static auto fill_owned(rspamd_lru_hash_t * h, int n, unsigned int ttl,
						   bool twice) -> unsigned int
	{
		unsigned int max_size = 0;

		for (int i = 0; i < n; i++) {
			for (int j = 0; j < (twice ? 2 : 1); j++) {
				rspamd_lru_hash_insert(h, g_strdup_printf("key%d", i),
									   g_strdup("value"), 1000, ttl);
				max_size = MAX(max_size, rspamd_lru_hash_size(h));
			}
		}

		return max_size;
	}

	static void count_free_value(gpointer p)
	{
		destroyed_values++;
		g_free(p);
	}

	static auto make_owned(int maxsize) -> rspamd_lru_hash_t *
	{
		destroyed_values = 0;

		return rspamd_lru_hash_new_full(maxsize, g_free, count_free_value,
										rspamd_strcase_hash, rspamd_strcase_equal);
	}

	TEST_CASE("entries that never expire respect the cap")
	{
		/* The keypair cache inserts with ttl (unsigned) -1 */
		auto *h = make_owned(32);

		CHECK(fill_owned(h, 2000, (unsigned int) -1, false) == 32 - 1);
		CHECK(rspamd_lru_hash_size(h) == 32 - 1);
		CHECK(destroyed_values == 2000 - 31);

		rspamd_lru_hash_destroy(h);
		CHECK(destroyed_values == 2000);
	}

	TEST_CASE("unexpired volatile entries respect the cap")
	{
		/* DKIM and SPF caches insert with the DNS ttl */
		auto *h = make_owned(64);

		CHECK(fill_owned(h, 5000, 86400, false) == 64 - 1);
		CHECK(rspamd_lru_hash_size(h) == 64 - 1);

		rspamd_lru_hash_destroy(h);
		CHECK(destroyed_values == 5000);
	}

	TEST_CASE("a rehash at the cap still evicts")
	{
		/* Rehashes clear the candidate pool; the same insertion must evict */
		auto *h = make_owned(64);

		CHECK(fill_owned(h, 20000, 0, false) == 64 - 1);

		rspamd_lru_hash_destroy(h);
		CHECK(destroyed_values == 20000);
	}

	TEST_CASE("re-inserting an existing key keeps the cap")
	{
		/* E.g. two TLS session tickets in a row for the same host */
		auto *h = make_owned(64);

		CHECK(fill_owned(h, 20000, 0, true) == 64 - 1);
		CHECK(destroyed_values == 40000 - (int) rspamd_lru_hash_size(h));

		rspamd_lru_hash_destroy(h);
		CHECK(destroyed_values == 40000);
	}

	TEST_CASE("unexpired entries stay below the cap and expire after their ttl")
	{
		auto *h = make_owned(64);
		std::vector<std::string> keys = make_keys(63);

		for (auto &k: keys) {
			rspamd_lru_hash_insert(h, g_strdup(k.c_str()), g_strdup("value"), 1000, 100);
		}

		CHECK(rspamd_lru_hash_size(h) == 63);
		for (auto &k: keys) {
			CHECK(rspamd_lru_hash_lookup(h, k.c_str(), 1050) != nullptr);
		}
		CHECK(destroyed_values == 0);

		for (auto &k: keys) {
			CHECK(rspamd_lru_hash_lookup(h, k.c_str(), 1101) == nullptr);
		}
		CHECK(rspamd_lru_hash_size(h) == 0);
		CHECK(destroyed_values == 63);

		rspamd_lru_hash_destroy(h);
	}

	/*
	 * Usage counters of recently used keys must not be aged: the scan used to
	 * compare seconds with the minutes stored in each element, so every scan
	 * halved every counter and hot keys were evicted with the cold ones.
	 */
	TEST_CASE("hot keys survive a stream of cold ones")
	{
		/* Cold keys are inserted at the lookup time or a minute behind it */
		for (auto [ttl, lag]: {std::pair{0U, 0}, std::pair{(unsigned int) -1, 0},
							   std::pair{0U, 60}}) {
			CAPTURE(ttl);
			CAPTURE(lag);
			auto *h = make_owned(512);
			auto hot = make_keys(64);
			time_t now = 1700000000;
			unsigned int lookups = 0, misses = 0;

			/* Four hot lookups per cold insert, about a minute per 600 inserts */
			for (int i = 0; i < 50000; i++) {
				if (i % 600 == 0) {
					now += 60;
				}

				for (int j = 0; j < 4; j++) {
					const auto &k = hot[(i * 4 + j) % hot.size()];
					lookups++;

					if (rspamd_lru_hash_lookup(h, k.c_str(), now) == nullptr) {
						misses++;
						rspamd_lru_hash_insert(h, g_strdup(k.c_str()), g_strdup("hot"),
											   now, ttl);
					}
				}

				rspamd_lru_hash_insert(h, g_strdup_printf("cold%d", i), g_strdup("cold"),
									   now - lag, ttl);
			}

			/* About 43% (83% with the lag) of the lookups missed with broken aging */
			CHECK(misses < lookups / 20);
			rspamd_lru_hash_destroy(h);
		}
	}
}

#endif
