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

/* Unit tests for upstream ring hash (ketama) consistent hashing */

#ifndef RSPAMD_CXX_UNIT_UPSTREAM_RING_HASH_HXX
#define RSPAMD_CXX_UNIT_UPSTREAM_RING_HASH_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "libutil/upstream.h"

#include <map>
#include <set>
#include <string>
#include <vector>

/*
 * Helper: create an upstream_ctx + upstream_list with N numeric IP upstreams
 * configured for HASHED rotation.
 * Uses 127.0.0.x addresses on port 11333 to avoid DNS resolution.
 */
struct ring_hash_test_ctx {
	struct upstream_ctx *ctx;
	struct upstream_list *ups;
	unsigned int n_upstreams;

	ring_hash_test_ctx(unsigned int n)
		: n_upstreams(n)
	{
		ctx = rspamd_upstreams_library_init();
		ups = rspamd_upstreams_create(ctx);

		rspamd_upstreams_set_rotation(ups, RSPAMD_UPSTREAM_HASHED);

		for (unsigned int i = 0; i < n; i++) {
			char addr[32];
			snprintf(addr, sizeof(addr), "127.0.0.%u:11333", i + 1);
			auto ok = rspamd_upstreams_add_upstream(ups, addr, 11333,
													RSPAMD_UPSTREAM_PARSE_DEFAULT, nullptr);
			REQUIRE(ok);
		}
	}

	~ring_hash_test_ctx()
	{
		rspamd_upstreams_destroy(ups);
		rspamd_upstreams_library_unref(ctx);
	}

	/* non-copyable */
	ring_hash_test_ctx(const ring_hash_test_ctx &) = delete;
	ring_hash_test_ctx &operator=(const ring_hash_test_ctx &) = delete;
};

TEST_SUITE("upstream_ring_hash")
{
	TEST_CASE("consistency: same key always returns the same upstream")
	{
		ring_hash_test_ctx t(5);

		const std::string key = "test-key-consistency";
		auto *first = rspamd_upstream_get(t.ups, RSPAMD_UPSTREAM_HASHED,
										  reinterpret_cast<const unsigned char *>(key.data()), key.size());
		REQUIRE(first != nullptr);
		auto first_name = std::string(rspamd_upstream_name(first));

		/* Same key must return the same upstream every time */
		for (int i = 0; i < 100; i++) {
			auto *up = rspamd_upstream_get(t.ups, RSPAMD_UPSTREAM_HASHED,
										   reinterpret_cast<const unsigned char *>(key.data()), key.size());
			REQUIRE(up != nullptr);
			CHECK(std::string(rspamd_upstream_name(up)) == first_name);
		}
	}

	TEST_CASE("distribution: many keys spread across all upstreams")
	{
		ring_hash_test_ctx t(5);

		std::map<std::string, int> counts;

		for (int i = 0; i < 10000; i++) {
			auto key = "distribution-key-" + std::to_string(i);
			auto *up = rspamd_upstream_get(t.ups, RSPAMD_UPSTREAM_HASHED,
										   reinterpret_cast<const unsigned char *>(key.data()), key.size());
			REQUIRE(up != nullptr);
			counts[rspamd_upstream_name(up)]++;
		}

		/* All 5 upstreams must receive traffic */
		CHECK(counts.size() == 5);

		/* Each upstream should get a reasonable share (20% +/- tolerance).
		 * With 10000 keys across 5 upstreams, expect ~2000 each.
		 * Allow wide range (500-4500) since hash distribution is not perfectly uniform. */
		for (const auto &[name, count]: counts) {
			CHECK(count >= 500);
			CHECK(count <= 4500);
		}
	}

	TEST_CASE("weighted distribution: weight=3 gets ~3x more keys than weight=1")
	{
		ring_hash_test_ctx t(3);

		/* Set weights: upstream 0 = weight 3, upstreams 1,2 = weight 1 */
		std::vector<struct upstream *> upstream_ptrs;
		struct {
			std::vector<struct upstream *> *vec;
		} cb_data{&upstream_ptrs};

		rspamd_upstreams_foreach(t.ups, [](struct upstream *up, unsigned int idx, void *ud) {
									auto *data = static_cast<decltype(cb_data) *>(ud);
									data->vec->push_back(up); }, &cb_data);

		REQUIRE(upstream_ptrs.size() == 3);

		/* Give the first upstream weight 3, others keep default weight 1 */
		rspamd_upstream_set_weight(upstream_ptrs[0], 3);

		auto heavy_name = std::string(rspamd_upstream_name(upstream_ptrs[0]));

		std::map<std::string, int> counts;

		for (int i = 0; i < 15000; i++) {
			auto key = "weight-test-key-" + std::to_string(i);
			auto *up = rspamd_upstream_get(t.ups, RSPAMD_UPSTREAM_HASHED,
										   reinterpret_cast<const unsigned char *>(key.data()), key.size());
			REQUIRE(up != nullptr);
			counts[rspamd_upstream_name(up)]++;
		}

		/* Weight 3 upstream should get roughly 3/5 = 60% of keys.
		 * Allow range 40%-80% (6000-12000 out of 15000) */
		CHECK(counts[heavy_name] >= 6000);
		CHECK(counts[heavy_name] <= 12000);

		/* Each light upstream should get some traffic */
		for (const auto &[name, count]: counts) {
			CHECK(count > 0);
		}
	}

	TEST_CASE("except parameter: returns a different upstream")
	{
		ring_hash_test_ctx t(3);

		const std::string key = "except-test-key";

		auto *first = rspamd_upstream_get(t.ups, RSPAMD_UPSTREAM_HASHED,
										  reinterpret_cast<const unsigned char *>(key.data()), key.size());
		REQUIRE(first != nullptr);
		auto first_name = std::string(rspamd_upstream_name(first));

		/* Get the same key but excluding the first result */
		auto *second = rspamd_upstream_get_except(t.ups, first, RSPAMD_UPSTREAM_HASHED,
												  reinterpret_cast<const unsigned char *>(key.data()), key.size());
		REQUIRE(second != nullptr);
		CHECK(std::string(rspamd_upstream_name(second)) != first_name);
	}

	TEST_CASE("stability: consistent hashing minimizes key movement when upstream set changes")
	{
		/* Test the consistent hashing property: when the set of upstreams
		 * changes, only keys that mapped to the removed upstream should move.
		 * We compare a 4-upstream list with a 3-upstream list (same first 3). */

		auto *ctx = rspamd_upstreams_library_init();

		/* List A: 4 upstreams */
		auto *ups_a = rspamd_upstreams_create(ctx);
		rspamd_upstreams_set_rotation(ups_a, RSPAMD_UPSTREAM_HASHED);

		for (unsigned int i = 0; i < 4; i++) {
			char addr[32];
			snprintf(addr, sizeof(addr), "127.0.0.%u:11333", i + 1);
			REQUIRE(rspamd_upstreams_add_upstream(ups_a, addr, 11333,
												  RSPAMD_UPSTREAM_PARSE_DEFAULT, nullptr));
		}

		/* List B: first 3 upstreams only (simulating removal of the 4th) */
		auto *ups_b = rspamd_upstreams_create(ctx);
		rspamd_upstreams_set_rotation(ups_b, RSPAMD_UPSTREAM_HASHED);

		for (unsigned int i = 0; i < 3; i++) {
			char addr[32];
			snprintf(addr, sizeof(addr), "127.0.0.%u:11333", i + 1);
			REQUIRE(rspamd_upstreams_add_upstream(ups_b, addr, 11333,
												  RSPAMD_UPSTREAM_PARSE_DEFAULT, nullptr));
		}

		/* The removed upstream is 127.0.0.4:11333 */
		const std::string removed_name = "127.0.0.4:11333";

		int stable_count = 0;
		int total_surviving = 0;
		int moved_from_removed = 0;
		const int num_keys = 5000;

		for (int i = 0; i < num_keys; i++) {
			auto key = "stability-key-" + std::to_string(i);
			auto *up_a = rspamd_upstream_get(ups_a, RSPAMD_UPSTREAM_HASHED,
											 reinterpret_cast<const unsigned char *>(key.data()), key.size());
			auto *up_b = rspamd_upstream_get(ups_b, RSPAMD_UPSTREAM_HASHED,
											 reinterpret_cast<const unsigned char *>(key.data()), key.size());
			REQUIRE(up_a != nullptr);
			REQUIRE(up_b != nullptr);

			auto name_a = std::string(rspamd_upstream_name(up_a));
			auto name_b = std::string(rspamd_upstream_name(up_b));

			if (name_a == removed_name) {
				/* This key was on the removed upstream; it must go somewhere in B */
				moved_from_removed++;
			}
			else {
				/* Key was on a surviving upstream; it should stay put */
				total_surviving++;
				if (name_a == name_b) {
					stable_count++;
				}
			}
		}

		/* Consistent hashing guarantee: keys on surviving upstreams stay put */
		if (total_surviving > 0) {
			double stability_ratio = static_cast<double>(stable_count) / total_surviving;
			CHECK(stability_ratio > 0.95);
		}

		/* The removed upstream should have had some keys */
		CHECK(moved_from_removed > 0);

		rspamd_upstreams_destroy(ups_a);
		rspamd_upstreams_destroy(ups_b);
		rspamd_upstreams_library_unref(ctx);
	}

	TEST_CASE("empty list: returns NULL")
	{
		auto *ctx = rspamd_upstreams_library_init();
		auto *ups = rspamd_upstreams_create(ctx);
		rspamd_upstreams_set_rotation(ups, RSPAMD_UPSTREAM_HASHED);

		const std::string key = "empty-test";
		auto *up = rspamd_upstream_get(ups, RSPAMD_UPSTREAM_HASHED,
									   reinterpret_cast<const unsigned char *>(key.data()), key.size());
		CHECK(up == nullptr);

		rspamd_upstreams_destroy(ups);
		rspamd_upstreams_library_unref(ctx);
	}

	TEST_CASE("single upstream: always returns it regardless of key")
	{
		ring_hash_test_ctx t(1);

		auto *expected = rspamd_upstream_get(t.ups, RSPAMD_UPSTREAM_HASHED,
											 reinterpret_cast<const unsigned char *>("first"), 5);
		REQUIRE(expected != nullptr);
		auto expected_name = std::string(rspamd_upstream_name(expected));

		for (int i = 0; i < 100; i++) {
			auto key = "single-upstream-key-" + std::to_string(i);
			auto *up = rspamd_upstream_get(t.ups, RSPAMD_UPSTREAM_HASHED,
										   reinterpret_cast<const unsigned char *>(key.data()), key.size());
			REQUIRE(up != nullptr);
			CHECK(std::string(rspamd_upstream_name(up)) == expected_name);
		}
	}

	TEST_CASE("no key falls back to random")
	{
		ring_hash_test_ctx t(3);

		/* When no key is provided, hashed rotation should fall back gracefully */
		auto *up = rspamd_upstream_get(t.ups, RSPAMD_UPSTREAM_HASHED, nullptr, 0);
		CHECK(up != nullptr);
	}

	TEST_CASE("different keys produce different upstreams")
	{
		ring_hash_test_ctx t(10);

		/* With 10 upstreams, 50 different keys should hit at least 2 different upstreams */
		std::set<std::string> seen;

		for (int i = 0; i < 50; i++) {
			auto key = "diverse-key-" + std::to_string(i);
			auto *up = rspamd_upstream_get(t.ups, RSPAMD_UPSTREAM_HASHED,
										   reinterpret_cast<const unsigned char *>(key.data()), key.size());
			REQUIRE(up != nullptr);
			seen.insert(rspamd_upstream_name(up));
		}

		CHECK(seen.size() >= 2);
	}

	TEST_CASE("except with single upstream returns it as last resort")
	{
		ring_hash_test_ctx t(1);

		const std::string key = "except-single";
		auto *up = rspamd_upstream_get(t.ups, RSPAMD_UPSTREAM_HASHED,
									   reinterpret_cast<const unsigned char *>(key.data()), key.size());
		REQUIRE(up != nullptr);

		/* With only one upstream alive, the fast path returns it even
		 * when excluded (last-resort behaviour to avoid returning NULL) */
		auto *second = rspamd_upstream_get_except(t.ups, up, RSPAMD_UPSTREAM_HASHED,
												  reinterpret_cast<const unsigned char *>(key.data()), key.size());
		CHECK(second != nullptr);
		CHECK(second == up);
	}
}

#endif
