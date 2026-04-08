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

/* Unit tests for upstream weighted round-robin selection */

#ifndef RSPAMD_CXX_UNIT_UPSTREAM_ROUND_ROBIN_HXX
#define RSPAMD_CXX_UNIT_UPSTREAM_ROUND_ROBIN_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "libutil/upstream.h"

#include <map>
#include <string>
#include <vector>

/*
 * Helper: create an upstream_ctx + upstream_list with N numeric IP upstreams
 * configured for ROUND_ROBIN rotation.
 * Uses 127.0.0.x addresses on port 11333 to avoid DNS resolution.
 */
struct round_robin_test_ctx {
	struct upstream_ctx *ctx;
	struct upstream_list *ups;
	unsigned int n_upstreams;
	std::vector<struct upstream *> upstream_ptrs;

	round_robin_test_ctx(unsigned int n)
		: n_upstreams(n)
	{
		ctx = rspamd_upstreams_library_init();
		ups = rspamd_upstreams_create(ctx);

		rspamd_upstreams_set_rotation(ups, RSPAMD_UPSTREAM_ROUND_ROBIN);

		for (unsigned int i = 0; i < n; i++) {
			char addr[32];
			snprintf(addr, sizeof(addr), "127.0.0.%u:11333", i + 1);
			auto ok = rspamd_upstreams_add_upstream(ups, addr, 11333,
													RSPAMD_UPSTREAM_PARSE_DEFAULT, nullptr);
			REQUIRE(ok);
		}

		/* Collect upstream pointers for weight manipulation */
		struct {
			std::vector<struct upstream *> *vec;
		} cb_data{&upstream_ptrs};

		rspamd_upstreams_foreach(ups, [](struct upstream *up, unsigned int idx, void *ud) {
								auto *data = static_cast<decltype(cb_data) *>(ud);
								data->vec->push_back(up); }, &cb_data);
	}

	~round_robin_test_ctx()
	{
		rspamd_upstreams_destroy(ups);
		rspamd_upstreams_library_unref(ctx);
	}

	/* non-copyable */
	round_robin_test_ctx(const round_robin_test_ctx &) = delete;
	round_robin_test_ctx &operator=(const round_robin_test_ctx &) = delete;
};

TEST_SUITE("upstream_round_robin")
{
	TEST_CASE("equal weights: uniform distribution")
	{
		round_robin_test_ctx t(3);

		std::map<std::string, int> counts;

		for (int i = 0; i < 3000; i++) {
			auto *up = rspamd_upstream_get(t.ups, RSPAMD_UPSTREAM_ROUND_ROBIN,
										   nullptr, 0);
			REQUIRE(up != nullptr);
			counts[rspamd_upstream_name(up)]++;
		}

		/* All 3 upstreams must receive traffic */
		CHECK(counts.size() == 3);

		/* Each should get ~1000 requests. Allow +-10% tolerance */
		for (const auto &[name, count]: counts) {
			CHECK(count >= 900);
			CHECK(count <= 1100);
		}
	}

	TEST_CASE("weighted round-robin: respects weight ratio over multiple cycles")
	{
		round_robin_test_ctx t(3);
		REQUIRE(t.upstream_ptrs.size() == 3);

		/* Set weights: 100, 100, 1 (the customer scenario) */
		rspamd_upstream_set_weight(t.upstream_ptrs[0], 100);
		rspamd_upstream_set_weight(t.upstream_ptrs[1], 100);
		rspamd_upstream_set_weight(t.upstream_ptrs[2], 1);

		auto heavy0_name = std::string(rspamd_upstream_name(t.upstream_ptrs[0]));
		auto heavy1_name = std::string(rspamd_upstream_name(t.upstream_ptrs[1]));
		auto light_name = std::string(rspamd_upstream_name(t.upstream_ptrs[2]));

		std::map<std::string, int> counts;

		/* Run enough requests to span multiple weight cycles.
		 * One cycle = 100 + 100 + 1 = 201 requests.
		 * Run ~10 cycles = 2010 requests. */
		const int total_requests = 2010;

		for (int i = 0; i < total_requests; i++) {
			auto *up = rspamd_upstream_get(t.ups, RSPAMD_UPSTREAM_ROUND_ROBIN,
										   nullptr, 0);
			REQUIRE(up != nullptr);
			counts[rspamd_upstream_name(up)]++;
		}

		/* Expected ratio: 100:100:1
		 * Total weight = 201
		 * Expected: heavy ~ 2010*100/201 = 1000, light ~ 2010*1/201 = 10 */
		CHECK(counts[heavy0_name] >= 900);
		CHECK(counts[heavy0_name] <= 1100);
		CHECK(counts[heavy1_name] >= 900);
		CHECK(counts[heavy1_name] <= 1100);
		CHECK(counts[light_name] >= 5);
		CHECK(counts[light_name] <= 20);
	}

	TEST_CASE("weighted round-robin: 10:1 ratio maintained across cycles")
	{
		round_robin_test_ctx t(2);
		REQUIRE(t.upstream_ptrs.size() == 2);

		rspamd_upstream_set_weight(t.upstream_ptrs[0], 10);
		rspamd_upstream_set_weight(t.upstream_ptrs[1], 1);

		auto heavy_name = std::string(rspamd_upstream_name(t.upstream_ptrs[0]));
		auto light_name = std::string(rspamd_upstream_name(t.upstream_ptrs[1]));

		std::map<std::string, int> counts;

		/* 11 requests per cycle, run 100 cycles = 1100 requests */
		const int total_requests = 1100;

		for (int i = 0; i < total_requests; i++) {
			auto *up = rspamd_upstream_get(t.ups, RSPAMD_UPSTREAM_ROUND_ROBIN,
										   nullptr, 0);
			REQUIRE(up != nullptr);
			counts[rspamd_upstream_name(up)]++;
		}

		/* Expected: heavy=1000, light=100 */
		CHECK(counts[heavy_name] >= 950);
		CHECK(counts[heavy_name] <= 1050);
		CHECK(counts[light_name] >= 80);
		CHECK(counts[light_name] <= 120);

		/* Verify ratio: heavy/light should be ~10 */
		double ratio = static_cast<double>(counts[heavy_name]) / counts[light_name];
		CHECK(ratio >= 8.0);
		CHECK(ratio <= 12.0);
	}

	TEST_CASE("weighted round-robin: 3 different weights")
	{
		round_robin_test_ctx t(3);
		REQUIRE(t.upstream_ptrs.size() == 3);

		/* Weights: 5, 3, 2 (total=10) */
		rspamd_upstream_set_weight(t.upstream_ptrs[0], 5);
		rspamd_upstream_set_weight(t.upstream_ptrs[1], 3);
		rspamd_upstream_set_weight(t.upstream_ptrs[2], 2);

		std::map<std::string, int> counts;

		/* 10 per cycle, 100 cycles = 1000 */
		const int total_requests = 1000;

		for (int i = 0; i < total_requests; i++) {
			auto *up = rspamd_upstream_get(t.ups, RSPAMD_UPSTREAM_ROUND_ROBIN,
										   nullptr, 0);
			REQUIRE(up != nullptr);
			counts[rspamd_upstream_name(up)]++;
		}

		auto name0 = std::string(rspamd_upstream_name(t.upstream_ptrs[0]));
		auto name1 = std::string(rspamd_upstream_name(t.upstream_ptrs[1]));
		auto name2 = std::string(rspamd_upstream_name(t.upstream_ptrs[2]));

		/* Expected: 500, 300, 200 */
		CHECK(counts[name0] >= 450);
		CHECK(counts[name0] <= 550);
		CHECK(counts[name1] >= 260);
		CHECK(counts[name1] <= 340);
		CHECK(counts[name2] >= 170);
		CHECK(counts[name2] <= 230);
	}

	TEST_CASE("weighted round-robin: single cycle is exact")
	{
		round_robin_test_ctx t(3);
		REQUIRE(t.upstream_ptrs.size() == 3);

		/* Weights: 3, 2, 1 (total=6) */
		rspamd_upstream_set_weight(t.upstream_ptrs[0], 3);
		rspamd_upstream_set_weight(t.upstream_ptrs[1], 2);
		rspamd_upstream_set_weight(t.upstream_ptrs[2], 1);

		std::map<std::string, int> counts;

		/* Exactly one cycle = 6 requests */
		for (int i = 0; i < 6; i++) {
			auto *up = rspamd_upstream_get(t.ups, RSPAMD_UPSTREAM_ROUND_ROBIN,
										   nullptr, 0);
			REQUIRE(up != nullptr);
			counts[rspamd_upstream_name(up)]++;
		}

		auto name0 = std::string(rspamd_upstream_name(t.upstream_ptrs[0]));
		auto name1 = std::string(rspamd_upstream_name(t.upstream_ptrs[1]));
		auto name2 = std::string(rspamd_upstream_name(t.upstream_ptrs[2]));

		CHECK(counts[name0] == 3);
		CHECK(counts[name1] == 2);
		CHECK(counts[name2] == 1);
	}

	TEST_CASE("weighted round-robin: two full cycles are exact")
	{
		round_robin_test_ctx t(3);
		REQUIRE(t.upstream_ptrs.size() == 3);

		/* Weights: 3, 2, 1 (total=6) */
		rspamd_upstream_set_weight(t.upstream_ptrs[0], 3);
		rspamd_upstream_set_weight(t.upstream_ptrs[1], 2);
		rspamd_upstream_set_weight(t.upstream_ptrs[2], 1);

		std::map<std::string, int> counts;

		/* Exactly two cycles = 12 requests */
		for (int i = 0; i < 12; i++) {
			auto *up = rspamd_upstream_get(t.ups, RSPAMD_UPSTREAM_ROUND_ROBIN,
										   nullptr, 0);
			REQUIRE(up != nullptr);
			counts[rspamd_upstream_name(up)]++;
		}

		auto name0 = std::string(rspamd_upstream_name(t.upstream_ptrs[0]));
		auto name1 = std::string(rspamd_upstream_name(t.upstream_ptrs[1]));
		auto name2 = std::string(rspamd_upstream_name(t.upstream_ptrs[2]));

		CHECK(counts[name0] == 6);
		CHECK(counts[name1] == 4);
		CHECK(counts[name2] == 2);
	}

	TEST_CASE("zero weights: equal distribution via min_checked")
	{
		round_robin_test_ctx t(3);

		/* Default weight is 0 when not set via addr:port:weight syntax.
		 * All upstreams have weight 0 => should use min_checked logic. */
		std::map<std::string, int> counts;

		for (int i = 0; i < 3000; i++) {
			auto *up = rspamd_upstream_get(t.ups, RSPAMD_UPSTREAM_ROUND_ROBIN,
										   nullptr, 0);
			REQUIRE(up != nullptr);
			counts[rspamd_upstream_name(up)]++;
		}

		CHECK(counts.size() == 3);

		/* With zero weights, distribution should be roughly equal */
		for (const auto &[name, count]: counts) {
			CHECK(count >= 800);
			CHECK(count <= 1200);
		}
	}

	TEST_CASE("except parameter: skips excluded upstream")
	{
		round_robin_test_ctx t(3);
		REQUIRE(t.upstream_ptrs.size() == 3);

		rspamd_upstream_set_weight(t.upstream_ptrs[0], 5);
		rspamd_upstream_set_weight(t.upstream_ptrs[1], 3);
		rspamd_upstream_set_weight(t.upstream_ptrs[2], 2);

		auto excluded_name = std::string(rspamd_upstream_name(t.upstream_ptrs[0]));

		/* Get upstream excluding the first one */
		for (int i = 0; i < 100; i++) {
			auto *up = rspamd_upstream_get_except(t.ups, t.upstream_ptrs[0],
												  RSPAMD_UPSTREAM_ROUND_ROBIN,
												  nullptr, 0);
			REQUIRE(up != nullptr);
			CHECK(std::string(rspamd_upstream_name(up)) != excluded_name);
		}
	}

	TEST_CASE("single upstream: always returns it")
	{
		round_robin_test_ctx t(1);

		auto *expected = rspamd_upstream_get(t.ups, RSPAMD_UPSTREAM_ROUND_ROBIN,
											 nullptr, 0);
		REQUIRE(expected != nullptr);
		auto expected_name = std::string(rspamd_upstream_name(expected));

		for (int i = 0; i < 100; i++) {
			auto *up = rspamd_upstream_get(t.ups, RSPAMD_UPSTREAM_ROUND_ROBIN,
										   nullptr, 0);
			REQUIRE(up != nullptr);
			CHECK(std::string(rspamd_upstream_name(up)) == expected_name);
		}
	}

	TEST_CASE("empty list: returns NULL")
	{
		auto *ctx = rspamd_upstreams_library_init();
		auto *ups = rspamd_upstreams_create(ctx);
		rspamd_upstreams_set_rotation(ups, RSPAMD_UPSTREAM_ROUND_ROBIN);

		auto *up = rspamd_upstream_get(ups, RSPAMD_UPSTREAM_ROUND_ROBIN,
									   nullptr, 0);
		CHECK(up == nullptr);

		rspamd_upstreams_destroy(ups);
		rspamd_upstreams_library_unref(ctx);
	}

	TEST_CASE("weight parsed from address string")
	{
		/* Test that host:port:weight parsing sets the weight correctly */
		auto *ctx = rspamd_upstreams_library_init();
		auto *ups = rspamd_upstreams_create(ctx);
		rspamd_upstreams_set_rotation(ups, RSPAMD_UPSTREAM_ROUND_ROBIN);

		/* Add with explicit weights via the address string */
		REQUIRE(rspamd_upstreams_add_upstream(ups, "127.0.0.1:11333:10", 11333,
											  RSPAMD_UPSTREAM_PARSE_DEFAULT, nullptr));
		REQUIRE(rspamd_upstreams_add_upstream(ups, "127.0.0.2:11333:1", 11333,
											  RSPAMD_UPSTREAM_PARSE_DEFAULT, nullptr));

		std::map<std::string, int> counts;

		/* 11 per cycle, 100 cycles = 1100 */
		for (int i = 0; i < 1100; i++) {
			auto *up = rspamd_upstream_get(ups, RSPAMD_UPSTREAM_ROUND_ROBIN,
										   nullptr, 0);
			REQUIRE(up != nullptr);
			counts[rspamd_upstream_name(up)]++;
		}

		/* Should be 10:1 ratio */
		CHECK(counts["127.0.0.1:11333"] >= 950);
		CHECK(counts["127.0.0.1:11333"] <= 1050);
		CHECK(counts["127.0.0.2:11333"] >= 80);
		CHECK(counts["127.0.0.2:11333"] <= 120);

		rspamd_upstreams_destroy(ups);
		rspamd_upstreams_library_unref(ctx);
	}

	TEST_CASE("high weight disparity maintained over many cycles")
	{
		round_robin_test_ctx t(3);
		REQUIRE(t.upstream_ptrs.size() == 3);

		/* Simulate the customer scenario: 100:100:1 */
		rspamd_upstream_set_weight(t.upstream_ptrs[0], 100);
		rspamd_upstream_set_weight(t.upstream_ptrs[1], 100);
		rspamd_upstream_set_weight(t.upstream_ptrs[2], 1);

		auto heavy0_name = std::string(rspamd_upstream_name(t.upstream_ptrs[0]));
		auto heavy1_name = std::string(rspamd_upstream_name(t.upstream_ptrs[1]));
		auto light_name = std::string(rspamd_upstream_name(t.upstream_ptrs[2]));

		/* Run 5025 requests = 25 full cycles of 201 */
		const int total_requests = 5025;
		std::map<std::string, int> counts;

		for (int i = 0; i < total_requests; i++) {
			auto *up = rspamd_upstream_get(t.ups, RSPAMD_UPSTREAM_ROUND_ROBIN,
										   nullptr, 0);
			REQUIRE(up != nullptr);
			counts[rspamd_upstream_name(up)]++;
		}

		/* Expected: heavy0=2500, heavy1=2500, light=25 */
		CHECK(counts[heavy0_name] >= 2300);
		CHECK(counts[heavy0_name] <= 2700);
		CHECK(counts[heavy1_name] >= 2300);
		CHECK(counts[heavy1_name] <= 2700);
		CHECK(counts[light_name] >= 15);
		CHECK(counts[light_name] <= 40);

		/* The light upstream must be dramatically less than either heavy one */
		CHECK(counts[light_name] < counts[heavy0_name] / 10);
		CHECK(counts[light_name] < counts[heavy1_name] / 10);
	}
}

#endif
