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

/* Unit tests for upstream latency EWMA tracking and P2C integration */

#ifndef RSPAMD_CXX_UNIT_UPSTREAM_LATENCY_HXX
#define RSPAMD_CXX_UNIT_UPSTREAM_LATENCY_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "libutil/upstream.h"

#include <cmath>
#include <map>
#include <string>

TEST_SUITE("upstream_latency")
{
	TEST_CASE("first sample sets the EWMA exactly")
	{
		auto *ctx = rspamd_upstreams_library_init();
		auto *ups = rspamd_upstreams_create(ctx);

		REQUIRE(rspamd_upstreams_add_upstream(ups, "127.0.0.1:11333", 11333,
											  RSPAMD_UPSTREAM_PARSE_DEFAULT, nullptr));

		auto *up = rspamd_upstream_get(ups, RSPAMD_UPSTREAM_P2C, nullptr, 0);
		REQUIRE(up != nullptr);

		CHECK(rspamd_upstream_get_latency(up) == 0.0);
		rspamd_upstream_record_latency(up, 0.123);
		CHECK(rspamd_upstream_get_latency(up) == doctest::Approx(0.123));

		rspamd_upstream_ok(up);
		rspamd_upstreams_destroy(ups);
		rspamd_upstreams_library_unref(ctx);
	}

	TEST_CASE("repeated samples converge toward steady value")
	{
		auto *ctx = rspamd_upstreams_library_init();
		auto *ups = rspamd_upstreams_create(ctx);
		REQUIRE(rspamd_upstreams_add_upstream(ups, "127.0.0.1:11333", 11333,
											  RSPAMD_UPSTREAM_PARSE_DEFAULT, nullptr));

		auto *up = rspamd_upstream_get(ups, RSPAMD_UPSTREAM_P2C, nullptr, 0);
		REQUIRE(up != nullptr);

		/* Feed 200 identical 0.05s samples; EWMA must converge to 0.05. */
		for (int i = 0; i < 200; i++) {
			rspamd_upstream_record_latency(up, 0.05);
		}
		CHECK(rspamd_upstream_get_latency(up) == doctest::Approx(0.05).epsilon(0.01));

		rspamd_upstream_ok(up);
		rspamd_upstreams_destroy(ups);
		rspamd_upstreams_library_unref(ctx);
	}

	TEST_CASE("step change is reflected after enough samples")
	{
		auto *ctx = rspamd_upstreams_library_init();
		auto *ups = rspamd_upstreams_create(ctx);
		REQUIRE(rspamd_upstreams_add_upstream(ups, "127.0.0.1:11333", 11333,
											  RSPAMD_UPSTREAM_PARSE_DEFAULT, nullptr));

		auto *up = rspamd_upstream_get(ups, RSPAMD_UPSTREAM_P2C, nullptr, 0);
		REQUIRE(up != nullptr);

		/* Steady at 1.0s, then a step to 0.1s. After many samples at 0.1
		 * the EWMA should be much closer to 0.1 than to 1.0. */
		for (int i = 0; i < 50; i++) {
			rspamd_upstream_record_latency(up, 1.0);
		}
		double slow = rspamd_upstream_get_latency(up);
		CHECK(slow > 0.5);

		for (int i = 0; i < 500; i++) {
			rspamd_upstream_record_latency(up, 0.1);
		}
		double fast = rspamd_upstream_get_latency(up);
		CHECK(fast < slow);
		CHECK(fast < 0.5);

		rspamd_upstream_ok(up);
		rspamd_upstreams_destroy(ups);
		rspamd_upstreams_library_unref(ctx);
	}

	TEST_CASE("negative samples are ignored")
	{
		auto *ctx = rspamd_upstreams_library_init();
		auto *ups = rspamd_upstreams_create(ctx);
		REQUIRE(rspamd_upstreams_add_upstream(ups, "127.0.0.1:11333", 11333,
											  RSPAMD_UPSTREAM_PARSE_DEFAULT, nullptr));

		auto *up = rspamd_upstream_get(ups, RSPAMD_UPSTREAM_P2C, nullptr, 0);
		REQUIRE(up != nullptr);

		rspamd_upstream_record_latency(up, 0.05);
		double before = rspamd_upstream_get_latency(up);
		rspamd_upstream_record_latency(up, -1.0);
		double after = rspamd_upstream_get_latency(up);
		CHECK(after == doctest::Approx(before));

		rspamd_upstream_ok(up);
		rspamd_upstreams_destroy(ups);
		rspamd_upstreams_library_unref(ctx);
	}

	TEST_CASE("set_latency_half_life accepts and clamps")
	{
		auto *ctx = rspamd_upstreams_library_init();
		auto *ups = rspamd_upstreams_create(ctx);
		REQUIRE(rspamd_upstreams_add_upstream(ups, "127.0.0.1:11333", 11333,
											  RSPAMD_UPSTREAM_PARSE_DEFAULT, nullptr));

		rspamd_upstreams_set_latency_half_life(ups, 30.0);
		rspamd_upstreams_set_latency_half_life(ups, 0);
		rspamd_upstreams_set_latency_half_life(ups, -5);

		auto *up = rspamd_upstream_get(ups, RSPAMD_UPSTREAM_P2C, nullptr, 0);
		REQUIRE(up != nullptr);
		rspamd_upstream_record_latency(up, 0.2);
		CHECK(rspamd_upstream_get_latency(up) == doctest::Approx(0.2));
		rspamd_upstream_ok(up);

		rspamd_upstreams_destroy(ups);
		rspamd_upstreams_library_unref(ctx);
	}

	TEST_CASE("P2C prefers the lower-latency upstream when load matches")
	{
		auto *ctx = rspamd_upstreams_library_init();
		auto *ups = rspamd_upstreams_create(ctx);
		rspamd_upstreams_set_rotation(ups, RSPAMD_UPSTREAM_P2C);

		REQUIRE(rspamd_upstreams_add_upstream(ups, "127.0.0.1:11333", 11333,
											  RSPAMD_UPSTREAM_PARSE_DEFAULT, nullptr));
		REQUIRE(rspamd_upstreams_add_upstream(ups, "127.0.0.2:11333", 11333,
											  RSPAMD_UPSTREAM_PARSE_DEFAULT, nullptr));

		/* Collect the two distinct upstream pointers via repeated selection. */
		std::map<std::string, struct upstream *> seen;
		for (int tries = 0; tries < 200 && seen.size() < 2; tries++) {
			auto *u = rspamd_upstream_get(ups, RSPAMD_UPSTREAM_P2C, nullptr, 0);
			REQUIRE(u != nullptr);
			seen[rspamd_upstream_name(u)] = u;
			rspamd_upstream_ok(u);
		}
		REQUIRE(seen.size() == 2);

		auto it = seen.begin();
		struct upstream *fast = it->second;
		std::string fast_name = it->first;
		++it;
		struct upstream *slow = it->second;
		std::string slow_name = it->first;

		/* Plant clear EWMAs: fast = 10ms, slow = 500ms. */
		for (int i = 0; i < 30; i++) {
			rspamd_upstream_record_latency(fast, 0.01);
			rspamd_upstream_record_latency(slow, 0.5);
		}
		CHECK(rspamd_upstream_get_latency(fast) < rspamd_upstream_get_latency(slow));

		std::map<std::string, int> hits;
		for (int i = 0; i < 1000; i++) {
			auto *u = rspamd_upstream_get(ups, RSPAMD_UPSTREAM_P2C, nullptr, 0);
			REQUIRE(u != nullptr);
			hits[rspamd_upstream_name(u)]++;
			rspamd_upstream_ok(u);
		}

		/* Latency-aware P2C should heavily favour the fast upstream. */
		CHECK(hits[fast_name] > hits[slow_name] * 2);

		rspamd_upstreams_destroy(ups);
		rspamd_upstreams_library_unref(ctx);
	}

	TEST_CASE("null/zero arguments handled safely")
	{
		rspamd_upstream_record_latency(nullptr, 0.1);
		CHECK(rspamd_upstream_get_latency(nullptr) == 0.0);
	}
}

#endif
