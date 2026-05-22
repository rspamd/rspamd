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

/* Unit tests for upstream Power-of-Two-Choices (P2C) selection */

#ifndef RSPAMD_CXX_UNIT_UPSTREAM_P2C_HXX
#define RSPAMD_CXX_UNIT_UPSTREAM_P2C_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "libutil/upstream.h"

#include <map>
#include <string>

struct p2c_test_ctx {
	struct upstream_ctx *ctx;
	struct upstream_list *ups;

	explicit p2c_test_ctx(unsigned int n)
	{
		ctx = rspamd_upstreams_library_init();
		ups = rspamd_upstreams_create(ctx);
		rspamd_upstreams_set_rotation(ups, RSPAMD_UPSTREAM_P2C);

		for (unsigned int i = 0; i < n; i++) {
			char addr[32];
			snprintf(addr, sizeof(addr), "127.0.0.%u:11333", i + 1);
			auto ok = rspamd_upstreams_add_upstream(ups, addr, 11333,
													RSPAMD_UPSTREAM_PARSE_DEFAULT, nullptr);
			REQUIRE(ok);
		}
	}

	~p2c_test_ctx()
	{
		rspamd_upstreams_destroy(ups);
		rspamd_upstreams_library_unref(ctx);
	}

	p2c_test_ctx(const p2c_test_ctx &) = delete;
	p2c_test_ctx &operator=(const p2c_test_ctx &) = delete;
};

TEST_SUITE("upstream_p2c")
{
	TEST_CASE("single upstream is selectable")
	{
		p2c_test_ctx t(1);
		auto *up = rspamd_upstream_get(t.ups, RSPAMD_UPSTREAM_P2C, nullptr, 0);
		REQUIRE(up != nullptr);
		rspamd_upstream_ok(up);
	}

	TEST_CASE("single upstream returned even when excluded (last resort)")
	{
		/*
		 * Documented behaviour shared with the other rotations: when only
		 * one upstream is alive, the _get_common fast path returns it even
		 * when it matches `except`, to avoid leaving the caller with no
		 * candidate at all.
		 */
		p2c_test_ctx t(1);
		auto *up = rspamd_upstream_get(t.ups, RSPAMD_UPSTREAM_P2C, nullptr, 0);
		REQUIRE(up != nullptr);
		rspamd_upstream_ok(up);

		auto *other = rspamd_upstream_get_except(t.ups, up, RSPAMD_UPSTREAM_P2C, nullptr, 0);
		CHECK(other == up);
		rspamd_upstream_ok(other);
	}

	TEST_CASE("two upstreams: except forces the other")
	{
		p2c_test_ctx t(2);
		auto *first = rspamd_upstream_get(t.ups, RSPAMD_UPSTREAM_P2C, nullptr, 0);
		REQUIRE(first != nullptr);
		auto first_name = std::string(rspamd_upstream_name(first));
		rspamd_upstream_ok(first);

		auto *second = rspamd_upstream_get_except(t.ups, first, RSPAMD_UPSTREAM_P2C, nullptr, 0);
		REQUIRE(second != nullptr);
		CHECK(std::string(rspamd_upstream_name(second)) != first_name);
		rspamd_upstream_ok(second);
	}

	TEST_CASE("RANDOM rotation silently uses P2C path")
	{
		/* Nothing observable changes for a healthy fleet, but the request
		 * must succeed identically to an explicit P2C rotation. */
		p2c_test_ctx t(3);
		rspamd_upstreams_set_rotation(t.ups, RSPAMD_UPSTREAM_RANDOM);

		for (int i = 0; i < 100; i++) {
			auto *up = rspamd_upstream_get(t.ups, RSPAMD_UPSTREAM_RANDOM, nullptr, 0);
			REQUIRE(up != nullptr);
			rspamd_upstream_ok(up);
		}
	}

	TEST_CASE("loaded upstream is picked less often than idle one")
	{
		/*
		 * Strategy: build a 4-upstream fleet, then deliberately leak inflight
		 * on one upstream by calling get without ok/fail. With pure random
		 * we'd expect ~25% selections of the loaded one; with P2C the load
		 * comparator should make it strictly under 25% over a large run.
		 */
		p2c_test_ctx t(4);

		/* Pick one upstream and leak inflight on it 10 times. */
		struct upstream *loaded = nullptr;
		{
			auto *first = rspamd_upstream_get(t.ups, RSPAMD_UPSTREAM_P2C, nullptr, 0);
			REQUIRE(first != nullptr);
			loaded = first;
			/* Don't ok/fail: keeps inflight high. */
			for (int i = 0; i < 9; i++) {
				/* Force selection of the same one by always calling get_except
				 * on the others; not exact, but get_p2c samples from all 4 so
				 * we can't pin selection. Instead, leak by directly counting.
				 *
				 * The intrusive way: just call get() 10 more times and ok()
				 * everything except 'loaded'. */
				auto *up = rspamd_upstream_get(t.ups, RSPAMD_UPSTREAM_P2C, nullptr, 0);
				REQUIRE(up != nullptr);
				if (up == loaded) {
					/* Skip ok/fail to leave inflight high on the loaded one. */
					continue;
				}
				rspamd_upstream_ok(up);
			}
		}

		auto loaded_name = std::string(rspamd_upstream_name(loaded));

		/* Now run 1000 selections, ok-ing each immediately, and count hits
		 * to the loaded upstream. */
		std::map<std::string, int> hits;
		for (int i = 0; i < 1000; i++) {
			auto *up = rspamd_upstream_get(t.ups, RSPAMD_UPSTREAM_P2C, nullptr, 0);
			REQUIRE(up != nullptr);
			hits[rspamd_upstream_name(up)]++;
			rspamd_upstream_ok(up);
		}

		int loaded_hits = hits[loaded_name];

		/*
		 * P2C with N=4 and one heavily loaded upstream: probability that an
		 * upstream is picked is the probability that both samples include
		 * it AND its score is the lowest. Theoretical analysis is messy
		 * because the loaded one starts with high inflight that gets
		 * decremented by ok() across the run; we just assert it's noticeably
		 * lower than uniform random would give (~250).
		 */
		CHECK(loaded_hits < 250);
	}

	TEST_CASE("inflight tracking via ok/fail balances out")
	{
		/* After get/ok pairs, inflight should round-trip to zero so the
		 * comparator behaves the same as a fresh fleet. We verify by
		 * exhausting many rounds and checking the distribution stays
		 * roughly uniform. */
		p2c_test_ctx t(3);
		std::map<std::string, int> hits;

		for (int i = 0; i < 3000; i++) {
			auto *up = rspamd_upstream_get(t.ups, RSPAMD_UPSTREAM_P2C, nullptr, 0);
			REQUIRE(up != nullptr);
			hits[rspamd_upstream_name(up)]++;
			rspamd_upstream_ok(up);
		}

		CHECK(hits.size() == 3);
		for (const auto &[name, count]: hits) {
			/* Each upstream gets ~1000 selections; ±25% tolerance. */
			CHECK(count >= 750);
			CHECK(count <= 1250);
		}
	}

	TEST_CASE("release retires inflight without affecting selection bias")
	{
		/*
		 * release() must decrement inflight just like ok()/fail() do, so
		 * abandoned selections (e.g. message-copy failures, fire-and-forget
		 * lookups) don't permanently skew the P2C comparator. We verify by
		 * leaking via release on one upstream and checking that selection
		 * stays balanced — unlike the "loaded upstream" test where leaking
		 * with no retirement skews selection away from it.
		 */
		p2c_test_ctx t(3);
		std::map<std::string, int> hits;

		/* Burn many get/release pairs on whatever P2C picks first. If
		 * release didn't retire inflight, that upstream would build up
		 * a load score and stop being picked. */
		for (int i = 0; i < 100; i++) {
			auto *up = rspamd_upstream_get(t.ups, RSPAMD_UPSTREAM_P2C, nullptr, 0);
			REQUIRE(up != nullptr);
			rspamd_upstream_release(up);
		}

		for (int i = 0; i < 1500; i++) {
			auto *up = rspamd_upstream_get(t.ups, RSPAMD_UPSTREAM_P2C, nullptr, 0);
			REQUIRE(up != nullptr);
			hits[rspamd_upstream_name(up)]++;
			rspamd_upstream_ok(up);
		}

		CHECK(hits.size() == 3);
		for (const auto &[name, count]: hits) {
			/* Each ~500; ±40% tolerance to absorb P2C noise. */
			CHECK(count >= 300);
		}
	}

	TEST_CASE("release on null is a no-op")
	{
		rspamd_upstream_release(nullptr);
	}

	TEST_CASE("get/fail rounds keep inflight bounded")
	{
		/*
		 * Without the inflight-decrement on fail, repeated get/fail rounds
		 * would let `inflight` grow unboundedly on whichever upstream the
		 * P2C comparator keeps choosing first, eventually starving the
		 * other one entirely. With the fix, inflight stays bounded and
		 * selection drift stays moderate.
		 *
		 * Run many iterations alternating get/fail; the loser side of P2C
		 * (the other upstream) must still be selected occasionally.
		 */
		p2c_test_ctx t(2);
		std::map<std::string, int> hits;

		for (int i = 0; i < 1000; i++) {
			auto *u = rspamd_upstream_get(t.ups, RSPAMD_UPSTREAM_P2C, nullptr, 0);
			REQUIRE(u != nullptr);
			hits[rspamd_upstream_name(u)]++;
			/* Mix of fail and ok keeps both error counts bounded. */
			if (i % 2 == 0) {
				rspamd_upstream_fail(u, FALSE, "test");
			}
			else {
				rspamd_upstream_ok(u);
			}
		}

		CHECK(hits.size() == 2);
		for (const auto &[name, count]: hits) {
			/* Both upstreams must be reachable. With the fix, inflight stays
			 * bounded and selection isn't permanently skewed. */
			CHECK(count > 0);
		}
	}
}

#endif
