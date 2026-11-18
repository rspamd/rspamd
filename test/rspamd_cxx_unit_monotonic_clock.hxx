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

/* rspamd_get_monotonic_ns: real clock, override and fake_clock integration */

#ifndef RSPAMD_CXX_UNIT_MONOTONIC_CLOCK_HXX
#define RSPAMD_CXX_UNIT_MONOTONIC_CLOCK_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "config.h"
#include <algorithm>
#include <cstdint>
#include "libutil/util.h"
#include "rspamd_test_fake_time.hxx"

namespace {
uint64_t mono_test_fixed_clock(void)
{
	return 123456789ULL;
}
}// namespace

TEST_SUITE("monotonic_clock")
{
	TEST_CASE("real clock is non-decreasing and advances")
	{
		auto first = rspamd_get_monotonic_ns();
		auto prev = first;

		for (auto i = 0; i < 100000; i++) {
			auto cur = rspamd_get_monotonic_ns();
			CHECK(cur >= prev);
			prev = cur;
		}

		/* Spin until the clock visibly moves; bounded by a generous count */
		auto moved = false;
		for (auto i = 0; i < 100000000 && !moved; i++) {
			moved = rspamd_get_monotonic_ns() > first;
		}
		CHECK(moved);
	}

	TEST_CASE("real clock has a sub-coarse-tick resolution")
	{
		/* A coarse clock ticks every 1-4 ms; the precise one steps far finer */
		uint64_t smallest = UINT64_MAX;
		auto prev = rspamd_get_monotonic_ns();

		for (auto i = 0; i < 1000000; i++) {
			auto cur = rspamd_get_monotonic_ns();
			if (cur > prev) {
				smallest = std::min<uint64_t>(smallest, cur - prev);
			}
			prev = cur;
		}

		CHECK(smallest != UINT64_MAX);
		CHECK(smallest < 500000ULL);
	}

	TEST_CASE("override and restore round trip")
	{
		CHECK(rspamd_set_monotonic_clock(&mono_test_fixed_clock) == nullptr);
		CHECK(rspamd_get_monotonic_ns() == 123456789ULL);
		CHECK(rspamd_set_monotonic_clock(nullptr) == &mono_test_fixed_clock);

		auto a = rspamd_get_monotonic_ns();
		CHECK(a != 123456789ULL);
		CHECK(rspamd_get_monotonic_ns() >= a);
	}

	TEST_CASE("fake_clock drives the monotonic clock")
	{
		{
			rspamd_test::fake_clock clk(1000.0);
			CHECK(rspamd_get_monotonic_ns() == 1000000000000ULL);
			clk.advance(0.0025);
			CHECK(rspamd_get_monotonic_ns() == 1000002500000ULL);
			clk.set(2000.0);
			CHECK(rspamd_get_monotonic_ns() == 2000000000000ULL);
		}

		/* Restored to the real clock */
		CHECK(rspamd_set_monotonic_clock(nullptr) == nullptr);
		CHECK(rspamd_get_monotonic_ns() != 2000000000000ULL);
	}

	TEST_CASE("fake_clock restores a previous override")
	{
		rspamd_set_monotonic_clock(&mono_test_fixed_clock);
		{
			rspamd_test::fake_clock clk(5.0);
			CHECK(rspamd_get_monotonic_ns() == 5000000000ULL);
		}
		CHECK(rspamd_get_monotonic_ns() == 123456789ULL);
		rspamd_set_monotonic_clock(nullptr);
	}
}

#endif /* RSPAMD_CXX_UNIT_MONOTONIC_CLOCK_HXX */
