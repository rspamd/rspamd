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

/* Unit tests for upstream slow-start ramping after revive */

#ifndef RSPAMD_CXX_UNIT_UPSTREAM_SLOW_START_HXX
#define RSPAMD_CXX_UNIT_UPSTREAM_SLOW_START_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "libutil/upstream.h"

#include <map>
#include <string>

TEST_SUITE("upstream_slow_start")
{
	TEST_CASE("setter accepts and applies the window")
	{
		auto *ctx = rspamd_upstreams_library_init();
		auto *ups = rspamd_upstreams_create(ctx);
		rspamd_upstreams_set_rotation(ups, RSPAMD_UPSTREAM_P2C);

		for (unsigned i = 0; i < 3; i++) {
			char addr[32];
			snprintf(addr, sizeof(addr), "127.0.0.%u:11333", i + 1);
			auto ok = rspamd_upstreams_add_upstream(ups, addr, 11333,
													RSPAMD_UPSTREAM_PARSE_DEFAULT, nullptr);
			REQUIRE(ok);
		}

		rspamd_upstreams_set_slow_start(ups, 5000);

		/* Without revive events the slow-start factor is 1.0, so selection
		 * should still cover all upstreams. */
		std::map<std::string, int> hits;
		for (int i = 0; i < 600; i++) {
			auto *up = rspamd_upstream_get(ups, RSPAMD_UPSTREAM_P2C, nullptr, 0);
			REQUIRE(up != nullptr);
			hits[rspamd_upstream_name(up)]++;
			rspamd_upstream_ok(up);
		}
		CHECK(hits.size() == 3);

		rspamd_upstreams_destroy(ups);
		rspamd_upstreams_library_unref(ctx);
	}

	TEST_CASE("disabled (default) is a no-op")
	{
		auto *ctx = rspamd_upstreams_library_init();
		auto *ups = rspamd_upstreams_create(ctx);
		rspamd_upstreams_set_rotation(ups, RSPAMD_UPSTREAM_P2C);

		for (unsigned i = 0; i < 3; i++) {
			char addr[32];
			snprintf(addr, sizeof(addr), "127.0.0.%u:11333", i + 1);
			REQUIRE(rspamd_upstreams_add_upstream(ups, addr, 11333,
												  RSPAMD_UPSTREAM_PARSE_DEFAULT, nullptr));
		}

		/* Don't set slow_start. Distribution must stay roughly uniform. */
		std::map<std::string, int> hits;
		for (int i = 0; i < 900; i++) {
			auto *up = rspamd_upstream_get(ups, RSPAMD_UPSTREAM_P2C, nullptr, 0);
			REQUIRE(up != nullptr);
			hits[rspamd_upstream_name(up)]++;
			rspamd_upstream_ok(up);
		}
		CHECK(hits.size() == 3);
		for (const auto &[name, count]: hits) {
			CHECK(count > 200);
		}

		rspamd_upstreams_destroy(ups);
		rspamd_upstreams_library_unref(ctx);
	}

	TEST_CASE("slow-start setter is idempotent under repeated calls")
	{
		auto *ctx = rspamd_upstreams_library_init();
		auto *ups = rspamd_upstreams_create(ctx);
		rspamd_upstreams_set_rotation(ups, RSPAMD_UPSTREAM_ROUND_ROBIN);

		REQUIRE(rspamd_upstreams_add_upstream(ups, "127.0.0.1:11333", 11333,
											  RSPAMD_UPSTREAM_PARSE_DEFAULT, nullptr));

		rspamd_upstreams_set_slow_start(ups, 1000);
		rspamd_upstreams_set_slow_start(ups, 2000);
		rspamd_upstreams_set_slow_start(ups, 0);

		auto *up = rspamd_upstream_get(ups, RSPAMD_UPSTREAM_ROUND_ROBIN, nullptr, 0);
		REQUIRE(up != nullptr);
		rspamd_upstream_ok(up);

		rspamd_upstreams_destroy(ups);
		rspamd_upstreams_library_unref(ctx);
	}
}

#endif
