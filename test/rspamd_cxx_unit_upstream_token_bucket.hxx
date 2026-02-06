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

/* Unit tests for upstream token bucket load balancing */

#ifndef RSPAMD_CXX_UNIT_UPSTREAM_TOKEN_BUCKET_HXX
#define RSPAMD_CXX_UNIT_UPSTREAM_TOKEN_BUCKET_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "libutil/upstream.h"

#include <map>
#include <string>

/*
 * Helper: create an upstream_ctx + upstream_list with N numeric IP upstreams.
 * Uses 127.0.0.x addresses on port 11333 to avoid DNS resolution.
 */
struct token_bucket_test_ctx {
	struct upstream_ctx *ctx;
	struct upstream_list *ups;
	unsigned int n_upstreams;

	token_bucket_test_ctx(unsigned int n, gsize max_tokens = 10000,
						  gsize scale = 1024, gsize min_tokens = 1,
						  gsize base_cost = 10)
		: n_upstreams(n)
	{
		ctx = rspamd_upstreams_library_init();
		ups = rspamd_upstreams_create(ctx);

		/* Must set rotation before adding upstreams so set_active initialises tokens */
		rspamd_upstreams_set_rotation(ups, RSPAMD_UPSTREAM_TOKEN_BUCKET);
		rspamd_upstreams_set_token_bucket(ups, max_tokens, scale, min_tokens, base_cost);

		for (unsigned int i = 0; i < n; i++) {
			char addr[32];
			snprintf(addr, sizeof(addr), "127.0.0.%u:11333", i + 1);
			auto ok = rspamd_upstreams_add_upstream(ups, addr, 11333,
													RSPAMD_UPSTREAM_PARSE_DEFAULT, nullptr);
			REQUIRE(ok);
		}
	}

	~token_bucket_test_ctx()
	{
		rspamd_upstreams_destroy(ups);
		rspamd_upstreams_library_unref(ctx);
	}

	/* non-copyable */
	token_bucket_test_ctx(const token_bucket_test_ctx &) = delete;
	token_bucket_test_ctx &operator=(const token_bucket_test_ctx &) = delete;
};

TEST_SUITE("upstream_token_bucket")
{
	TEST_CASE("basic selection returns non-null upstream")
	{
		token_bucket_test_ctx t(3);

		CHECK(rspamd_upstreams_count(t.ups) == 3);
		CHECK(rspamd_upstreams_alive(t.ups) == 3);

		gsize reserved = 0;
		auto *up = rspamd_upstream_get_token_bucket(t.ups, nullptr, 1024, &reserved);
		CHECK(up != nullptr);
		CHECK(reserved > 0);

		/* Return tokens so cleanup is clean */
		rspamd_upstream_return_tokens(up, reserved, TRUE);
	}

	TEST_CASE("token cost formula: base_cost + message_size / scale")
	{
		/* scale=1024, base_cost=10 => cost(10240) = 10 + 10240/1024 = 20 */
		token_bucket_test_ctx t(1, 10000, 1024, 1, 10);

		gsize reserved = 0;
		auto *up = rspamd_upstream_get_token_bucket(t.ups, nullptr, 10240, &reserved);
		REQUIRE(up != nullptr);
		CHECK(reserved == 20);
		rspamd_upstream_return_tokens(up, reserved, TRUE);

		/* Zero-length message: cost = base_cost only */
		reserved = 0;
		up = rspamd_upstream_get_token_bucket(t.ups, nullptr, 0, &reserved);
		REQUIRE(up != nullptr);
		CHECK(reserved == 10);
		rspamd_upstream_return_tokens(up, reserved, TRUE);

		/* Large message: 1 MB => cost = 10 + 1048576/1024 = 1034 */
		reserved = 0;
		up = rspamd_upstream_get_token_bucket(t.ups, nullptr, 1048576, &reserved);
		REQUIRE(up != nullptr);
		CHECK(reserved == 1034);
		rspamd_upstream_return_tokens(up, reserved, TRUE);
	}

	TEST_CASE("token return on success restores available tokens")
	{
		/* Single upstream with 100 max tokens, scale=1, base_cost=10 */
		token_bucket_test_ctx t(1, 100, 1, 0, 10);

		gsize reserved = 0;
		auto *up = rspamd_upstream_get_token_bucket(t.ups, nullptr, 20, &reserved);
		REQUIRE(up != nullptr);
		/* cost = 10 + 20/1 = 30 */
		CHECK(reserved == 30);

		/* After reserving, get another - should still succeed since 100-30=70 available */
		gsize reserved2 = 0;
		auto *up2 = rspamd_upstream_get_token_bucket(t.ups, nullptr, 20, &reserved2);
		REQUIRE(up2 != nullptr);
		CHECK(reserved2 == 30);

		/* Return first batch on success */
		rspamd_upstream_return_tokens(up, reserved, TRUE);

		/* Return second batch on success */
		rspamd_upstream_return_tokens(up2, reserved2, TRUE);

		/* After returning both, upstream should be fully available again */
		gsize reserved3 = 0;
		auto *up3 = rspamd_upstream_get_token_bucket(t.ups, nullptr, 80, &reserved3);
		REQUIRE(up3 != nullptr);
		/* cost = 10 + 80 = 90, should be fine since tokens were returned */
		CHECK(reserved3 == 90);
		rspamd_upstream_return_tokens(up3, reserved3, TRUE);
	}

	TEST_CASE("token penalty on failure does not restore available tokens")
	{
		/* Single upstream with 200 max tokens, scale=1, base_cost=10 (default) */
		token_bucket_test_ctx t(1, 200, 1, 1, 10);

		gsize reserved = 0;
		auto *up = rspamd_upstream_get_token_bucket(t.ups, nullptr, 60, &reserved);
		REQUIRE(up != nullptr);
		/* cost = 10 + 60/1 = 70 */
		CHECK(reserved == 70);

		/* Return with failure - tokens NOT restored to available pool.
		 * available: 200 - 70 = 130, inflight: 0 */
		rspamd_upstream_return_tokens(up, reserved, FALSE);

		/* Now 130 tokens available. Request for 50: cost = 10 + 50 = 60 => ok */
		gsize reserved2 = 0;
		auto *up2 = rspamd_upstream_get_token_bucket(t.ups, nullptr, 50, &reserved2);
		REQUIRE(up2 != nullptr);
		CHECK(reserved2 == 60);

		/* Return success to restore these */
		rspamd_upstream_return_tokens(up2, reserved2, TRUE);

		/* Now available = 130 - 60 + 60 = 130 (original 70 still lost from failure).
		 * Request for 140: cost = 10 + 140 = 150 > 130 => still selected as fallback */
		gsize reserved3 = 0;
		auto *up3 = rspamd_upstream_get_token_bucket(t.ups, nullptr, 140, &reserved3);
		REQUIRE(up3 != nullptr);
		CHECK(reserved3 == 150);
		rspamd_upstream_return_tokens(up3, reserved3, TRUE);
	}

	TEST_CASE("least-loaded upstream is preferred")
	{
		/* 2 upstreams, 1000 tokens each, scale=1, base_cost=0 */
		token_bucket_test_ctx t(2, 1000, 1, 0, 0);

		/* Load up the first upstream with a heavy request */
		gsize reserved_heavy = 0;
		auto *heavy = rspamd_upstream_get_token_bucket(t.ups, nullptr, 800, &reserved_heavy);
		REQUIRE(heavy != nullptr);
		auto heavy_name = std::string(rspamd_upstream_name(heavy));

		/* Next request should prefer the OTHER upstream (less loaded) */
		gsize reserved2 = 0;
		auto *light = rspamd_upstream_get_token_bucket(t.ups, nullptr, 10, &reserved2);
		REQUIRE(light != nullptr);
		auto light_name = std::string(rspamd_upstream_name(light));
		CHECK(light_name != heavy_name);

		rspamd_upstream_return_tokens(heavy, reserved_heavy, TRUE);
		rspamd_upstream_return_tokens(light, reserved2, TRUE);
	}

	TEST_CASE("except parameter excludes upstream")
	{
		token_bucket_test_ctx t(2);

		gsize reserved = 0;
		auto *first = rspamd_upstream_get_token_bucket(t.ups, nullptr, 0, &reserved);
		REQUIRE(first != nullptr);
		auto first_name = std::string(rspamd_upstream_name(first));

		/* Get another upstream excluding the first one */
		gsize reserved2 = 0;
		auto *second = rspamd_upstream_get_token_bucket(t.ups, first, 0, &reserved2);
		REQUIRE(second != nullptr);
		CHECK(std::string(rspamd_upstream_name(second)) != first_name);

		rspamd_upstream_return_tokens(first, reserved, TRUE);
		rspamd_upstream_return_tokens(second, reserved2, TRUE);
	}

	TEST_CASE("exhaustion fallback to least-inflight upstream")
	{
		/* 2 upstreams, only 50 tokens each, scale=1, base_cost=0 */
		token_bucket_test_ctx t(2, 50, 1, 0, 0);

		/* Exhaust both upstreams */
		gsize r1 = 0, r2 = 0;
		auto *up1 = rspamd_upstream_get_token_bucket(t.ups, nullptr, 50, &r1);
		REQUIRE(up1 != nullptr);

		auto *up2 = rspamd_upstream_get_token_bucket(t.ups, nullptr, 50, &r2);
		REQUIRE(up2 != nullptr);

		/* Both upstreams should now have 0 available tokens.
		 * Next request should still succeed (fallback to least-inflight) */
		gsize r3 = 0;
		auto *up3 = rspamd_upstream_get_token_bucket(t.ups, nullptr, 10, &r3);
		CHECK(up3 != nullptr);

		if (up3) rspamd_upstream_return_tokens(up3, r3, TRUE);
		rspamd_upstream_return_tokens(up1, r1, TRUE);
		rspamd_upstream_return_tokens(up2, r2, TRUE);
	}

	TEST_CASE("fair distribution across upstreams with inflight requests")
	{
		/* 3 upstreams, generous token pool.
		 * The min-heap selects by lowest inflight_tokens, so we must keep
		 * requests inflight for the algorithm to distribute across upstreams. */
		token_bucket_test_ctx t(3, 100000, 1024, 1, 10);

		const int batch_size = 30;
		struct upstream *batch_ups[batch_size];
		gsize batch_reserved[batch_size];
		std::map<std::string, int> counts;

		/* Issue batch_size requests without returning tokens (simulating concurrency) */
		for (int i = 0; i < batch_size; i++) {
			batch_reserved[i] = 0;
			batch_ups[i] = rspamd_upstream_get_token_bucket(t.ups, nullptr, 1024, &batch_reserved[i]);
			REQUIRE(batch_ups[i] != nullptr);
			counts[rspamd_upstream_name(batch_ups[i])]++;
		}

		/* All 3 upstreams should be used */
		CHECK(counts.size() == 3);
		for (const auto &[name, count]: counts) {
			/* Each upstream should get ~10 requests (30/3), allow some tolerance */
			CHECK(count >= 5);
			CHECK(count <= 15);
		}

		/* Cleanup: return all tokens */
		for (int i = 0; i < batch_size; i++) {
			rspamd_upstream_return_tokens(batch_ups[i], batch_reserved[i], TRUE);
		}
	}

	TEST_CASE("custom token bucket configuration takes effect")
	{
		/* max=500, scale=512, base_cost=5 */
		token_bucket_test_ctx t(1, 500, 512, 1, 5);

		gsize reserved = 0;
		auto *up = rspamd_upstream_get_token_bucket(t.ups, nullptr, 2048, &reserved);
		REQUIRE(up != nullptr);
		/* cost = 5 + 2048/512 = 9 */
		CHECK(reserved == 9);
		rspamd_upstream_return_tokens(up, reserved, TRUE);
	}

	TEST_CASE("empty upstream list returns null")
	{
		auto *ctx = rspamd_upstreams_library_init();
		auto *ups = rspamd_upstreams_create(ctx);
		rspamd_upstreams_set_rotation(ups, RSPAMD_UPSTREAM_TOKEN_BUCKET);

		gsize reserved = 0;
		auto *up = rspamd_upstream_get_token_bucket(ups, nullptr, 1024, &reserved);
		CHECK(up == nullptr);
		CHECK(reserved == 0);

		rspamd_upstreams_destroy(ups);
		rspamd_upstreams_library_unref(ctx);
	}

	TEST_CASE("null parameters handled safely")
	{
		auto *up = rspamd_upstream_get_token_bucket(nullptr, nullptr, 1024, nullptr);
		CHECK(up == nullptr);

		/* Return tokens with null upstream is a no-op */
		rspamd_upstream_return_tokens(nullptr, 100, TRUE);
	}

	TEST_CASE("large message size does not overflow")
	{
		/* scale=1024, base_cost=10, max_tokens=100000 */
		token_bucket_test_ctx t(1, 100000, 1024, 1, 10);

		/* 100 MB message */
		gsize reserved = 0;
		auto *up = rspamd_upstream_get_token_bucket(t.ups, nullptr, 100 * 1024 * 1024, &reserved);
		REQUIRE(up != nullptr);
		/* cost = 10 + (100*1024*1024)/1024 = 10 + 102400 = 102410 */
		CHECK(reserved == 102410);
		rspamd_upstream_return_tokens(up, reserved, TRUE);
	}

	TEST_CASE("multiple inflight requests track correctly")
	{
		/* 1 upstream, 10000 tokens, scale=1, base_cost=10 */
		token_bucket_test_ctx t(1, 10000, 1, 1, 10);

		/* Issue 5 concurrent requests of 100 bytes each, cost=10+100=110 */
		struct upstream *ups[5];
		gsize reservations[5];

		for (int i = 0; i < 5; i++) {
			reservations[i] = 0;
			ups[i] = rspamd_upstream_get_token_bucket(t.ups, nullptr, 100, &reservations[i]);
			REQUIRE(ups[i] != nullptr);
			CHECK(reservations[i] == 110);
		}

		/* Total inflight: 500, available: 10000-500=9500 */
		/* Should still be able to get more */
		gsize r6 = 0;
		auto *up6 = rspamd_upstream_get_token_bucket(t.ups, nullptr, 100, &r6);
		CHECK(up6 != nullptr);
		rspamd_upstream_return_tokens(up6, r6, TRUE);

		/* Return all 5 in reverse order */
		for (int i = 4; i >= 0; i--) {
			rspamd_upstream_return_tokens(ups[i], reservations[i], TRUE);
		}
	}

	TEST_CASE("mixed success and failure token returns")
	{
		/* 1 upstream, 2000 tokens, scale=1, base_cost=10 */
		token_bucket_test_ctx t(1, 2000, 1, 1, 10);

		/* Request 1: msg=200 => cost=210, succeeds
		 * available: 2000->1790->2000 (restored) */
		gsize r1 = 0;
		auto *up1 = rspamd_upstream_get_token_bucket(t.ups, nullptr, 200, &r1);
		REQUIRE(up1 != nullptr);
		CHECK(r1 == 210);
		rspamd_upstream_return_tokens(up1, r1, TRUE);

		/* Request 2: msg=200 => cost=210, fails
		 * available: 2000->1790, failure: NOT restored -> stays 1790 */
		gsize r2 = 0;
		auto *up2 = rspamd_upstream_get_token_bucket(t.ups, nullptr, 200, &r2);
		REQUIRE(up2 != nullptr);
		CHECK(r2 == 210);
		rspamd_upstream_return_tokens(up2, r2, FALSE);

		/* Request 3: msg=200 => cost=210, succeeds
		 * available: 1790->1580->1790 (restored) */
		gsize r3 = 0;
		auto *up3 = rspamd_upstream_get_token_bucket(t.ups, nullptr, 200, &r3);
		REQUIRE(up3 != nullptr);
		CHECK(r3 == 210);
		rspamd_upstream_return_tokens(up3, r3, TRUE);

		/* Net available: 1790 (lost 210 from failure).
		 * Request 4: msg=800 => cost=810 < 1790 => should succeed normally */
		gsize r4 = 0;
		auto *up4 = rspamd_upstream_get_token_bucket(t.ups, nullptr, 800, &r4);
		REQUIRE(up4 != nullptr);
		CHECK(r4 == 810);
		rspamd_upstream_return_tokens(up4, r4, TRUE);
	}

	TEST_CASE("get via generic API falls back for token bucket rotation")
	{
		token_bucket_test_ctx t(3);

		/* Using rspamd_upstream_get with TOKEN_BUCKET rotation should fall back
		 * to round-robin (as documented in the switch case) */
		auto *up = rspamd_upstream_get(t.ups, RSPAMD_UPSTREAM_TOKEN_BUCKET, nullptr, 0);
		CHECK(up != nullptr);
	}
}

#endif
