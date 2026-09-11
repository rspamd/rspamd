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

/* Per-source stat tables of fuzzy storage keys: lazy growth and overflow */

#ifndef RSPAMD_RSPAMD_CXX_UNIT_FUZZY_KEY_IPS_HXX
#define RSPAMD_RSPAMD_CXX_UNIT_FUZZY_KEY_IPS_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

extern "C" {
#include "libserver/fuzzy_storage_internal.h"
#include "libutil/addr.h"
}

#include <memory>
#include <string>

TEST_SUITE("fuzzy_key_ips")
{
	using addr_ptr = std::unique_ptr<rspamd_inet_addr_t, decltype(&rspamd_inet_address_free)>;

	static auto make_addr(unsigned int n) -> addr_ptr
	{
		/* 10.a.b.c, distinct for every n below 2^24 */
		auto s = "10." + std::to_string((n >> 16) & 0xff) + "." +
				 std::to_string((n >> 8) & 0xff) + "." + std::to_string(n & 0xff);
		rspamd_inet_addr_t *a = nullptr;
		REQUIRE(rspamd_parse_inet_address(&a, s.c_str(), s.size(),
										  RSPAMD_INET_ADDRESS_PARSE_DEFAULT));
		return addr_ptr{a, rspamd_inet_address_free};
	}

	struct stat_holder {
		struct fuzzy_key_stat *st;
		stat_holder()
		{
			st = (struct fuzzy_key_stat *) g_malloc0(sizeof(*st));
			REF_INIT_RETAIN(st, fuzzy_key_stat_dtor);
		}
		~stat_holder()
		{
			REF_RELEASE(st);
		}
	};

	TEST_CASE("table is created on first use and not at all when disabled")
	{
		stat_holder h;
		auto a = make_addr(1);

		CHECK(h.st->last_ips == nullptr);
		CHECK(fuzzy_key_stat_get_ip(h.st, 0, a.get(), 100.0) == nullptr);
		CHECK(h.st->last_ips == nullptr);
		CHECK(h.st->ips_inserted == 0);

		auto *ip1 = fuzzy_key_stat_get_ip(h.st, 64, a.get(), 100.0);
		REQUIRE(ip1 != nullptr);
		REQUIRE(h.st->last_ips != nullptr);
		CHECK(rspamd_lru_hash_size(h.st->last_ips) == 1);
		CHECK(h.st->ips_inserted == 1);

		/* Same source comes back as the same record and is not re-counted */
		CHECK(fuzzy_key_stat_get_ip(h.st, 64, a.get(), 101.0) == ip1);
		CHECK(h.st->ips_inserted == 1);
	}

	TEST_CASE("a small population never trips the overflow guard")
	{
		stat_holder h;
		/* 32 is the smallest cap the LRU accepts */
		const unsigned int cap = 32;

		for (int round = 0; round < 50; round++) {
			for (unsigned int i = 0; i < cap / 2; i++) {
				auto a = make_addr(i);
				CHECK(fuzzy_key_stat_get_ip(h.st, cap, a.get(), 100.0 + round) != nullptr);
			}
		}

		CHECK_FALSE(h.st->ips_overflow);
		CHECK(h.st->last_ips != nullptr);
		CHECK(h.st->ips_inserted == cap / 2);
	}

	TEST_CASE("churn past the cap drops the table and sticks")
	{
		stat_holder h;
		const unsigned int cap = 32;
		const unsigned int limit = FUZZY_KEY_IPS_OVERFLOW_FACTOR * cap;
		unsigned int n = 0;

		/*
		 * Fill up to the point where the next insertion evicts: the LRU
		 * evicts on reaching its cap, so that is cap - 1 entries. None of
		 * these count as churn
		 */
		for (; n < cap - 1; n++) {
			auto a = make_addr(n);
			REQUIRE(fuzzy_key_stat_get_ip(h.st, cap, a.get(), 100.0) != nullptr);
		}
		CHECK_FALSE(h.st->ips_overflow);
		CHECK(h.st->ips_inserted_window == 0);

		/* Up to the threshold the table still serves new sources */
		for (; n < cap - 1 + limit; n++) {
			auto a = make_addr(n);
			REQUIRE(fuzzy_key_stat_get_ip(h.st, cap, a.get(), 100.0) != nullptr);
		}
		CHECK_FALSE(h.st->ips_overflow);
		CHECK(h.st->ips_inserted_window == limit);

		/* One more new source inside the window trips it */
		auto a = make_addr(n++);
		CHECK(fuzzy_key_stat_get_ip(h.st, cap, a.get(), 100.0) == nullptr);
		CHECK(h.st->ips_overflow);
		CHECK(h.st->last_ips == nullptr);
		CHECK(h.st->ips_inserted == n);

		/* And it stays off, even for sources that were tracked before */
		auto first = make_addr(0);
		CHECK(fuzzy_key_stat_get_ip(h.st, cap, first.get(), 5000.0) == nullptr);
		CHECK(h.st->last_ips == nullptr);
	}

	TEST_CASE("slow churn spread over windows does not trip")
	{
		stat_holder h;
		const unsigned int cap = 32;
		const unsigned int limit = FUZZY_KEY_IPS_OVERFLOW_FACTOR * cap;
		unsigned int n = 0;
		double now = 100.0;

		for (; n < cap - 1; n++) {
			auto a = make_addr(n);
			REQUIRE(fuzzy_key_stat_get_ip(h.st, cap, a.get(), now) != nullptr);
		}

		/* Half the threshold per window, over four windows */
		for (int w = 0; w < 4; w++) {
			now += FUZZY_KEY_IPS_OVERFLOW_WINDOW + 1.0;
			for (unsigned int i = 0; i < limit / 2; i++, n++) {
				auto a = make_addr(n);
				REQUIRE(fuzzy_key_stat_get_ip(h.st, cap, a.get(), now) != nullptr);
			}
		}

		CHECK_FALSE(h.st->ips_overflow);
		CHECK(h.st->last_ips != nullptr);
		CHECK(h.st->ips_inserted == n);
	}

	TEST_CASE("effective cap: explicit extension, default key, worker default")
	{
		struct rspamd_fuzzy_storage_ctx ctx;
		struct fuzzy_key def, other;

		memset(&ctx, 0, sizeof(ctx));
		memset(&def, 0, sizeof(def));
		memset(&other, 0, sizeof(other));
		ctx.max_ips_per_key = 1024;
		ctx.default_key = &def;
		def.max_ips = -1;
		other.max_ips = -1;

		CHECK(fuzzy_key_max_ips(&ctx, &def) == 0);
		CHECK(fuzzy_key_max_ips(&ctx, &other) == 1024);

		def.max_ips = 256;
		other.max_ips = 0;
		CHECK(fuzzy_key_max_ips(&ctx, &def) == 256);
		CHECK(fuzzy_key_max_ips(&ctx, &other) == 0);
	}
}

#endif
