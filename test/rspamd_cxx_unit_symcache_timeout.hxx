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

#ifndef RSPAMD_CXX_UNIT_SYMCACHE_TIMEOUT_HXX
#define RSPAMD_CXX_UNIT_SYMCACHE_TIMEOUT_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "libserver/rspamd_symcache.h"
#include "libutil/util.h"

namespace {
/* Dummy callback — does nothing, just satisfies the symbol_func_t signature */
static void
dummy_callback(struct rspamd_task *task, struct rspamd_symcache_dynamic_item *item, gpointer ud)
{
}

struct symcache_fixture {
	struct rspamd_config *cfg = nullptr;
	struct rspamd_symcache *cache = nullptr;

	symcache_fixture()
	{
		cfg = rspamd_config_new(RSPAMD_CONFIG_INIT_DEFAULT);
		REQUIRE(cfg != nullptr);
		cache = rspamd_symcache_new(cfg);
		REQUIRE(cache != nullptr);
	}

	~symcache_fixture()
	{
		if (cache != nullptr) {
			rspamd_symcache_destroy(cache);
		}
		if (cfg != nullptr) {
			rspamd_config_free(cfg);
		}
	}

	/* Add a symbol with a timeout augmentation and return its id */
	int add_symbol(const char *name, int priority, int type_flags, double timeout)
	{
		int id = rspamd_symcache_add_symbol(cache, name, priority,
											dummy_callback, nullptr, type_flags, -1);
		REQUIRE(id >= 0);

		if (timeout > 0.0) {
			char timeout_str[64];
			snprintf(timeout_str, sizeof(timeout_str), "timeout=%f", timeout);
			auto ok = rspamd_symcache_add_symbol_augmentation(cache, id, timeout_str, nullptr);
			REQUIRE(ok);
		}

		return id;
	}

	double get_max_timeout()
	{
		auto *tres = rspamd_symcache_get_max_timeout(cache);
		REQUIRE(tres != nullptr);
		double result = tres->max_timeout;
		rspamd_symcache_timeout_result_free(tres);
		return result;
	}
};

}// namespace

TEST_SUITE("symcache_timeout")
{
	TEST_CASE("same priority prefilters contribute max, not sum")
	{
		symcache_fixture fx;

		fx.add_symbol("PRE_A", 5, SYMBOL_TYPE_PREFILTER, 8.0);
		fx.add_symbol("PRE_B", 5, SYMBOL_TYPE_PREFILTER, 3.0);

		REQUIRE(rspamd_symcache_init(fx.cache));

		/* Both at priority 5: max(8, 3) = 8, not 8 + 3 = 11 */
		CHECK(fx.get_max_timeout() == doctest::Approx(8.0));
	}

	TEST_CASE("different priorities are summed")
	{
		symcache_fixture fx;

		fx.add_symbol("PRE_A", 5, SYMBOL_TYPE_PREFILTER, 8.0);
		fx.add_symbol("PRE_B", 3, SYMBOL_TYPE_PREFILTER, 4.0);

		REQUIRE(rspamd_symcache_init(fx.cache));

		/* Different priority groups: 8 + 4 = 12 */
		CHECK(fx.get_max_timeout() == doctest::Approx(12.0));
	}

	TEST_CASE("phases are summed, items within a phase are grouped")
	{
		symcache_fixture fx;

		/* Prefilter phase: two at same priority 5 */
		fx.add_symbol("PRE_A", 5, SYMBOL_TYPE_PREFILTER, 5.0);
		fx.add_symbol("PRE_B", 5, SYMBOL_TYPE_PREFILTER, 3.0);
		/* → max(5, 3) = 5 */

		/* Normal filter phase: longest chain */
		fx.add_symbol("FILTER_A", 0, SYMBOL_TYPE_NORMAL, 10.0);
		/* → 10 */

		/* Postfilter phase */
		fx.add_symbol("POST_A", 0, SYMBOL_TYPE_POSTFILTER, 3.0);
		/* → 3 */

		/* Idempotent phase: two at same priority 0 */
		fx.add_symbol("IDEM_A", 0, SYMBOL_TYPE_IDEMPOTENT, 5.0);
		fx.add_symbol("IDEM_B", 0, SYMBOL_TYPE_IDEMPOTENT, 2.0);
		/* → max(5, 2) = 5 */

		REQUIRE(rspamd_symcache_init(fx.cache));

		/* Total: 5 (prefilters) + 10 (filters) + 3 (postfilters) + 5 (idempotent) = 23 */
		CHECK(fx.get_max_timeout() == doctest::Approx(23.0));
	}

	TEST_CASE("single item per phase")
	{
		symcache_fixture fx;

		fx.add_symbol("PRE_A", 5, SYMBOL_TYPE_PREFILTER, 7.0);

		REQUIRE(rspamd_symcache_init(fx.cache));

		CHECK(fx.get_max_timeout() == doctest::Approx(7.0));
	}

	TEST_CASE("three items same priority take max")
	{
		symcache_fixture fx;

		fx.add_symbol("PRE_A", 5, SYMBOL_TYPE_PREFILTER, 3.0);
		fx.add_symbol("PRE_B", 5, SYMBOL_TYPE_PREFILTER, 9.0);
		fx.add_symbol("PRE_C", 5, SYMBOL_TYPE_PREFILTER, 5.0);

		REQUIRE(rspamd_symcache_init(fx.cache));

		/* max(3, 9, 5) = 9 */
		CHECK(fx.get_max_timeout() == doctest::Approx(9.0));
	}

	TEST_CASE("normal filters take longest chain")
	{
		symcache_fixture fx;

		/* Two normal filters: max(6, 12) = 12 */
		fx.add_symbol("FILTER_A", 0, SYMBOL_TYPE_NORMAL, 6.0);
		fx.add_symbol("FILTER_B", 0, SYMBOL_TYPE_NORMAL, 12.0);

		REQUIRE(rspamd_symcache_init(fx.cache));

		CHECK(fx.get_max_timeout() == doctest::Approx(12.0));
	}
}

#endif// RSPAMD_CXX_UNIT_SYMCACHE_TIMEOUT_HXX
