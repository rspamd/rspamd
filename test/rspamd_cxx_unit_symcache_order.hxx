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

/*
 * Unit tests for the symbols cache execution plan: stages, levels, hoisting
 * of dependencies, rejected edges and the timeout accounting that follows
 * the plan.
 */

#ifndef RSPAMD_CXX_UNIT_SYMCACHE_ORDER_HXX
#define RSPAMD_CXX_UNIT_SYMCACHE_ORDER_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "libserver/cfg_file.h"
#include "libserver/rspamd_symcache.h"
#include "libutil/util.h"

#include <algorithm>
#include <string>
#include <vector>

namespace {

static void
order_dummy_callback(struct rspamd_task *task, struct rspamd_symcache_dynamic_item *item, gpointer ud)
{
}

struct symcache_order_fixture {
	struct rspamd_config *cfg = nullptr;
	struct rspamd_symcache *cache = nullptr;

	symcache_order_fixture()
	{
		cfg = rspamd_config_new(RSPAMD_CONFIG_INIT_DEFAULT);
		REQUIRE(cfg != nullptr);
		cache = rspamd_symcache_new(cfg);
		REQUIRE(cache != nullptr);
	}

	~symcache_order_fixture()
	{
		if (cache != nullptr) {
			rspamd_symcache_destroy(cache);
		}
		if (cfg != nullptr) {
			rspamd_config_free(cfg);
		}
	}

	int add(const char *name, int priority, int type_flags, double timeout = 0.0)
	{
		int id = rspamd_symcache_add_symbol(cache, name, priority,
											order_dummy_callback, nullptr, type_flags, -1);
		REQUIRE(id >= 0);

		if (timeout > 0.0) {
			char timeout_str[64];
			snprintf(timeout_str, sizeof(timeout_str), "timeout=%f", timeout);
			REQUIRE(rspamd_symcache_add_symbol_augmentation(cache, id, timeout_str, nullptr));
		}

		return id;
	}

	int add_virtual(const char *name, int parent)
	{
		int id = rspamd_symcache_add_symbol(cache, name, 0, nullptr, nullptr,
											SYMBOL_TYPE_VIRTUAL, parent);
		REQUIRE(id >= 0);

		return id;
	}

	void depends(const char *from, const char *to, bool hard = false)
	{
		rspamd_symcache_add_delayed_dependency(cache, from, to, hard);
	}

	void init()
	{
		REQUIRE(rspamd_symcache_init(cache));
	}

	struct rspamd_symcache_exec_info info(const char *name)
	{
		struct rspamd_symcache_exec_info i{};
		REQUIRE(rspamd_symcache_get_symbol_exec_info(cache, name, &i));

		return i;
	}

	/* Symbols in the execution order */
	std::vector<std::string> plan()
	{
		std::vector<std::string> out;
		auto *obj = rspamd_symcache_dump_exec_plan(cache);
		ucl_object_iter_t it = nullptr;
		const ucl_object_t *bucket;

		while ((bucket = ucl_object_iterate(obj, &it, true)) != nullptr) {
			const auto *syms = ucl_object_lookup(bucket, "symbols");
			ucl_object_iter_t sit = nullptr;
			const ucl_object_t *sym;

			while ((sym = ucl_object_iterate(syms, &sit, true)) != nullptr) {
				out.emplace_back(ucl_object_tostring(ucl_object_lookup(sym, "symbol")));
			}
		}

		ucl_object_unref(obj);

		return out;
	}

	/* Dependencies of a symbol as they are known to the runtime */
	std::vector<std::string> deps_of(const char *name)
	{
		std::vector<std::string> out;
		auto *obj = rspamd_symcache_dump_exec_plan(cache);
		ucl_object_iter_t it = nullptr;
		const ucl_object_t *bucket;

		while ((bucket = ucl_object_iterate(obj, &it, true)) != nullptr) {
			const auto *syms = ucl_object_lookup(bucket, "symbols");
			ucl_object_iter_t sit = nullptr;
			const ucl_object_t *sym;

			while ((sym = ucl_object_iterate(syms, &sit, true)) != nullptr) {
				if (strcmp(ucl_object_tostring(ucl_object_lookup(sym, "symbol")), name) == 0) {
					const auto *deps = ucl_object_lookup(sym, "dependencies");

					if (deps != nullptr) {
						ucl_object_iter_t dit = nullptr;
						const ucl_object_t *dep;

						while ((dep = ucl_object_iterate(deps, &dit, true)) != nullptr) {
							out.emplace_back(ucl_object_tostring(dep));
						}
					}
				}
			}
		}

		ucl_object_unref(obj);

		return out;
	}

	static int position(const std::vector<std::string> &p, const char *name)
	{
		auto it = std::find(p.begin(), p.end(), name);
		REQUIRE(it != p.end());

		return static_cast<int>(it - p.begin());
	}

	double max_timeout()
	{
		auto *tres = rspamd_symcache_get_max_timeout(cache);
		REQUIRE(tres != nullptr);
		double result = tres->max_timeout;
		rspamd_symcache_timeout_result_free(tres);

		return result;
	}
};

}// namespace

TEST_SUITE("symcache_order")
{
	TEST_CASE_FIXTURE(symcache_order_fixture, "declared types define stages and levels")
	{
		add("CONN", 1, SYMBOL_TYPE_CONNFILTER);
		add("PRE", 9, SYMBOL_TYPE_PREFILTER);
		add("FILT", 5, SYMBOL_TYPE_NORMAL);
		add("POST", 9, SYMBOL_TYPE_POSTFILTER);
		add("IDEM", 3, SYMBOL_TYPE_IDEMPOTENT);
		init();

		auto i = info("CONN");
		CHECK(std::string(i.stage) == "connfilters");
		CHECK(i.level == 1);
		CHECK(i.hoisted_by == nullptr);

		i = info("PRE");
		CHECK(std::string(i.stage) == "prefilters");
		CHECK(i.level == 9);

		/* Priority of filters is a soft key only */
		i = info("FILT");
		CHECK(std::string(i.stage) == "filters");
		CHECK(i.level == 0);

		/* Higher priority runs later for postfilters and idempotent symbols */
		i = info("POST");
		CHECK(std::string(i.stage) == "postfilters");
		CHECK(i.level == -9);

		i = info("IDEM");
		CHECK(std::string(i.stage) == "idempotent");
		CHECK(i.level == -3);
	}

	TEST_CASE_FIXTURE(symcache_order_fixture, "prefilters run by level, postfilters in the inverted order")
	{
		add("PRE_MED_A", 5, SYMBOL_TYPE_PREFILTER);
		add("PRE_HIGH", 9, SYMBOL_TYPE_PREFILTER);
		add("PRE_MED_B", 5, SYMBOL_TYPE_PREFILTER);
		add("PRE_LOW", 1, SYMBOL_TYPE_PREFILTER);
		add("POST_LOW", 1, SYMBOL_TYPE_POSTFILTER);
		add("POST_HIGH", 9, SYMBOL_TYPE_POSTFILTER);
		add("FILT", 0, SYMBOL_TYPE_NORMAL);
		init();

		auto p = plan();
		CHECK(position(p, "PRE_HIGH") < position(p, "PRE_MED_A"));
		/* Registration order inside a level */
		CHECK(position(p, "PRE_MED_A") < position(p, "PRE_MED_B"));
		CHECK(position(p, "PRE_MED_B") < position(p, "PRE_LOW"));
		CHECK(position(p, "PRE_LOW") < position(p, "FILT"));
		CHECK(position(p, "FILT") < position(p, "POST_LOW"));
		CHECK(position(p, "POST_LOW") < position(p, "POST_HIGH"));
	}

	TEST_CASE_FIXTURE(symcache_order_fixture, "a prefilter dependency hoists a filter with its chain")
	{
		add("PRE", 5, SYMBOL_TYPE_PREFILTER);
		add("F", 0, SYMBOL_TYPE_NORMAL);
		add("G", 0, SYMBOL_TYPE_NORMAL);
		add("H", 0, SYMBOL_TYPE_NORMAL);
		add("PLAIN", 0, SYMBOL_TYPE_NORMAL);
		depends("PRE", "F");
		depends("F", "G");
		depends("H", "F");
		init();

		auto i = info("F");
		CHECK(std::string(i.stage) == "prefilters");
		CHECK(i.level == 5);
		REQUIRE(i.hoisted_by != nullptr);
		CHECK(std::string(i.hoisted_by) == "PRE");

		/* Transitive: the dependency of the hoisted filter follows it */
		i = info("G");
		CHECK(std::string(i.stage) == "prefilters");
		CHECK(i.level == 5);
		REQUIRE(i.hoisted_by != nullptr);
		CHECK(std::string(i.hoisted_by) == "PRE");

		/* A filter that depends on the hoisted one stays a filter */
		i = info("H");
		CHECK(std::string(i.stage) == "filters");
		CHECK(i.hoisted_by == nullptr);

		i = info("PLAIN");
		CHECK(std::string(i.stage) == "filters");

		/* Dependencies first inside the bucket, and everything before the plain filters */
		auto p = plan();
		CHECK(position(p, "G") < position(p, "F"));
		CHECK(position(p, "F") < position(p, "PRE"));
		CHECK(position(p, "PRE") < position(p, "H"));
		CHECK(position(p, "PRE") < position(p, "PLAIN"));
	}

	TEST_CASE_FIXTURE(symcache_order_fixture, "the earliest dependent wins")
	{
		add("PRE_MED", 5, SYMBOL_TYPE_PREFILTER);
		add("PRE_HIGH", 9, SYMBOL_TYPE_PREFILTER);
		add("F", 0, SYMBOL_TYPE_NORMAL);
		depends("PRE_MED", "F");
		depends("PRE_HIGH", "F");
		/* A prefilter depending on a lower level prefilter raises it */
		add("PRE_LOW", 1, SYMBOL_TYPE_PREFILTER);
		add("PRE_MED2", 5, SYMBOL_TYPE_PREFILTER);
		depends("PRE_MED2", "PRE_LOW");
		init();

		auto i = info("F");
		CHECK(std::string(i.stage) == "prefilters");
		CHECK(i.level == 9);
		REQUIRE(i.hoisted_by != nullptr);
		CHECK(std::string(i.hoisted_by) == "PRE_HIGH");

		i = info("PRE_LOW");
		CHECK(std::string(i.stage) == "prefilters");
		CHECK(i.level == 5);
		REQUIRE(i.hoisted_by != nullptr);
		CHECK(std::string(i.hoisted_by) == "PRE_MED2");

		auto p = plan();
		CHECK(position(p, "F") < position(p, "PRE_HIGH"));
		CHECK(position(p, "PRE_LOW") < position(p, "PRE_MED2"));
	}

	TEST_CASE_FIXTURE(symcache_order_fixture, "dependencies through virtual symbols hoist the parent")
	{
		auto fid = add("F", 0, SYMBOL_TYPE_NORMAL);
		add_virtual("F_VIRT", fid);
		add("PRE", 5, SYMBOL_TYPE_PREFILTER);
		depends("PRE", "F_VIRT");

		auto pid = add("P2", 5, SYMBOL_TYPE_PREFILTER);
		add_virtual("P2_VIRT", pid);
		add("F2", 0, SYMBOL_TYPE_NORMAL);
		depends("P2_VIRT", "F2");
		init();

		auto i = info("F");
		CHECK(std::string(i.stage) == "prefilters");
		CHECK(i.level == 5);

		/* Virtual symbols report the plan of their parents */
		i = info("F_VIRT");
		CHECK(std::string(i.stage) == "prefilters");
		CHECK(i.level == 5);

		i = info("F2");
		CHECK(std::string(i.stage) == "prefilters");
		REQUIRE(i.hoisted_by != nullptr);
		CHECK(std::string(i.hoisted_by) == "P2");
	}

	TEST_CASE_FIXTURE(symcache_order_fixture, "edges to a later stage are dropped")
	{
		add("CONN", 1, SYMBOL_TYPE_CONNFILTER);
		add("F", 0, SYMBOL_TYPE_NORMAL);
		add("PRE", 5, SYMBOL_TYPE_PREFILTER);
		add("POST", 5, SYMBOL_TYPE_POSTFILTER);
		add("IDEM", 0, SYMBOL_TYPE_IDEMPOTENT);
		add("SELF", 0, SYMBOL_TYPE_NORMAL);
		/* Rejected: the message is not read at the connfilters stage */
		depends("CONN", "F");
		depends("PRE", "POST");
		depends("F", "POST");
		depends("POST", "IDEM");
		depends("SELF", "SELF");
		/* Accepted: later stages depend on earlier ones */
		depends("POST", "F");
		depends("IDEM", "PRE");
		depends("F", "CONN");
		init();

		CHECK(deps_of("CONN").empty());
		CHECK(deps_of("PRE").empty());
		CHECK(deps_of("SELF").empty());
		CHECK(deps_of("F") == std::vector<std::string>{"CONN"});
		CHECK(deps_of("POST") == std::vector<std::string>{"F"});
		CHECK(deps_of("IDEM") == std::vector<std::string>{"PRE"});

		/* Nothing has moved */
		CHECK(std::string(info("F").stage) == "filters");
		CHECK(std::string(info("POST").stage) == "postfilters");
		CHECK(std::string(info("IDEM").stage) == "idempotent");
		CHECK(std::string(info("CONN").stage) == "connfilters");
	}

	TEST_CASE_FIXTURE(symcache_order_fixture, "cycles are broken at init")
	{
		add("A", 0, SYMBOL_TYPE_NORMAL, 1.0);
		add("B", 0, SYMBOL_TYPE_NORMAL, 2.0);
		depends("A", "B");
		depends("B", "A");
		add("PRE", 5, SYMBOL_TYPE_PREFILTER, 0.5);
		depends("PRE", "A");
		/* A longer cycle through a filter chain */
		add("C", 0, SYMBOL_TYPE_NORMAL, 1.0);
		add("D", 0, SYMBOL_TYPE_NORMAL, 1.0);
		add("E", 0, SYMBOL_TYPE_NORMAL, 1.0);
		depends("C", "D");
		depends("D", "E");
		depends("E", "C");
		init();

		/* One edge of each cycle has been dropped */
		CHECK(deps_of("A").size() + deps_of("B").size() == 1);
		CHECK(deps_of("C").size() + deps_of("D").size() + deps_of("E").size() == 2);

		CHECK(std::string(info("A").stage) == "prefilters");
		CHECK(std::string(info("B").stage) == "prefilters");
		CHECK(info("A").level == 5);
		CHECK(info("B").level == 5);

		auto p = plan();
		CHECK(p.size() == 6);
		CHECK(position(p, "PRE") > position(p, "A"));

		/*
		 * The timeouts traversal terminates: the prefilter bucket is either
		 * PRE -> A -> B (3.5) or max(PRE -> A, B) (2.0), the filters chain is 3.0
		 */
		auto t = max_timeout();
		CHECK(t >= 2.0 + 3.0);
		CHECK(t <= 3.5 + 3.0);
	}

	TEST_CASE_FIXTURE(symcache_order_fixture, "hoisted chains are accounted in the prefilter stage timeout")
	{
		add("PRE", 5, SYMBOL_TYPE_PREFILTER, 2.0);
		add("F", 0, SYMBOL_TYPE_NORMAL, 3.0);
		add("OTHER", 0, SYMBOL_TYPE_NORMAL, 1.0);
		depends("PRE", "F");
		init();

		/* Prefilters level 5: PRE waits for F (2 + 3); filters: OTHER (1) */
		CHECK(max_timeout() == doctest::Approx(6.0));
	}

	TEST_CASE_FIXTURE(symcache_order_fixture, "levels are summed and buckets take the longest chain")
	{
		add("PRE_HIGH", 9, SYMBOL_TYPE_PREFILTER, 4.0);
		add("PRE_MED_A", 5, SYMBOL_TYPE_PREFILTER, 2.0);
		add("PRE_MED_B", 5, SYMBOL_TYPE_PREFILTER, 1.0);
		/* Sequential inside the bucket: 1 + 2 */
		depends("PRE_MED_B", "PRE_MED_A");
		add("POST_LOW", 1, SYMBOL_TYPE_POSTFILTER, 1.5);
		add("POST_HIGH", 9, SYMBOL_TYPE_POSTFILTER, 2.5);
		init();

		CHECK(max_timeout() == doctest::Approx(4.0 + 3.0 + 1.5 + 2.5));
	}

	TEST_CASE_FIXTURE(symcache_order_fixture, "symbols registered after init are planned on resort")
	{
		add("PRE", 5, SYMBOL_TYPE_PREFILTER);
		add("F", 0, SYMBOL_TYPE_NORMAL);
		init();

		/* E.g. regexp rules loaded from a map */
		add("LATE_PRE", 9, SYMBOL_TYPE_PREFILTER);
		add("LATE_F", 0, SYMBOL_TYPE_NORMAL);
		add("LATE_POST", 1, SYMBOL_TYPE_POSTFILTER);
		rspamd_symcache_promote_resort(cache);

		/* The dump resorts the cache, which plans the new symbols */
		auto p = plan();
		CHECK(p.size() == 5);
		CHECK(position(p, "LATE_PRE") < position(p, "PRE"));
		CHECK(position(p, "PRE") < position(p, "F"));
		CHECK(position(p, "F") < position(p, "LATE_POST"));

		auto i = info("LATE_PRE");
		CHECK(std::string(i.stage) == "prefilters");
		CHECK(i.level == 9);
		i = info("LATE_F");
		CHECK(std::string(i.stage) == "filters");
		i = info("LATE_POST");
		CHECK(std::string(i.stage) == "postfilters");
		CHECK(i.level == -1);

		/* The old symbols keep their plan */
		i = info("PRE");
		CHECK(i.level == 5);
	}
}

#endif
