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
 * Precise per-item timings of the symcache runtime. A real task is driven
 * through rspamd_symcache_process_symbols with C callbacks and the fake
 * monotonic clock, so every number is deterministic.
 */

#ifndef RSPAMD_CXX_UNIT_SYMCACHE_PROFILE_HXX
#define RSPAMD_CXX_UNIT_SYMCACHE_PROFILE_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "libserver/async_session.h"
#include "libserver/cfg_file.h"
#include "libserver/rspamd_symcache.h"
#include "libserver/task.h"
#include "libutil/util.h"
#include "rspamd_test_fake_time.hxx"

#include <map>
#include <string>
#include <vector>

namespace {

struct profile_cb_data {
	rspamd_test::fake_clock *clock = nullptr;
	/* Time spent in the synchronous part of the callback, seconds */
	double sync_time = 0.0;
	/* Asynchronous items keep their event open and remember the item */
	bool async = false;
	struct rspamd_symcache_dynamic_item *item = nullptr;
	struct rspamd_task *task = nullptr;
	/* Release the symcache item when the session finishes the event */
	bool dec_on_fin = false;
};

static void
profile_event_fin(gpointer ud)
{
	auto *cbd = static_cast<profile_cb_data *>(ud);

	if (cbd->dec_on_fin && cbd->item != nullptr) {
		auto *item = cbd->item;
		cbd->item = nullptr;
		rspamd_symcache_item_async_dec_check(cbd->task, item, "unit-test");
	}
}

static void
profile_callback(struct rspamd_task *task, struct rspamd_symcache_dynamic_item *item, gpointer ud)
{
	auto *cbd = static_cast<profile_cb_data *>(ud);

	rspamd_symcache_item_async_inc(task, item, "unit-test");
	cbd->clock->advance(cbd->sync_time);

	if (cbd->async) {
		/* A real asynchronous request keeps an event in the session */
		rspamd_session_add_event(task->s, profile_event_fin, cbd, "unit-test");
		cbd->item = item;
		cbd->task = task;
		return;
	}

	rspamd_symcache_item_async_dec_check(task, item, "unit-test");
}

static gboolean
profile_session_fin(gpointer ud)
{
	return TRUE;
}

struct profile_entry {
	double time_ms;
	double sync_time_ms;
	unsigned int flags;
};

static void
profile_collect_cb(struct rspamd_task *task, const struct rspamd_symcache_profile_entry *entry, gpointer ud)
{
	auto *out = static_cast<std::vector<std::pair<std::string, profile_entry>> *>(ud);

	out->emplace_back(entry->symbol, profile_entry{entry->time_ms, entry->sync_time_ms, entry->flags});
}

struct symcache_profile_fixture {
	rspamd_test::fake_clock clock{1000.0};
	struct rspamd_config *cfg = nullptr;
	struct rspamd_symcache *cache = nullptr;
	struct ev_loop *loop = nullptr;
	struct rspamd_task *task = nullptr;
	std::map<std::string, profile_cb_data> cbdata;

	symcache_profile_fixture()
	{
		cfg = rspamd_config_new(RSPAMD_CONFIG_INIT_DEFAULT);
		REQUIRE(cfg != nullptr);
		cache = rspamd_symcache_new(cfg);
		REQUIRE(cache != nullptr);
		cfg->cache = cache;
		loop = ev_loop_new(EVFLAG_AUTO);
		REQUIRE(loop != nullptr);
	}

	~symcache_profile_fixture()
	{
		if (task != nullptr) {
			rspamd_task_free(task);
		}
		/* The cache is owned here, not by the config */
		cfg->cache = nullptr;
		rspamd_symcache_destroy(cache);
		rspamd_config_free(cfg);
		ev_loop_destroy(loop);
	}

	int add(const char *name, double sync_time, bool async = false, int type = SYMBOL_TYPE_NORMAL)
	{
		auto &cbd = cbdata[name];
		cbd.clock = &clock;
		cbd.sync_time = sync_time;
		cbd.async = async;

		return rspamd_symcache_add_symbol(cache, name, 0, profile_callback, &cbd, type, -1);
	}

	/* The first group is the main one, the others are secondary memberships */
	void add_to_group(const char *name, const char *group)
	{
		if (g_hash_table_lookup(cfg->symbols, name) == nullptr) {
			rspamd_config_add_symbol(cfg, name, 1.0, "test", group, 0, 0, 1);
		}
		else {
			rspamd_config_add_symbol_group(cfg, name, group);
		}
	}

	void init()
	{
		REQUIRE(rspamd_symcache_init(cache));
	}

	void make_task(unsigned int extra_flags = 0)
	{
		task = rspamd_task_new(nullptr, cfg, nullptr, nullptr, loop, FALSE);
		task->flags |= extra_flags;
		task->s = rspamd_session_create(task->task_pool, profile_session_fin, nullptr, nullptr, task);
	}

	bool run_filters()
	{
		return rspamd_symcache_process_symbols(task, cache, RSPAMD_TASK_STAGE_FILTERS);
	}

	std::vector<std::pair<std::string, profile_entry>> report(bool all)
	{
		std::vector<std::pair<std::string, profile_entry>> out;
		auto n = rspamd_symcache_profile_foreach(task, all ? TRUE : FALSE, profile_collect_cb, &out);

		CHECK(n == out.size());

		return out;
	}
};

}// namespace

TEST_SUITE("symcache_profile")
{
	TEST_CASE("sync item reports its callback time")
	{
		symcache_profile_fixture fx;

		fx.add("SYNC_A", 0.25);
		fx.cfg->cache = fx.cache;
		rspamd_symcache_add_profiled_symbol(fx.cache, "SYNC_A");
		fx.init();
		fx.make_task();

		CHECK(fx.run_filters());

		auto rep = fx.report(false);
		REQUIRE(rep.size() == 1);
		CHECK(rep[0].first == "SYNC_A");
		CHECK(rep[0].second.time_ms == doctest::Approx(250.0));
		CHECK(rep[0].second.sync_time_ms == doctest::Approx(250.0));
		CHECK(rep[0].second.flags == 0);
	}

	TEST_CASE("async item reports total time and the synchronous part")
	{
		symcache_profile_fixture fx;

		fx.add("ASYNC_A", 0.05, true);
		rspamd_symcache_add_profiled_symbol(fx.cache, "ASYNC_A");
		fx.init();
		fx.make_task();

		/* The item is pending: not finished, but it belongs to the current stage */
		CHECK_FALSE(fx.run_filters());
		CHECK(fx.report(false).empty());

		fx.clock.advance(0.45);
		auto &cbd = fx.cbdata["ASYNC_A"];
		REQUIRE(cbd.item != nullptr);
		CHECK(rspamd_symcache_item_async_dec_check(fx.task, cbd.item, "unit-test"));

		auto rep = fx.report(false);
		REQUIRE(rep.size() == 1);
		CHECK(rep[0].second.time_ms == doctest::Approx(500.0));
		CHECK(rep[0].second.sync_time_ms == doctest::Approx(50.0));
		CHECK(rep[0].second.sync_time_ms < rep[0].second.time_ms);
		CHECK(rep[0].second.flags == RSPAMD_SYMCACHE_PROFILE_ASYNC);
	}

	TEST_CASE("an item finished by forced session cleanup is aborted")
	{
		symcache_profile_fixture fx;

		fx.add("ABORTED_A", 0.05, true);
		rspamd_symcache_add_profiled_symbol(fx.cache, "ABORTED_A");
		fx.init();
		fx.make_task();
		fx.cbdata["ABORTED_A"].dec_on_fin = true;

		CHECK_FALSE(fx.run_filters());
		fx.clock.advance(0.45);
		/* What rspamd_task_timeout does: finish pending events by force */
		rspamd_session_cleanup(fx.task->s, true);

		auto rep = fx.report(false);
		REQUIRE(rep.size() == 1);
		CHECK(rep[0].second.flags == (RSPAMD_SYMCACHE_PROFILE_ASYNC | RSPAMD_SYMCACHE_PROFILE_ABORTED));
		CHECK(rep[0].second.time_ms == doctest::Approx(500.0));
		CHECK(rep[0].second.sync_time_ms == doctest::Approx(50.0));
	}

	TEST_CASE("a hanging item of an earlier stage is reported as unfinished")
	{
		symcache_profile_fixture fx;

		fx.add("HANGING", 0.01, true);
		rspamd_symcache_add_profiled_symbol(fx.cache, "HANGING");
		fx.init();
		fx.make_task();

		fx.run_filters();
		/* Same stage: the item is merely in flight */
		CHECK(fx.report(false).empty());

		fx.clock.advance(2.0);
		rspamd_symcache_process_symbols(fx.task, fx.cache, RSPAMD_TASK_STAGE_POST_FILTERS);

		auto rep = fx.report(false);
		REQUIRE(rep.size() == 1);
		CHECK(rep[0].second.flags == (RSPAMD_SYMCACHE_PROFILE_ASYNC | RSPAMD_SYMCACHE_PROFILE_UNFINISHED));
		CHECK(rep[0].second.time_ms == doctest::Approx(2010.0));
		CHECK(rep[0].second.sync_time_ms == doctest::Approx(10.0));
	}

	TEST_CASE("unselected items are absent, also with all, when not timed")
	{
		symcache_profile_fixture fx;

		fx.add("SELECTED", 0.01);
		fx.add("OTHER", 0.02);
		rspamd_symcache_add_profiled_symbol(fx.cache, "SELECTED");
		fx.init();
		fx.make_task();

		CHECK(fx.run_filters());

		auto rep = fx.report(false);
		REQUIRE(rep.size() == 1);
		CHECK(rep[0].first == "SELECTED");

		/* `all` reports only items that were timed: the other one was not */
		CHECK(fx.report(true).size() == 1);
	}

	TEST_CASE("a task without selected items has no timings")
	{
		symcache_profile_fixture fx;

		fx.add("PLAIN", 0.01);
		fx.init();
		fx.make_task();

		CHECK(fx.run_filters());
		CHECK(fx.report(false).empty());
		CHECK(fx.report(true).empty());
	}

	TEST_CASE("an unselected item is absent on a task without the profile flag")
	{
		symcache_profile_fixture fx;

		fx.add("SELECTED", 0.01);
		fx.add("OTHER", 0.02);
		rspamd_symcache_add_profiled_symbol(fx.cache, "SELECTED");
		fx.init();
		fx.make_task();
		CHECK(fx.run_filters());

		auto rep = fx.report(true);
		REQUIRE(rep.size() == 1);
		CHECK(rep[0].first == "SELECTED");
	}

	TEST_CASE("a dependent started inside the parent callback does not inflate it")
	{
		symcache_profile_fixture fx;

		fx.add("SYNC_PARENT", 0.01);
		fx.add("SYNC_CHILD", 0.2);
		fx.add("ASYNC_CHILD", 0.03, true);
		fx.cfg->cache = fx.cache;
		for (const auto *n: {"SYNC_PARENT", "SYNC_CHILD", "ASYNC_CHILD"}) {
			rspamd_symcache_add_profiled_symbol(fx.cache, n);
		}
		rspamd_symcache_add_delayed_dependency(fx.cache, "SYNC_CHILD", "SYNC_PARENT", FALSE);
		rspamd_symcache_add_delayed_dependency(fx.cache, "ASYNC_CHILD", "SYNC_PARENT", FALSE);
		fx.init();
		fx.make_task();

		/* The async child is still pending */
		CHECK_FALSE(fx.run_filters());
		fx.clock.advance(0.1);
		auto &cbd = fx.cbdata["ASYNC_CHILD"];
		REQUIRE(cbd.item != nullptr);
		CHECK(rspamd_symcache_item_async_dec_check(fx.task, cbd.item, "unit-test"));

		std::map<std::string, profile_entry> by_name;
		for (const auto &[name, e]: fx.report(false)) {
			by_name[name] = e;
		}
		REQUIRE(by_name.size() == 3);
		CHECK(by_name["SYNC_PARENT"].time_ms == doctest::Approx(10.0));
		CHECK(by_name["SYNC_PARENT"].sync_time_ms == doctest::Approx(10.0));
		CHECK(by_name["SYNC_PARENT"].flags == 0);
		CHECK(by_name["SYNC_CHILD"].time_ms == doctest::Approx(200.0));
		CHECK(by_name["SYNC_CHILD"].flags == 0);
		CHECK(by_name["ASYNC_CHILD"].sync_time_ms == doctest::Approx(30.0));
		CHECK(by_name["ASYNC_CHILD"].time_ms == doctest::Approx(130.0));
		CHECK(by_name["ASYNC_CHILD"].flags == RSPAMD_SYMCACHE_PROFILE_ASYNC);
	}

	TEST_CASE("clock reads happen only for tasks that time items")
	{
		{
			symcache_profile_fixture fx;

			fx.add("PLAIN_A", 0.01);
			fx.add("PLAIN_B", 0.01);
			fx.init();
			fx.make_task();

			auto before = fx.clock.reads();
			CHECK(fx.run_filters());
			CHECK(fx.clock.reads() == before);
			CHECK_FALSE(rspamd_symcache_has_profile(fx.task));
		}
		{
			symcache_profile_fixture fx;

			fx.add("SEL", 0.01);
			fx.add("UNSEL_A", 0.01);
			fx.add("UNSEL_B", 0.01);
			rspamd_symcache_add_profiled_symbol(fx.cache, "SEL");
			fx.init();
			fx.make_task();

			auto before = fx.clock.reads();
			CHECK(fx.run_filters());
			/* Runtime base, item start and item end: nothing for unselected items */
			CHECK(fx.clock.reads() - before == 3);
			CHECK(rspamd_symcache_has_profile(fx.task));
		}
	}

	TEST_CASE("the profile flag times every executed item")
	{
		symcache_profile_fixture fx;

		fx.add("ITEM_A", 0.01);
		fx.add("ITEM_B", 0.02);
		fx.add("ITEM_C", 0.03);
		fx.init();
		fx.make_task(RSPAMD_TASK_FLAG_PROFILE);

		CHECK(fx.run_filters());

		auto rep = fx.report(true);
		REQUIRE(rep.size() == 3);

		std::map<std::string, double> times;
		for (const auto &[name, e]: rep) {
			times[name] = e.time_ms;
		}

		CHECK(times["ITEM_A"] == doctest::Approx(10.0));
		CHECK(times["ITEM_B"] == doctest::Approx(20.0));
		CHECK(times["ITEM_C"] == doctest::Approx(30.0));
		/* Nothing is selected, so the selective view is empty */
		CHECK(fx.report(false).empty());
	}

	TEST_CASE("a virtual child and its group select the parent once")
	{
		symcache_profile_fixture fx;

		auto parent = fx.add("PARENT_CB", 0.1);
		rspamd_symcache_add_symbol(fx.cache, "VIRT_CHILD", 0, nullptr, nullptr, SYMBOL_TYPE_VIRTUAL, parent);
		fx.add_to_group("VIRT_CHILD", "unit_group");
		/* The group of a secondary membership is selected as well */
		fx.add_to_group("VIRT_CHILD", "unit_second_group");

		rspamd_symcache_add_profiled_symbol(fx.cache, "VIRT_CHILD");
		rspamd_symcache_add_profiled_group(fx.cache, "unit_group");
		rspamd_symcache_add_profiled_group(fx.cache, "unit_second_group");
		fx.init();
		fx.make_task();

		CHECK(fx.run_filters());

		auto rep = fx.report(false);
		REQUIRE(rep.size() == 1);
		CHECK(rep[0].first == "PARENT_CB");
		CHECK(rep[0].second.time_ms == doctest::Approx(100.0));
	}

	TEST_CASE("a secondary group selects its symbols")
	{
		symcache_profile_fixture fx;

		fx.add("GROUPED", 0.01);
		fx.add("UNGROUPED", 0.01);
		fx.add_to_group("GROUPED", "first_group");
		fx.add_to_group("GROUPED", "second_group");
		rspamd_symcache_add_profiled_group(fx.cache, "second_group");
		fx.init();
		fx.make_task();

		CHECK(fx.run_filters());

		auto rep = fx.report(false);
		REQUIRE(rep.size() == 1);
		CHECK(rep[0].first == "GROUPED");
	}

	TEST_CASE("unknown names select nothing")
	{
		symcache_profile_fixture fx;

		fx.add("KNOWN", 0.01);
		rspamd_symcache_add_profiled_symbol(fx.cache, "NO_SUCH_SYMBOL");
		rspamd_symcache_add_profiled_group(fx.cache, "no_such_group");
		fx.init();
		fx.make_task();

		CHECK(fx.run_filters());
		CHECK(fx.report(false).empty());
		CHECK(fx.report(true).empty());
	}

	TEST_CASE("a request after init resolves immediately")
	{
		symcache_profile_fixture fx;

		fx.add("LATE", 0.01);
		fx.init();
		rspamd_symcache_add_profiled_symbol(fx.cache, "LATE");
		fx.make_task();

		CHECK(fx.run_filters());
		CHECK(fx.report(false).size() == 1);
	}

	TEST_CASE("a symbol registered after init is covered")
	{
		symcache_profile_fixture fx;

		fx.add("EARLY", 0.01);
		rspamd_symcache_add_profiled_symbol(fx.cache, "DYNAMIC");
		fx.init();

		fx.add("DYNAMIC", 0.02);
		rspamd_symcache_promote_resort(fx.cache);
		fx.make_task();

		CHECK(fx.run_filters());

		auto rep = fx.report(false);
		REQUIRE(rep.size() == 1);
		CHECK(rep[0].first == "DYNAMIC");
	}

	TEST_CASE("a disabled item is absent")
	{
		symcache_profile_fixture fx;

		fx.add("DISABLED_ONE", 0.01);
		fx.add("ENABLED_ONE", 0.01);
		rspamd_symcache_add_profiled_symbol(fx.cache, "DISABLED_ONE");
		rspamd_symcache_add_profiled_symbol(fx.cache, "ENABLED_ONE");
		fx.init();
		fx.make_task();

		/* The runtime is created by the first processed stage */
		CHECK(rspamd_symcache_process_symbols(fx.task, fx.cache, RSPAMD_TASK_STAGE_PRE_FILTERS));
		CHECK(rspamd_symcache_disable_symbol(fx.task, fx.cache, "DISABLED_ONE"));
		CHECK(fx.run_filters());

		auto rep = fx.report(false);
		REQUIRE(rep.size() == 1);
		CHECK(rep[0].first == "ENABLED_ONE");
	}

	TEST_CASE("a task without a runtime reports nothing")
	{
		symcache_profile_fixture fx;

		fx.add("NEVER_RUN", 0.01);
		rspamd_symcache_add_profiled_symbol(fx.cache, "NEVER_RUN");
		fx.init();
		fx.make_task();

		std::vector<std::pair<std::string, profile_entry>> out;
		CHECK(rspamd_symcache_profile_foreach(fx.task, TRUE, profile_collect_cb, &out) == 0);
		CHECK(out.empty());
	}

	TEST_CASE("long times saturate instead of wrapping")
	{
		symcache_profile_fixture fx;

		/* More than 2^32 microseconds (about 4295 s) */
		fx.add("VERY_SLOW", 6000.0);
		rspamd_symcache_add_profiled_symbol(fx.cache, "VERY_SLOW");
		fx.init();
		fx.make_task();

		CHECK(fx.run_filters());

		auto rep = fx.report(false);
		REQUIRE(rep.size() == 1);
		CHECK(rep[0].second.time_ms == doctest::Approx(4294967.295));
		CHECK(rep[0].second.sync_time_ms == doctest::Approx(4294967.295));
	}
}

#endif
