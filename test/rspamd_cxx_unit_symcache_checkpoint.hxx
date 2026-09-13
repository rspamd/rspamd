/*
 * Copyright 2026 Vsevolod Stakhov
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef RSPAMD_CXX_UNIT_SYMCACHE_CHECKPOINT_HXX
#define RSPAMD_CXX_UNIT_SYMCACHE_CHECKPOINT_HXX

#include "libserver/task.h"
#include "libserver/rspamd_symcache.h"
#include "libmime/scan_result.h"
#include "lua/lua_common.h"
#include <deque>
#include <string>
#include <vector>
#include <functional>
#include <memory>

namespace {
struct checkpoint_fixture {
	struct callback_data {
		checkpoint_fixture *fixture;
		std::string name;
		bool async;
		struct rspamd_symcache_dynamic_item *item = nullptr;
		std::function<void(struct rspamd_task *)> run{};
		std::function<void(struct rspamd_task *)> complete{};
	};
	struct rspamd_config *cfg = rspamd_config_new(RSPAMD_CONFIG_INIT_DEFAULT);
	struct ev_loop *loop = ev_loop_new(0);
	struct rspamd_task *task = nullptr;
	std::deque<callback_data> callbacks;
	std::vector<std::string> calls;
	static constexpr unsigned int envelope = RSPAMD_SYMCACHE_INPUT_CONNECTION | RSPAMD_SYMCACHE_INPUT_HELO |
											 RSPAMD_SYMCACHE_INPUT_SENDER | RSPAMD_SYMCACHE_INPUT_RECIPIENTS;

	~checkpoint_fixture()
	{
		if (task) {
			rspamd_session_destroy(task->s);
			rspamd_task_free(task);
		}

		rspamd_config_free(cfg);
		ev_loop_destroy(loop);
	}

	static void event_done(gpointer ud)
	{
		auto *cb = static_cast<callback_data *>(ud);
		auto *task = cb->fixture->task;
		auto *saved = rspamd_symcache_set_cur_item(task, cb->item);

		if (cb->complete && !rspamd_session_blocked(task->s)) {
			cb->complete(task);
		}

		rspamd_symcache_item_async_dec_check(cb->fixture->task, cb->item, "checkpoint test");
		rspamd_symcache_set_cur_item(task, saved);
	}

	static void callback(struct rspamd_task *task, struct rspamd_symcache_dynamic_item *item, gpointer ud)
	{
		auto *cb = static_cast<callback_data *>(ud);
		cb->fixture->calls.push_back(cb->name);

		if (cb->run) {
			cb->run(task);
		}

		if (cb->async) {
			cb->item = item;
			rspamd_symcache_item_async_inc(task, item, "checkpoint test");
			rspamd_session_add_event(task->s, event_done, cb, "checkpoint test");
		}
		else {
			rspamd_symcache_finalize_item(task, item);
		}
	}

	void add(const char *name, unsigned int inputs = RSPAMD_SYMCACHE_INPUT_EOM, int type = SYMBOL_TYPE_NORMAL,
			 bool async = false, int priority = 0, unsigned int replay_version = 0)
	{
		callbacks.push_back({this, name, async});
		auto id = rspamd_symcache_add_symbol(cfg->cache, name, priority, callback, &callbacks.back(), type, -1);
		REQUIRE(id >= 0);
		REQUIRE(rspamd_symcache_set_symbol_inputs(cfg->cache, id, inputs));

		if (replay_version) {
			REQUIRE(rspamd_symcache_set_symbol_replay(cfg->cache, id, replay_version));
		}
	}

	void depends(const char *from, const char *to, bool hard = false)
	{
		rspamd_symcache_add_delayed_dependency(cfg->cache, from, to, hard);
	}

	void init()
	{
		REQUIRE(rspamd_symcache_init(cfg->cache));
		new_task();
	}

	void new_task()
	{
		if (task) {
			rspamd_session_destroy(task->s);
			rspamd_task_free(task);
		}

		task = rspamd_task_new(nullptr, cfg, nullptr, nullptr, loop, FALSE);
		task->s = rspamd_session_create(task->task_pool, nullptr, nullptr, nullptr, nullptr);
	}

	void run_lua(const char *source)
	{
		auto *L = RSPAMD_LUA_CFG_STATE(cfg);
		auto **pcfg = static_cast<struct rspamd_config **>(lua_newuserdata(L, sizeof(cfg)));
		*pcfg = cfg;
		rspamd_lua_setclass(L, rspamd_config_classname, -1);
		lua_setglobal(L, "checkpoint_config");
		auto ret = luaL_dostring(L, source);

		if (ret != 0) {
			FAIL(lua_tostring(L, -1));
			lua_pop(L, 1);
		}
	}

	auto checkpoint(unsigned int inputs = envelope)
	{
		return rspamd_symcache_process_checkpoint(task, cfg->cache, inputs);
	}

	void finish_async()
	{
		for (auto &cb: callbacks) {
			if (cb.item) {
				rspamd_session_remove_event(task->s, event_done, &cb);
				cb.item = nullptr;
			}
		}
	}

	void full_scan()
	{
		for (auto stage: {RSPAMD_TASK_STAGE_CONNFILTERS, RSPAMD_TASK_STAGE_PRE_FILTERS, RSPAMD_TASK_STAGE_FILTERS,
						  RSPAMD_TASK_STAGE_POST_FILTERS, RSPAMD_TASK_STAGE_IDEMPOTENT}) {
			REQUIRE(rspamd_symcache_process_symbols(task, cfg->cache, stage));
		}
	}
};
}// namespace

TEST_SUITE("symcache_checkpoint")
{
	TEST_CASE_FIXTURE(checkpoint_fixture, "Lua declarations are validated and conditions remain EOM-only")
	{
		run_lua(R"lua(
local cfg = checkpoint_config
for _, invalid in ipairs({'sender', {'unknown'}, {false}, {sender = true},
    {[0] = 'sender'}, {[1.5] = 'sender'}, {'sender\0body'}}) do
  assert(not pcall(function()
    cfg:register_symbol({name = 'INVALID_INPUT', required_inputs = invalid,
      callback = function() end})
  end))
end
cfg:register_symbol({name = 'LUA_EARLY', required_inputs = {'sender'},
  callback = function(task) task:insert_result('LUA_EARLY', 1) end})
cfg:register_symbol({name = 'LUA_CONDITION', required_inputs = {'sender'},
  condition = function(task)
    condition_calls = (condition_calls or 0) + 1
    return true
  end,
  callback = function(task) task:insert_result('LUA_CONDITION', 1) end})
)lua");
		init();
		REQUIRE(checkpoint() == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		CHECK(rspamd_task_find_symbol_result(task, "LUA_EARLY", nullptr) != nullptr);
		CHECK_FALSE(rspamd_symcache_is_symbol_enabled(task, cfg->cache, "LUA_CONDITION"));
		run_lua("assert(condition_calls == nil)");
		full_scan();
		CHECK(rspamd_task_find_symbol_result(task, "LUA_CONDITION", nullptr) != nullptr);
		run_lua("assert(condition_calls == 1)");
	}

	TEST_CASE_FIXTURE(checkpoint_fixture,
					  "disabled deferred checks can be re-enabled without bypassing input readiness")
	{
		add("BODY", RSPAMD_SYMCACHE_INPUT_BODY);
		init();
		REQUIRE(checkpoint() == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		rspamd_symcache_disable_all_symbols(task, cfg->cache, 0);
		REQUIRE(rspamd_symcache_enable_symbol(task, cfg->cache, "BODY"));
		CHECK_FALSE(rspamd_symcache_is_checked(task, cfg->cache, "BODY"));
		REQUIRE(checkpoint() == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		CHECK(calls.empty());
		full_scan();
		CHECK(calls == std::vector<std::string>{"BODY"});
	}

	TEST_CASE_FIXTURE(checkpoint_fixture, "abort cancels asynchronous work without starting dependents")
	{
		add("DNS", envelope, SYMBOL_TYPE_NORMAL, true);
		add("CONSUMER", envelope);
		depends("CONSUMER", "DNS");
		init();
		REQUIRE(checkpoint() == RSPAMD_SYMCACHE_CHECKPOINT_PENDING);
		rspamd_session_destroy(task->s);
		CHECK(checkpoint() == RSPAMD_SYMCACHE_CHECKPOINT_ERROR);
		CHECK(calls == std::vector<std::string>{"DNS"});
	}

	TEST_CASE_FIXTURE(checkpoint_fixture,
					  "checkpoint preserves content checks for EOM and does not repeat completed checks")
	{
		add("ENVELOPE", envelope);
		add("BODY", RSPAMD_SYMCACHE_INPUT_BODY);
		add("DEPENDENT", envelope);
		add("LEGACY", RSPAMD_SYMCACHE_INPUT_EOM, SYMBOL_TYPE_NORMAL | SYMBOL_TYPE_EMPTY);
		add("POST", 0, SYMBOL_TYPE_POSTFILTER);
		add("OBSERVER", 0, SYMBOL_TYPE_IDEMPOTENT);
		depends("DEPENDENT", "BODY", true);
		init();
		REQUIRE(checkpoint() == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		CHECK(calls == std::vector<std::string>{"ENVELOPE"});
		CHECK(task->message == nullptr);
		CHECK(task->processed_stages == 0);
		CHECK_FALSE(rspamd_symcache_is_checked(task, cfg->cache, "BODY"));
		CHECK_FALSE(rspamd_symcache_is_checked(task, cfg->cache, "DEPENDENT"));
		REQUIRE(checkpoint() == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		CHECK(calls.size() == 1);
		full_scan();
		CHECK(calls.size() == 6);
		CHECK(std::count(calls.begin(), calls.end(), "ENVELOPE") == 1);
		CHECK(std::find(calls.begin(), calls.end(), "BODY") < std::find(calls.begin(), calls.end(), "DEPENDENT"));
		CHECK(checkpoint() == RSPAMD_SYMCACHE_CHECKPOINT_ERROR);
	}

	TEST_CASE_FIXTURE(checkpoint_fixture, "async prerequisite drains before its dependent without completing the task")
	{
		add("DNS", envelope, SYMBOL_TYPE_NORMAL, true);
		add("CONSUMER", envelope);
		depends("CONSUMER", "DNS");
		init();
		REQUIRE(checkpoint() == RSPAMD_SYMCACHE_CHECKPOINT_PENDING);
		CHECK(calls == std::vector<std::string>{"DNS"});
		REQUIRE(checkpoint() == RSPAMD_SYMCACHE_CHECKPOINT_PENDING);
		CHECK(calls.size() == 1);
		CHECK_FALSE(rspamd_symcache_process_symbols(task, cfg->cache, RSPAMD_TASK_STAGE_CONNFILTERS));
		finish_async();
		REQUIRE(checkpoint() == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		CHECK(calls == std::vector<std::string>{"DNS", "CONSUMER"});
		CHECK(task->processed_stages == 0);
		full_scan();
		CHECK(calls.size() == 2);
	}

	TEST_CASE_FIXTURE(checkpoint_fixture, "new input unblocks deferred checks and shrinking input is rejected")
	{
		add("SENDER", RSPAMD_SYMCACHE_INPUT_SENDER);
		add("BODY", RSPAMD_SYMCACHE_INPUT_BODY);
		init();
		REQUIRE(checkpoint() == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		REQUIRE(checkpoint(envelope | RSPAMD_SYMCACHE_INPUT_BODY) == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		CHECK(calls.size() == 2);
		CHECK(checkpoint() == RSPAMD_SYMCACHE_CHECKPOINT_ERROR);
		CHECK(checkpoint(RSPAMD_SYMCACHE_INPUT_ALL) == RSPAMD_SYMCACHE_CHECKPOINT_ERROR);
		CHECK(checkpoint(~0u) == RSPAMD_SYMCACHE_CHECKPOINT_ERROR);
	}

	TEST_CASE_FIXTURE(checkpoint_fixture, "partial score does not suppress remaining early evidence")
	{
		add("FIRST", envelope);
		add("SECOND", envelope);
		depends("SECOND", "FIRST");
		init();
		task->result->score = 1000.0;
		REQUIRE(checkpoint() == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		CHECK(calls == std::vector<std::string>{"FIRST", "SECOND"});
	}

	TEST_CASE_FIXTURE(checkpoint_fixture, "disabling deferred work is preserved when EOM starts")
	{
		add("BODY", RSPAMD_SYMCACHE_INPUT_BODY);
		add("HARD", envelope);
		add("WEAK", envelope);
		depends("HARD", "BODY", true);
		depends("WEAK", "BODY");
		init();
		REQUIRE(checkpoint() == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		REQUIRE(rspamd_symcache_disable_symbol(task, cfg->cache, "BODY"));
		full_scan();
		CHECK(calls == std::vector<std::string>{"WEAK"});
	}
}

#endif
