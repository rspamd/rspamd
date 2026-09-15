/*
 * Copyright 2026 Vsevolod Stakhov
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 */
#ifndef RSPAMD_CXX_UNIT_SYMCACHE_REPLAY_HXX
#define RSPAMD_CXX_UNIT_SYMCACHE_REPLAY_HXX

#include "rspamd_cxx_unit_symcache_checkpoint.hxx"
#include "libserver/symcache/symcache_checkpoint.h"

namespace {
using replay_record = std::unique_ptr<ucl_object_t, decltype(&ucl_object_unref)>;
auto replay_field(ucl_object_t *obj, const char *key) -> ucl_object_t *
{
	return const_cast<ucl_object_t *>(ucl_object_lookup(obj, key));
}

void replay_replace(ucl_object_t *obj, const char *key, ucl_object_t *value)
{
	ucl_object_replace_key(obj, value, key, 0, true);
}

auto replay_copy(const ucl_object_t *obj) -> ucl_object_t *
{
	auto *json = ucl_object_emit(obj, UCL_EMIT_JSON_COMPACT);
	auto *parser = ucl_parser_new(UCL_PARSER_DEFAULT);
	REQUIRE(ucl_parser_add_string(parser, reinterpret_cast<const char *>(json), 0));
	auto *out = ucl_parser_get_object(parser);
	ucl_parser_free(parser);
	free(json);
	return out;
}

auto replay_options(const rspamd_symbol_result *s) -> std::vector<std::string>
{
	std::vector<std::string> out;

	for (auto *opt = s->opts_head; opt; opt = opt->next) {
		out.emplace_back(opt->option, opt->optlen);
	}

	return out;
}
}// namespace

TEST_SUITE("symcache_replay")
{
	TEST_CASE_FIXTURE(checkpoint_fixture, "replay at the normal slot applies EOM scores, shot limits and options")
	{
		add("PRODUCER", envelope, SYMBOL_TYPE_NORMAL, false, 0, 1);
		callbacks.back().run = [](auto *t) {
			auto *s = rspamd_task_insert_result_full(t, "SCORE", 2.0, "inline", RSPAMD_SYMBOL_INSERT_ENFORCE, nullptr);
			rspamd_task_add_result_option(t, s, "later", 5);
			rspamd_task_insert_result_full(t, "SCORE", 0.5, "single", RSPAMD_SYMBOL_INSERT_SINGLE, nullptr);
			replay_record fact{ucl_object_fromstring("pass"), &ucl_object_unref};
			REQUIRE(rspamd_symcache_set_check_fact(t, "result", fact.get()));
		};
		add("SETTINGS", 0, SYMBOL_TYPE_PREFILTER);
		callbacks.back().run = [](auto *t) {
			CHECK(rspamd_task_find_symbol_result(t, "SCORE", nullptr) == nullptr);
			CHECK(rspamd_symcache_get_check_fact(t, "PRODUCER", "result") == nullptr);
			t->settings = ucl_object_typed_new(UCL_OBJECT);
			replay_replace(t->settings, "SCORE", ucl_object_fromdouble(3.0));
		};
		add("CONSUMER");
		callbacks.back().run = [](auto *t) {
			auto *fact = rspamd_symcache_get_check_fact(t, "PRODUCER", "result");
			REQUIRE(fact != nullptr);
			CHECK(std::string(ucl_object_tostring(fact)) == "pass");
		};
		depends("CONSUMER", "PRODUCER", true);
		init();
		REQUIRE(checkpoint() == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		replay_record record{rspamd_symcache_export_checkpoint(task, "transaction-policy"), &ucl_object_unref};
		REQUIRE(record != nullptr);
		CHECK(rspamd_task_find_symbol_result(task, "SCORE", nullptr)->score == 2.0);
		new_task();
		calls.clear();
		REQUIRE(rspamd_symcache_import_checkpoint(task, record.get(), "transaction-policy"));
		CHECK_FALSE(rspamd_symcache_is_checked(task, cfg->cache, "PRODUCER"));
		CHECK(rspamd_symcache_get_check_fact(task, "PRODUCER", "result") == nullptr);
		full_scan();
		CHECK(calls == std::vector<std::string>{"SETTINGS", "CONSUMER"});
		auto *s = rspamd_task_find_symbol_result(task, "SCORE", nullptr);
		REQUIRE(s != nullptr);
		CHECK(s->score == 6.0);
		CHECK(s->nshots == 2);
		auto options = replay_options(s);
		CHECK(options == std::vector<std::string>{"inline", "later", "single"});
		new_task();
		full_scan();
		s = rspamd_task_find_symbol_result(task, "SCORE", nullptr);
		CHECK(s->score == 6.0);
		CHECK(s->nshots == 2);
		CHECK(replay_options(s) == options);
	}

	TEST_CASE_FIXTURE(checkpoint_fixture, "asynchronous empty completion and facts survive a serialized round trip")
	{
		add("EMPTY", envelope, SYMBOL_TYPE_NORMAL, true, 0, 2);
		callbacks.back().complete = [](auto *t) {
			replay_record value{ucl_object_typed_new(UCL_OBJECT), &ucl_object_unref};
			replay_replace(value.get(), "checked", ucl_object_frombool(true));
			replay_replace(value.get(), "ttl", ucl_object_fromint(60));
			REQUIRE(rspamd_symcache_set_check_fact(t, "dns", value.get()));
		};
		init();
		REQUIRE(checkpoint() == RSPAMD_SYMCACHE_CHECKPOINT_PENDING);
		CHECK(rspamd_symcache_export_checkpoint(task, "txn") == nullptr);
		finish_async();
		REQUIRE(checkpoint() == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		replay_record record{rspamd_symcache_export_checkpoint(task, "txn"), &ucl_object_unref};
		REQUIRE(record != nullptr);
		auto *entries = replay_field(record.get(), "checks");
		REQUIRE(entries->len == 1);
		CHECK(ucl_object_lookup(ucl_object_lookup(entries, "EMPTY"), "ops")->len == 0);
		auto *json = ucl_object_emit(record.get(), UCL_EMIT_JSON_COMPACT);
		auto *parser = ucl_parser_new(UCL_PARSER_DEFAULT);
		REQUIRE(ucl_parser_add_string(parser, reinterpret_cast<const char *>(json), 0));
		replay_record parsed{ucl_parser_get_object(parser), &ucl_object_unref};
		ucl_parser_free(parser);
		free(json);
		new_task();
		calls.clear();
		REQUIRE(rspamd_symcache_import_checkpoint(task, parsed.get(), "txn"));
		CHECK(checkpoint() == RSPAMD_SYMCACHE_CHECKPOINT_ERROR);
		full_scan();
		CHECK(calls.empty());
		auto *fact = rspamd_symcache_get_check_fact(task, "EMPTY", "dns");
		REQUIRE(fact != nullptr);
		CHECK(ucl_object_toint(ucl_object_lookup(fact, "ttl")) == 60);
		CHECK(ucl_object_toboolean(ucl_object_lookup(fact, "checked")));
	}

	TEST_CASE_FIXTURE(checkpoint_fixture, "export omits unaudited callbacks and their dependency closure")
	{
		add("UNAUDITED", envelope);
		add("DEPENDENT", envelope, SYMBOL_TYPE_NORMAL, false, 0, 1);
		add("INDEPENDENT", envelope, SYMBOL_TYPE_NORMAL, false, 0, 1);
		depends("DEPENDENT", "UNAUDITED");
		init();
		REQUIRE(checkpoint() == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		replay_record record{rspamd_symcache_export_checkpoint(task, "txn"), &ucl_object_unref};
		REQUIRE(record != nullptr);
		auto *entries = replay_field(record.get(), "checks");
		CHECK(entries->len == 1);
		CHECK(ucl_object_lookup(entries, "INDEPENDENT") != nullptr);
		new_task();
		calls.clear();
		REQUIRE(rspamd_symcache_import_checkpoint(task, record.get(), "txn"));
		full_scan();
		CHECK(calls == std::vector<std::string>{"UNAUDITED", "DEPENDENT"});
	}

	TEST_CASE_FIXTURE(checkpoint_fixture, "EOM-disabled prerequisite forces a weak dependent to run again")
	{
		add("PREREQUISITE", envelope, SYMBOL_TYPE_NORMAL, false, 0, 1);
		add("DEPENDENT", envelope, SYMBOL_TYPE_NORMAL, false, 0, 1);
		depends("DEPENDENT", "PREREQUISITE");
		init();
		REQUIRE(checkpoint() == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		replay_record record{rspamd_symcache_export_checkpoint(task, "txn"), &ucl_object_unref};
		REQUIRE(record != nullptr);
		new_task();
		calls.clear();
		REQUIRE(rspamd_symcache_import_checkpoint(task, record.get(), "txn"));
		REQUIRE(rspamd_symcache_disable_symbol(task, cfg->cache, "PREREQUISITE"));
		full_scan();
		CHECK(calls == std::vector<std::string>{"DEPENDENT"});
	}

	TEST_CASE_FIXTURE(checkpoint_fixture,
					  "incompatible and malformed records fail atomically and permit normal scanning")
	{
		add("FIRST", envelope, SYMBOL_TYPE_NORMAL, false, 0, 1);
		callbacks.back().run = [](auto *t) {
			rspamd_task_insert_result(t, "SCORE", 1, "option");
		};
		add("SECOND", envelope, SYMBOL_TYPE_NORMAL, false, 0, 1);
		depends("SECOND", "FIRST", true);
		init();
		REQUIRE(checkpoint() == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		replay_record record{rspamd_symcache_export_checkpoint(task, "txn"), &ucl_object_unref};
		REQUIRE(record != nullptr);
		std::vector<std::function<void(ucl_object_t *)>> corruptions = {
			[](auto *r) {
				replay_replace(r, "format", ucl_object_fromint(2));
			},
			[](auto *r) {
				replay_replace(r, "binding", ucl_object_fromstring("other"));
			},
			[](auto *r) {
				replay_replace(r, "configuration", ucl_object_fromstring("other"));
			},
			[](auto *r) {
				replay_replace(replay_field(replay_field(r, "checks"), "FIRST"), "version", ucl_object_fromint(2));
			},
			[](auto *r) {
				replay_replace(replay_field(replay_field(r, "checks"), "FIRST"), "inputs",
							   ucl_object_fromint(RSPAMD_SYMCACHE_INPUT_ALL));
			},
			[](auto *r) {
				ucl_object_delete_key(replay_field(r, "checks"), "FIRST");
			},
			[](auto *r) {
				replay_replace(replay_field(r, "checks"), "UNKNOWN", ucl_object_typed_new(UCL_OBJECT));
			},
			[](auto *r) {
				auto *ops = replay_field(replay_field(replay_field(r, "checks"), "FIRST"), "ops");
				replay_replace(const_cast<ucl_object_t *>(ucl_array_find_index(ops, 0)), "weight",
							   ucl_object_fromdouble(NAN));
			},
			[](auto *r) {
				auto *ops = replay_field(replay_field(replay_field(r, "checks"), "FIRST"), "ops");
				auto *bad = ucl_object_typed_new(UCL_OBJECT);
				replay_replace(bad, "insert", ucl_object_fromint(100));
				replay_replace(bad, "option", ucl_object_fromstring("invalid"));
				ucl_array_append(ops, bad);
			},
		};

		for (const auto &corrupt: corruptions) {
			new_task();
			calls.clear();
			replay_record bad{replay_copy(record.get()), &ucl_object_unref};
			corrupt(bad.get());
			CHECK_FALSE(rspamd_symcache_import_checkpoint(task, bad.get(), "txn"));
			CHECK(rspamd_task_find_symbol_result(task, "SCORE", nullptr) == nullptr);
			CHECK_FALSE(rspamd_symcache_is_checked(task, cfg->cache, "FIRST"));
			full_scan();
			CHECK(calls == std::vector<std::string>{"FIRST", "SECOND"});
		}

		new_task();
		REQUIRE(rspamd_symcache_import_checkpoint(task, record.get(), "txn"));
		CHECK_FALSE(rspamd_symcache_import_checkpoint(task, record.get(), "txn"));
		full_scan();
		CHECK_FALSE(rspamd_symcache_import_checkpoint(task, record.get(), "txn"));
	}

	TEST_CASE_FIXTURE(checkpoint_fixture, "unsupported writes and oversized journals fall back to execution")
	{
		add("UNSAFE", envelope, SYMBOL_TYPE_NORMAL, false, 0, 1);
		callbacks.back().run = [](auto *t) {
			rspamd_task_insert_result(t, "SCORE", 1, nullptr);
			rspamd_task_remove_symbol_result(t, "SCORE", nullptr);
		};
		init();
		REQUIRE(checkpoint() == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		CHECK(rspamd_symcache_export_checkpoint(task, "txn") == nullptr);
		new_task();
		callbacks.back().run = [](auto *t) {
			std::string large(65536, 'x');
			rspamd_task_insert_result(t, "SCORE", 1, large.c_str());
		};
		REQUIRE(checkpoint() == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		CHECK(rspamd_symcache_export_checkpoint(task, "txn") == nullptr);
	}

	TEST_CASE_FIXTURE(checkpoint_fixture, "Lua producers capture options and require an explicit version")
	{
		run_lua(R"lua(
for _, v in ipairs({0, -1, 0.5, '1', math.huge}) do
  assert(not pcall(function()
    checkpoint_config:register_symbol({name = 'INVALID_REPLAY', replay_version = v,
      callback = function() end})
  end))
end
checkpoint_config:register_symbol({name = 'LUA_REPLAY', required_inputs = {'sender'},
  replay_version = 1, callback = function(task)
    replay_calls = (replay_calls or 0) + 1
    task:insert_result('LUA_REPLAY', 1, 'first', {'second', 'third'})
    local fact = {status = 'pass', domains = {'a.example', 'b.example'}, raw = 'a\0b'}
    assert(task:set_check_fact('spf', fact))
    fact.status = 'modified'
    local readback = task:get_check_fact('LUA_REPLAY', 'spf')
    assert(readback.status == 'pass' and readback.raw == 'a\0b')
    readback.status = 'modified'
    assert(task:get_check_fact('LUA_REPLAY', 'spf').status == 'pass')
    local cyclic = {}; cyclic.self = cyclic
    for _, invalid in ipairs({cyclic, {function() end}, {[2] = 'sparse'},
        {[1] = 'mixed', other = true}, setmetatable({}, {}), math.huge}) do
      assert(not pcall(function() task:set_check_fact('invalid', invalid) end))
    end
  end})
checkpoint_config:register_symbol({name = 'LUA_FACT_CONSUMER', callback = function(task)
  local fact = task:get_check_fact('LUA_REPLAY', 'spf')
  assert(fact.status == 'pass' and fact.raw == 'a\0b' and fact.domains[2] == 'b.example')
  fact_consumed = true
end})
checkpoint_config:register_dependency('LUA_FACT_CONSUMER', 'LUA_REPLAY')
)lua");
		init();
		REQUIRE(checkpoint() == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		replay_record record{rspamd_symcache_export_checkpoint(task, "txn"), &ucl_object_unref};
		REQUIRE(record != nullptr);
		new_task();
		REQUIRE(rspamd_symcache_import_checkpoint(task, record.get(), "txn"));
		full_scan();
		run_lua("assert(replay_calls == 1 and fact_consumed)");
		auto *s = rspamd_task_find_symbol_result(task, "LUA_REPLAY", nullptr);
		REQUIRE(s != nullptr);
		CHECK(replay_options(s) == std::vector<std::string>{"first", "second", "third"});
	}

	TEST_CASE_FIXTURE(checkpoint_fixture, "synchronous replay restores state before dependent callbacks")
	{
		run_lua(R"lua(
producer_calls, restore_calls, consumed = 0, 0, false
checkpoint_config:register_symbol {
  name = 'RESTORED', required_inputs = {'sender'}, replay_version = 1,
  callback = function(task)
    producer_calls = producer_calls + 1
    task:insert_result('RESTORED', 1, 'original')
    task:set_check_fact('state', {result = 'pass'})
    task:get_mempool():set_variable('restored', 'pass')
  end,
  replay_callback = function(task, facts)
    restore_calls = restore_calls + 1
    assert(not task:has_symbol('RESTORED'))
    assert(not task:get_check_fact('RESTORED', 'state'))
    assert(facts.state.result == 'pass')
    task:get_mempool():set_variable('restored', facts.state.result)
    facts.state.result = 'changed copy'
    return true
  end,
}
checkpoint_config:register_symbol {
  name = 'RESTORED_CONSUMER', callback = function(task)
    consumed = task:get_mempool():get_variable('restored') == 'pass' and
        task:get_check_fact('RESTORED', 'state').result == 'pass' and
        task:has_symbol('RESTORED')
  end,
}
checkpoint_config:register_dependency('RESTORED_CONSUMER', 'RESTORED')
)lua");
		init();
		REQUIRE(checkpoint() == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		run_lua("assert(producer_calls == 1 and restore_calls == 0 and not consumed)");
		replay_record record{rspamd_symcache_export_checkpoint(task, "txn"), &ucl_object_unref};
		REQUIRE(record != nullptr);
		new_task();
		REQUIRE(rspamd_symcache_import_checkpoint(task, record.get(), "txn"));
		full_scan();
		run_lua("assert(producer_calls == 1 and restore_calls == 1 and consumed)");
		new_task();
		REQUIRE(rspamd_symcache_import_checkpoint(task, record.get(), "txn"));
		REQUIRE(rspamd_symcache_disable_symbol(task, cfg->cache, "RESTORED"));
		full_scan();
		run_lua("assert(producer_calls == 1 and restore_calls == 1)");
		new_task();
		full_scan();
		run_lua("assert(producer_calls == 2 and restore_calls == 1 and consumed)");
	}

	TEST_CASE_FIXTURE(checkpoint_fixture, "rejected replay runs the producer and dependent without stale evidence")
	{
		run_lua(R"lua(
producer_calls, dependent_calls, restore_calls = 0, 0, 0
checkpoint_config:register_symbol {
  name = 'VALIDATED', required_inputs = {'sender'}, replay_version = 1,
  callback = function(task)
    producer_calls = producer_calls + 1
    assert(not task:has_symbol('STALE'))
    assert(not task:get_check_fact('VALIDATED', 'state'))
    task:insert_result(producer_calls == 1 and 'STALE' or 'FRESH', 1)
    task:set_check_fact('state', 'complete')
  end,
  replay_callback = function()
    restore_calls = restore_calls + 1

    if restore_calls == 1 then
      return false
    elseif restore_calls == 2 then
      error('deliberate restoration failure')
    end

    return 'truthy is not true'
  end,
}
checkpoint_config:register_symbol {
  name = 'VALIDATED_DEPENDENT', required_inputs = {'sender'}, replay_version = 1,
  callback = function() dependent_calls = dependent_calls + 1 end,
}
checkpoint_config:register_dependency('VALIDATED_DEPENDENT', 'VALIDATED')
)lua");
		init();
		REQUIRE(checkpoint() == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		replay_record record{rspamd_symcache_export_checkpoint(task, "txn"), &ucl_object_unref};
		REQUIRE(record != nullptr);

		for (int i = 0; i < 3; i++) {
			new_task();
			REQUIRE(rspamd_symcache_import_checkpoint(task, record.get(), "txn"));
			full_scan();
			CHECK(rspamd_task_find_symbol_result(task, "STALE", nullptr) == nullptr);
			CHECK(rspamd_task_find_symbol_result(task, "FRESH", nullptr) != nullptr);
		}

		run_lua("assert(producer_calls == 4 and dependent_calls == 4 and restore_calls == 3)");
	}

	TEST_CASE_FIXTURE(checkpoint_fixture, "replay callbacks require a version and a function")
	{
		run_lua(R"lua(
for _, options in ipairs({
    {replay_callback = function() end},
    {replay_callback = true, replay_version = 1},
    {replay_callback = 'invalid', replay_version = 1},
}) do
  options.name = 'INVALID_RESTORATION'
  options.callback = function() end
  assert(not pcall(checkpoint_config.register_symbol, checkpoint_config, options))
end
)lua");
	}

	TEST_CASE_FIXTURE(checkpoint_fixture, "Lua failure cannot be exported as a successful empty check")
	{
		run_lua(R"lua(
checkpoint_config:register_symbol({name = 'LUA_FAILURE', required_inputs = {'sender'},
  replay_version = 1, callback = function(task)
    task:insert_result('PARTIAL', 1)
    error('deliberate replay regression')
  end})
)lua");
		init();
		REQUIRE(checkpoint() == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		CHECK(rspamd_symcache_export_checkpoint(task, "txn") == nullptr);
	}

	TEST_CASE_FIXTURE(checkpoint_fixture, "EOM policy can suppress a producer without publishing its evidence")
	{
		add("EARLY", envelope, SYMBOL_TYPE_NORMAL, false, 0, 1);
		callbacks.back().run = [](auto *t) {
			rspamd_task_insert_result(t, "EVIDENCE", 1, nullptr);
		};
		add("POLICY", 0, SYMBOL_TYPE_PREFILTER);
		callbacks.back().run = [](auto *t) {
			REQUIRE(rspamd_symcache_disable_symbol(t, t->cfg->cache, "EARLY"));
		};
		init();
		REQUIRE(checkpoint() == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		replay_record record{rspamd_symcache_export_checkpoint(task, "txn"), &ucl_object_unref};
		REQUIRE(record != nullptr);
		new_task();
		calls.clear();
		REQUIRE(rspamd_symcache_import_checkpoint(task, record.get(), "txn"));
		full_scan();
		CHECK(calls == std::vector<std::string>{"POLICY"});
		CHECK(rspamd_task_find_symbol_result(task, "EVIDENCE", nullptr) == nullptr);
	}

	TEST_CASE_FIXTURE(checkpoint_fixture, "portable producer names do not depend on scanner-local IDs")
	{
		add("A", envelope, SYMBOL_TYPE_NORMAL, false, 0, 1);
		add("B", envelope, SYMBOL_TYPE_NORMAL, false, 0, 1);
		depends("B", "A", true);
		init();
		REQUIRE(checkpoint() == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		replay_record record{rspamd_symcache_export_checkpoint(task, "txn"), &ucl_object_unref};
		REQUIRE(record != nullptr);
		checkpoint_fixture remote;
		remote.add("B", envelope, SYMBOL_TYPE_NORMAL, false, 0, 1);
		remote.add("A", envelope, SYMBOL_TYPE_NORMAL, false, 0, 1);
		remote.depends("B", "A", true);
		remote.init();
		CHECK(rspamd_symcache_find_symbol(cfg->cache, "A") != rspamd_symcache_find_symbol(remote.cfg->cache, "A"));
		REQUIRE(rspamd_symcache_import_checkpoint(remote.task, record.get(), "txn"));
		remote.full_scan();
		CHECK(remote.calls.empty());
	}

	TEST_CASE_FIXTURE(checkpoint_fixture, "provisional insertions do not double-count symbol hits")
	{
		run_lua(R"lua(
checkpoint_config:register_symbol({name = 'COUNTED', score = 1, required_inputs = {'sender'},
  replay_version = 1, callback = function(task) task:insert_result('COUNTED', 1) end})
)lua");
		init();
		REQUIRE(rspamd_symcache_validate(cfg->cache, cfg, false));
		auto hits = [&]() {
			double frequency, deviation, time;
			unsigned int count;
			REQUIRE(rspamd_symcache_stat_symbol(cfg->cache, "COUNTED", &frequency, &deviation, &time, &count));
			return count;
		};
		auto before = hits();
		REQUIRE(checkpoint() == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		CHECK(hits() == before);
		replay_record record{rspamd_symcache_export_checkpoint(task, "txn"), &ucl_object_unref};
		REQUIRE(record != nullptr);
		new_task();
		REQUIRE(rspamd_symcache_import_checkpoint(task, record.get(), "txn"));
		full_scan();
		CHECK(hits() == before + 1);
		new_task();
		REQUIRE(checkpoint() == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		CHECK(hits() == before + 1);
		full_scan();
		CHECK(hits() == before + 2);
	}
}

#endif
