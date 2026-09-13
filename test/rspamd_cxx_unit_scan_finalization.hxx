/*
 * Copyright 2026 Vsevolod Stakhov
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 */
#ifndef RSPAMD_CXX_UNIT_SCAN_FINALIZATION_HXX
#define RSPAMD_CXX_UNIT_SCAN_FINALIZATION_HXX

#include "rspamd_cxx_unit_symcache_checkpoint.hxx"
#include "libserver/scan_finalization.h"
#include "libserver/protocol.h"
#include "libserver/roll_history.h"
#include "libserver/cfg_file_private.h"
#include "unix-std.h"
#include <array>

namespace {
struct finalization_fixture : checkpoint_fixture {
	struct rspamd_main server{};
	struct rspamd_worker worker{};
	struct rspamd_stat statistics{};
	std::array<roll_history_row, 2> rows{};
	struct roll_history history{};

	~finalization_fixture()
	{
		if (task) {
			task->worker = nullptr;
		}
	}

	void init()
	{
		checkpoint_fixture::init();
		server.stat = &statistics;
		server.history = &history;
		worker.srv = &server;
		history.rows = rows.data();
		history.nrows = rows.size();
		task->worker = &worker;
		task->cmd = CMD_CHECK_V2;
	}

	void observer(const char *name, unsigned int inputs = envelope, bool async = false)
	{
		add(name, inputs, SYMBOL_TYPE_IDEMPOTENT, async);
		REQUIRE(rspamd_symcache_set_terminal_observer(cfg->cache, rspamd_symcache_find_symbol(cfg->cache, name)));
	}

	void begin(const char *action = "reject")
	{
		REQUIRE(rspamd_task_begin_early_result(task, action, "test-policy", "explicit test decision",
											   "transaction-1:data"));
	}

	auto event_field(const char *key) -> const ucl_object_t *
	{
		return ucl_object_lookup(rspamd_task_get_terminal_event(task), key);
	}

	void serialize()
	{
		auto *msg = rspamd_http_new_message(HTTP_RESPONSE);
		rspamd_protocol_http_reply(msg, task, nullptr, UCL_EMIT_JSON_COMPACT);
		rspamd_http_message_free(msg);
		msg = rspamd_http_new_message(HTTP_RESPONSE);
		rspamd_protocol_http_reply_v3(msg, task);
		rspamd_http_message_free(msg);
	}
};
}// namespace

TEST_SUITE("scan_finalization")
{
	TEST_CASE_FIXTURE(finalization_fixture, "DATA continuation and serialization do not finalize or run observers")
	{
		add("EARLY", envelope);
		add("POST", envelope, SYMBOL_TYPE_POSTFILTER);
		add("LEGACY_IDEMPOTENT", envelope, SYMBOL_TYPE_IDEMPOTENT);
		observer("AUDITED");
		init();
		REQUIRE(checkpoint() == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		CHECK(calls == std::vector<std::string>{"EARLY"});
		CHECK_FALSE(rspamd_task_finalize_scan(task));
		serialize();
		CHECK(statistics.messages_scanned == 0);
		CHECK(history.cur_row == 0);
		CHECK(task->processed_stages == 0);
		CHECK(std::isnan(task->time_real_finish));
		CHECK(rspamd_task_get_terminal_event(task) == nullptr);
	}

	TEST_CASE_FIXTURE(finalization_fixture, "explicit DATA decisions are immutable and accounted once")
	{
		add("EARLY", envelope);
		callbacks.back().run = [](auto *t) {
			rspamd_task_insert_result_full(t, "EVIDENCE", 2, "dns match", RSPAMD_SYMBOL_INSERT_ENFORCE, nullptr);
		};
		observer("OBSERVER");
		callbacks.back().run = [](auto *t) {
			REQUIRE(t->message == nullptr);
			auto *s = rspamd_task_find_symbol_result(t, "EVIDENCE", nullptr);
			REQUIRE(s != nullptr);
			CHECK(rspamd_task_insert_result(t, "LATE", 100, nullptr) == nullptr);
			CHECK_FALSE(rspamd_task_add_result_option(t, s, "late", 4));
			CHECK(rspamd_task_remove_symbol_result(t, "EVIDENCE", nullptr) == nullptr);
			CHECK_FALSE(rspamd_add_passthrough_result(t, rspamd_config_get_action(t->cfg, "no action"), 10, NAN,
													  "late override", "observer", 0, nullptr));
			CHECK(rspamd_check_action_metric(t, nullptr, nullptr)->action_type == METRIC_ACTION_SOFT_REJECT);
		};
		add("BODY", RSPAMD_SYMCACHE_INPUT_BODY);
		add("POST", 0, SYMBOL_TYPE_POSTFILTER);
		add("LEGACY", 0, SYMBOL_TYPE_IDEMPOTENT);
		observer("BODY_OBSERVER", RSPAMD_SYMCACHE_INPUT_BODY);
		observer("BODY_DEPENDENT");
		depends("BODY_DEPENDENT", "BODY");
		init();
		REQUIRE(checkpoint() == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		task->result->score = 1000;
		CHECK_FALSE(rspamd_task_begin_early_result(task, "no action", "policy", "", nullptr));
		CHECK_FALSE(rspamd_task_begin_early_result(task, "reject", "", "", nullptr));
		begin("soft reject");
		CHECK_FALSE(rspamd_task_begin_early_result(task, "reject", "replacement", "", nullptr));
		CHECK(rspamd_check_action_metric(task, nullptr, nullptr)->action_type == METRIC_ACTION_SOFT_REJECT);
		serialize();
		CHECK(statistics.messages_scanned == 0);
		REQUIRE(rspamd_task_process_early_result(task, false) == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		CHECK(calls == std::vector<std::string>{"EARLY", "OBSERVER"});
		CHECK(statistics.messages_scanned == 1);
		CHECK(statistics.actions_stat[METRIC_ACTION_SOFT_REJECT] == 1);
		CHECK(statistics.actions_stat[METRIC_ACTION_REJECT] == 0);
		CHECK(statistics.avg_time.cur_slot == 1);
		CHECK(history.cur_row == 1);
		CHECK(task->processed_stages == RSPAMD_TASK_STAGE_DONE);
		CHECK(rspamd_task_process_early_result(task, true) == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		CHECK_FALSE(rspamd_task_finalize_scan(task));
		CHECK_FALSE(rspamd_task_process(task, RSPAMD_TASK_PROCESS_ALL));
		CHECK_FALSE(rspamd_symcache_process_symbols(task, cfg->cache, RSPAMD_TASK_STAGE_IDEMPOTENT));
		CHECK(checkpoint() == RSPAMD_SYMCACHE_CHECKPOINT_ERROR);
		serialize();
		CHECK(statistics.messages_scanned == 1);
		CHECK(history.cur_row == 1);
		CHECK(std::string(ucl_object_tostring(event_field("completion_kind"))) == "early_tempfail");
		CHECK_FALSE(ucl_object_toboolean(event_field("has_body")));
		CHECK(ucl_object_type(event_field("size")) == UCL_NULL);
		CHECK(ucl_object_type(event_field("reply_delivered")) == UCL_NULL);
		CHECK(event_field("digest") == nullptr);
		CHECK(event_field("subject") == nullptr);
		CHECK(ucl_object_todouble(event_field("partial_score")) == 1000);
	}

	TEST_CASE_FIXTURE(finalization_fixture, "asynchronous observers drain in dependency order")
	{
		add("EARLY", envelope);
		observer("ASYNC", envelope, true);
		observer("AFTER");
		depends("AFTER", "ASYNC", true);
		init();
		REQUIRE(checkpoint() == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		begin();
		REQUIRE(rspamd_task_process_early_result(task, false) == RSPAMD_SYMCACHE_CHECKPOINT_PENDING);
		CHECK(calls == std::vector<std::string>{"EARLY", "ASYNC"});
		CHECK_FALSE(rspamd_task_finalize_scan(task));
		CHECK(statistics.messages_scanned == 0);
		finish_async();
		REQUIRE(rspamd_task_process_early_result(task, false) == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		CHECK(calls == std::vector<std::string>{"EARLY", "ASYNC", "AFTER"});
		CHECK(statistics.messages_scanned == 1);
		CHECK(std::string(ucl_object_tostring(event_field("observer_status"))) == "complete");
	}

	TEST_CASE_FIXTURE(finalization_fixture, "filters depending on terminal observers remain EOM-only")
	{
		add("EARLY", envelope);
		observer("OBSERVER");
		add("CONSUMER", envelope);
		depends("CONSUMER", "OBSERVER");
		init();
		REQUIRE(checkpoint() == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		CHECK(calls == std::vector<std::string>{"EARLY"});
		begin();
		REQUIRE(rspamd_task_process_early_result(task, false) == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		CHECK(calls == std::vector<std::string>{"EARLY", "OBSERVER"});
	}

	TEST_CASE_FIXTURE(finalization_fixture, "observer deadline cancels work without starting dependents")
	{
		observer("ASYNC", envelope, true);
		observer("AFTER");
		depends("AFTER", "ASYNC", true);
		init();
		REQUIRE(checkpoint() == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		begin();
		REQUIRE(rspamd_task_process_early_result(task, false) == RSPAMD_SYMCACHE_CHECKPOINT_PENDING);
		REQUIRE(rspamd_task_process_early_result(task, true) == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		CHECK(calls == std::vector<std::string>{"ASYNC"});
		CHECK(rspamd_session_events_pending(task->s) == 0);
		CHECK(statistics.messages_scanned == 1);
		CHECK(std::string(ucl_object_tostring(event_field("observer_status"))) == "timeout");
		CHECK(rspamd_task_process_early_result(task, false) == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
	}

	TEST_CASE_FIXTURE(finalization_fixture, "pending or aborted checkpoints cannot become terminal decisions")
	{
		add("DNS", envelope, SYMBOL_TYPE_NORMAL, true);
		init();
		REQUIRE(checkpoint() == RSPAMD_SYMCACHE_CHECKPOINT_PENDING);
		CHECK_FALSE(rspamd_task_begin_early_result(task, "reject", "policy", "", nullptr));
		rspamd_session_destroy(task->s);
		CHECK_FALSE(rspamd_task_begin_early_result(task, "reject", "policy", "", nullptr));
		CHECK(statistics.messages_scanned == 0);
		CHECK(history.cur_row == 0);
	}

	TEST_CASE_FIXTURE(finalization_fixture, "ordinary EOM completion accounts once and retains normal observers")
	{
		observer("AUDITED");
		add("LEGACY", 0, SYMBOL_TYPE_IDEMPOTENT);
		init();
		full_scan();
		CHECK(calls.size() == 2);
		task->processed_stages = RSPAMD_TASK_STAGE_DONE;
		serialize();
		CHECK(statistics.messages_scanned == 0);
		REQUIRE(rspamd_task_finalize_scan(task));
		CHECK(statistics.messages_scanned == 1);
		CHECK(history.cur_row == 1);
		CHECK_FALSE(rows[0].partial);
		CHECK_FALSE(rspamd_task_finalize_scan(task));
		serialize();
		CHECK(statistics.messages_scanned == 1);
		CHECK(rspamd_task_get_terminal_event(task) == nullptr);
	}

	TEST_CASE_FIXTURE(finalization_fixture, "NO_STAT and NO_LOG retain their separate meanings")
	{
		init();
		REQUIRE(checkpoint() == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		SUBCASE("NO_STAT")
		{
			task->flags |= RSPAMD_TASK_FLAG_NO_STAT;
		}

		SUBCASE("NO_LOG")
		{
			task->flags |= RSPAMD_TASK_FLAG_NO_LOG;
		}

		begin();
		REQUIRE(rspamd_task_process_early_result(task, false) == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		CHECK(statistics.messages_scanned == ((task->flags & RSPAMD_TASK_FLAG_NO_STAT) ? 0 : 1));
		CHECK(history.cur_row == ((task->flags & RSPAMD_TASK_FLAG_NO_LOG) ? 0 : 1));
	}

	TEST_CASE_FIXTURE(finalization_fixture, "partial history clears stale content and round trips availability")
	{
		init();
		strcpy(rows[0].message_id, "old message id");
		strcpy(rows[0].symbols, "old symbols");
		REQUIRE(checkpoint() == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		begin();
		REQUIRE(rspamd_task_process_early_result(task, false) == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		CHECK(rows[0].partial);
		CHECK(std::string(rows[0].message_id).empty());
		CHECK(std::string(rows[0].symbols).empty());
		CHECK(std::isnan(rows[0].required_score));
		CHECK(std::string(rows[0].event_id) == "transaction-1:data");
		gchar *path = nullptr;
		int fd = g_file_open_tmp("rspamd-terminal-history-XXXXXX", &path, nullptr);
		REQUIRE(fd != -1);
		close(fd);
		REQUIRE(rspamd_roll_history_save(&history, path));
		std::array<roll_history_row, 2> restored{};
		struct roll_history loaded{};
		loaded.nrows = restored.size();
		loaded.rows = restored.data();
		REQUIRE(rspamd_roll_history_load(&loaded, path));
		unlink(path);
		g_free(path);
		CHECK(restored[0].partial);
		CHECK(std::isnan(restored[0].required_score));
		CHECK(std::string(restored[0].early_policy) == "test-policy");
		auto *out = ucl_object_typed_new(UCL_OBJECT);
		rspamd_roll_history_add_completion(&restored[0], out);
		CHECK_FALSE(ucl_object_toboolean(ucl_object_lookup(out, "has_body")));
		CHECK(std::string(ucl_object_tostring(ucl_object_lookup(out, "decision_stage"))) == "data");
		ucl_object_unref(out);
	}

	TEST_CASE_FIXTURE(finalization_fixture, "terminal decisions publish provisional symbol hits once")
	{
		run_lua(R"lua(
checkpoint_config:register_symbol({name = 'COUNTED', score = 1, required_inputs = {'sender'},
  callback = function() return true end})
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
		begin();
		REQUIRE(rspamd_task_process_early_result(task, false) == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		CHECK(hits() == before + 1);
		CHECK(rspamd_task_process_early_result(task, false) == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		serialize();
		CHECK(hits() == before + 1);
	}

	TEST_CASE_FIXTURE(finalization_fixture, "Lua observers read copies of the event and failures preserve the decision")
	{
		run_lua(R"lua(
checkpoint_config:register_symbol({name = 'LUA_OBSERVER', type = 'idempotent',
  required_inputs = {'sender'}, terminal_observer = true, callback = function(task)
    local event = task:get_terminal_event()
    assert(event.policy == 'test-policy' and event.action == 'reject' and event.has_body == false)
    event.action = 'no action'
    assert(task:get_terminal_event().action == 'reject')
    error('deliberate observer failure')
  end})
)lua");
		init();
		REQUIRE(checkpoint() == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		begin();
		REQUIRE(rspamd_task_process_early_result(task, false) == RSPAMD_SYMCACHE_CHECKPOINT_COMPLETE);
		CHECK(std::string(ucl_object_tostring(event_field("observer_status"))) == "error");
		CHECK(statistics.actions_stat[METRIC_ACTION_REJECT] == 1);
	}
}

#endif
