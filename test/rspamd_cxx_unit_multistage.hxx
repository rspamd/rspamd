/* Copyright 2026 Vsevolod Stakhov. Licensed under the Apache License, Version 2.0. */
#ifndef RSPAMD_CXX_UNIT_MULTISTAGE_HXX
#define RSPAMD_CXX_UNIT_MULTISTAGE_HXX

#include "rspamd_cxx_unit_symcache_replay.hxx"
#include "rspamd_test_fake_time.hxx"
#include "libserver/multistage.h"
#include "libserver/http/http_message.h"
#include "libserver/http/http_private.h"

namespace {
using transport_string = std::unique_ptr<rspamd_fstring_t, decltype(&rspamd_fstring_free)>;
struct multistage_fixture : checkpoint_fixture {
	replay_record metadata{ucl_object_typed_new(UCL_OBJECT), &ucl_object_unref};
	transport_string reply{nullptr, &rspamd_fstring_free};
	unsigned int replies = 0;
	static constexpr const char *id = "0123456789abcdef0123456789abcdef";

	multistage_fixture()
	{
		rspamd_lua_set_path(RSPAMD_LUA_CFG_STATE(cfg), nullptr, nullptr);
		cfg->cfg_ucl_obj = ucl_object_typed_new(UCL_OBJECT);
		auto *opts = ucl_object_typed_new(UCL_OBJECT);
		replay_replace(opts, "key", ucl_object_fromstring("test-only-multistage-shared-key-01"));
		replay_replace(cfg->cfg_ucl_obj, "multistage", opts);
		replay_replace(metadata.get(), "from", ucl_object_fromstring("<sender@example.com>"));
		replay_replace(metadata.get(), "helo", ucl_object_fromstring("mail.example.com"));
		replay_replace(metadata.get(), "ip", ucl_object_fromstring("192.0.2.1"));
		auto *rcpts = ucl_object_typed_new(UCL_ARRAY);
		ucl_array_append(rcpts, ucl_object_fromstring("<recipient@example.org>"));
		replay_replace(metadata.get(), "rcpt", rcpts);
	}

	~multistage_fixture()
	{
		clear_data_task();
	}

	void clear_data_task()
	{
		if (task && task->multistage) {
			rspamd_session_destroy(task->s);
			task = nullptr;
		}
	}

	void policy(const char *action)
	{
		auto *p = ucl_object_typed_new(UCL_OBJECT);
		replay_replace(p, "name", ucl_object_fromstring("explicit-envelope-policy"));
		replay_replace(p, "symbol", ucl_object_fromstring("EARLY"));
		replay_replace(p, "action", ucl_object_fromstring(action));
		replay_replace(p, "reason", ucl_object_fromstring("test policy"));
		auto *policies = ucl_object_typed_new(UCL_ARRAY);
		ucl_array_append(policies, p);
		replay_replace(replay_field(cfg->cfg_ucl_obj, "multistage"), "policies", policies);
	}

	static void on_reply(struct rspamd_task *, const rspamd_fstring_t *wire, void *ud)
	{
		auto *fixture = static_cast<multistage_fixture *>(ud);
		fixture->replies++;

		if (wire) {
			fixture->reply.reset(rspamd_fstring_new_init(wire->str, wire->len));
		}
	}

	void start()
	{
		rspamd_session_destroy(task->s);
		task->s = nullptr;
		auto *msg = rspamd_multistage_data_request(cfg, metadata.get(), id);
		REQUIRE(msg != nullptr);
		REQUIRE(rspamd_multistage_start(task, msg, on_reply, this));
		rspamd_http_message_unref(msg);
	}

	auto response() -> replay_record
	{
		REQUIRE(reply != nullptr);
		return replay_record{rspamd_multistage_open(cfg, "data-response", reply->str, reply->len), &ucl_object_unref};
	}
};
}// namespace

TEST_SUITE("multistage")
{
	TEST_CASE_FIXTURE(multistage_fixture, "explicit disable stops both sides of the transport")
	{
		auto *msg = rspamd_multistage_data_request(cfg, metadata.get(), id);
		gsize len;
		auto *wire = rspamd_http_message_get_body(msg, &len);
		auto *opts = replay_field(cfg->cfg_ucl_obj, "multistage");
		policy("reject");
		REQUIRE(rspamd_multistage_validate(cfg));
		REQUIRE(cfg->multistage_policy_ref > 0);
		replay_replace(opts, "enabled", ucl_object_frombool(false));
		CHECK(rspamd_multistage_validate(cfg));
		CHECK(cfg->multistage_policy_ref == 0);
		CHECK_FALSE(rspamd_multistage_enabled(cfg));
		CHECK(rspamd_multistage_open(cfg, "data-request", wire, len) == nullptr);
		CHECK(rspamd_multistage_seal(cfg, "data-request", metadata.get()) == nullptr);
		replay_replace(opts, "key", ucl_object_fromstring(""));
		CHECK(rspamd_multistage_validate(cfg));
		replay_replace(opts, "enabled", ucl_object_frombool(true));
		CHECK_FALSE(rspamd_multistage_validate(cfg));
		replay_replace(opts, "enabled", ucl_object_fromint(1));
		CHECK_FALSE(rspamd_multistage_validate(cfg));
		CHECK_FALSE(rspamd_multistage_enabled(cfg));
		rspamd_http_message_unref(msg);
	}

	TEST_CASE_FIXTURE(multistage_fixture, "execution diagnostics explain DATA admission")
	{
		add("EARLY", envelope, SYMBOL_TYPE_NORMAL, false, 0, 1);
		add("UNAUDITED", envelope);
		add("DEPENDENT", envelope, SYMBOL_TYPE_NORMAL, false, 0, 1);
		depends("DEPENDENT", "UNAUDITED");
		add("TRANSITIVE", envelope, SYMBOL_TYPE_NORMAL, false, 0, 1);
		depends("TRANSITIVE", "DEPENDENT");
		add("BODY");
		init();

		for (auto *name: {"EARLY", "UNAUDITED", "DEPENDENT", "TRANSITIVE", "BODY"}) {
			replay_record details{ucl_object_typed_new(UCL_OBJECT), &ucl_object_unref};
			rspamd_symcache_get_symbol_details(cfg->cache, name, details.get());
			CHECK(ucl_object_toboolean(ucl_object_lookup(details.get(), "data_candidate")) == (std::string_view{name} == "EARLY"));

			if (std::string_view{name} == "DEPENDENT") {
				auto *blocked = ucl_object_lookup(details.get(), "data_blocking_dependencies");
				REQUIRE(blocked->len == 1);
				CHECK(std::string_view{ucl_object_tostring(ucl_array_find_index(blocked, 0))} == "UNAUDITED");
			}
		}
	}

	TEST_CASE("statistics snapshot, histogram boundaries and reset")
	{
		rspamd_stat stat{};
		rspamd_main srv{};
		rspamd_worker worker{};
		srv.stat = &stat;
		worker.srv = &srv;
		rspamd_multistage_count(&worker, RSPAMD_MULTISTAGE_DATA_STARTED);
		rspamd_multistage_observe(&worker, 0.005);
		rspamd_multistage_observe(&worker, 0.3);
		rspamd_multistage_observe(&worker, 2.0);
		replay_record snapshot{rspamd_multistage_stats(&stat.multistage, TRUE), &ucl_object_unref};
		CHECK(ucl_object_toint(ucl_object_lookup(snapshot.get(), "data_started")) == 1);
		CHECK(ucl_object_toint(ucl_object_lookup(snapshot.get(), "data_duration_count")) == 3);
		CHECK(ucl_object_todouble(ucl_object_lookup(snapshot.get(), "data_duration_sum")) == doctest::Approx(2.305));
		auto *buckets = ucl_object_lookup(snapshot.get(), "data_duration_buckets");
		CHECK(ucl_object_toint(ucl_object_lookup(ucl_array_find_index(buckets, 0), "count")) == 1);
		CHECK(ucl_object_toint(ucl_object_lookup(ucl_array_find_index(buckets, 6), "count")) == 2);
		rspamd_fstring_t *metrics = rspamd_fstring_new();
		rspamd_multistage_metrics(snapshot.get(), &metrics);
		std::string_view text{metrics->str, metrics->len};
		CHECK(text.find("rspamd_multistage_data_duration_seconds_bucket{le=\"+Inf\"} 3") != std::string_view::npos);
		CHECK(text.find("rspamd_multistage_data_started_total 1") != std::string_view::npos);
		rspamd_fstring_free(metrics);
		snapshot.reset(rspamd_multistage_stats(&stat.multistage, FALSE));
		CHECK(ucl_object_toint(ucl_object_lookup(snapshot.get(), "data_started")) == 0);
		CHECK(ucl_object_toint(ucl_object_lookup(snapshot.get(), "data_duration_count")) == 0);
	}

	TEST_CASE_FIXTURE(multistage_fixture, "authentication binds domain, bytes, key and expiry")
	{
		auto *msg = rspamd_multistage_data_request(cfg, metadata.get(), id);
		gsize len;
		auto *body = rspamd_http_message_get_body(msg, &len);
		replay_record request{rspamd_multistage_open(cfg, "data-request", body, len), &ucl_object_unref};
		REQUIRE(request != nullptr);
		CHECK(rspamd_multistage_open(cfg, "data-response", body, len) == nullptr);
		std::string tampered(body, len);
		tampered.back() ^= 1;
		CHECK(rspamd_multistage_open(cfg, "data-request", tampered.data(), tampered.size()) == nullptr);
		replay_replace(request.get(), "issued", ucl_object_fromdouble(ev_time() - 301));
		transport_string expired{rspamd_multistage_seal(cfg, "data-request", request.get()), &rspamd_fstring_free};
		CHECK(rspamd_multistage_open(cfg, "data-request", expired->str, expired->len) == nullptr);
		replay_replace(replay_field(cfg->cfg_ucl_obj, "multistage"), "key",
					   ucl_object_fromstring("test-only-multistage-shared-key-02"));
		CHECK(rspamd_multistage_open(cfg, "data-request", body, len) == nullptr);
		CHECK(rspamd_multistage_open(cfg, "data-request", body, RSPAMD_MULTISTAGE_MAX_WIRE + 1) == nullptr);
		rspamd_http_message_unref(msg);
	}

	TEST_CASE_FIXTURE(multistage_fixture, "portable DATA excludes unaudited dependency closure and replays once at EOM")
	{
		int type = SYMBOL_TYPE_NORMAL;

		SUBCASE("audited prefilter")
		{
			type = SYMBOL_TYPE_PREFILTER;
		}

		add("EARLY", envelope, type, false, 0, 1);
		callbacks.back().run = [](auto *t) {
			rspamd_task_insert_result(t, "EARLY", 100.0, "data");
		};
		add("UNAUDITED", envelope);
		add("DEPENDENT", envelope, SYMBOL_TYPE_NORMAL, false, 0, 1);
		depends("DEPENDENT", "UNAUDITED");
		add("BODY");
		init();
		start();
		CHECK(calls == std::vector<std::string>{"EARLY"});
		REQUIRE(replies == 1);
		auto payload = response();
		REQUIRE(payload != nullptr);
		CHECK(std::string(ucl_object_tostring(ucl_object_lookup(payload.get(), "decision"))) == "continue");
		CHECK(task->processed_stages == 0);
		clear_data_task();
		new_task();
		task->meta = replay_copy(metadata.get());
		replay_replace(task->meta, "early_record", ucl_object_fromlstring(reply->str, reply->len));
		REQUIRE(rspamd_multistage_import(task));
		CHECK(rspamd_task_find_symbol_result(task, "EARLY", nullptr) == nullptr);
		calls.clear();
		full_scan();
		CHECK(calls == std::vector<std::string>{"UNAUDITED", "DEPENDENT", "BODY"});
		CHECK(rspamd_task_find_symbol_result(task, "EARLY", nullptr)->nshots == 1);
		new_task();
		task->meta = replay_copy(metadata.get());
		replay_replace(task->meta, "helo", ucl_object_fromstring("changed.example.com"));
		replay_replace(task->meta, "early_record", ucl_object_fromlstring(reply->str, reply->len));
		CHECK_FALSE(rspamd_multistage_import(task));
		calls.clear();
		full_scan();
		CHECK(std::count(calls.begin(), calls.end(), "EARLY") == 1);
	}

	TEST_CASE_FIXTURE(multistage_fixture, "only explicit policy produces a terminal DATA response")
	{
		const char *action = "reject";
		SUBCASE("temporary")
		{
			action = "soft reject";
		}

		policy(action);
		REQUIRE(rspamd_multistage_validate(cfg));
		add("EARLY", envelope, SYMBOL_TYPE_NORMAL, false, 0, 1);
		callbacks.back().run = [](auto *t) {
			rspamd_task_insert_result(t, "EARLY", 1.0, nullptr);
		};
		init();
		start();
		REQUIRE(replies == 1);
		auto payload = response();
		REQUIRE(payload != nullptr);
		CHECK(std::string(ucl_object_tostring(ucl_object_lookup(payload.get(), "decision"))) == action);
		CHECK(ucl_object_lookup(payload.get(), "record") == nullptr);
		CHECK(ucl_object_lookup(payload.get(), "terminal") != nullptr);
		auto *terminal_action = ucl_object_lookup(ucl_object_lookup(payload.get(), "terminal"), "action");
		REQUIRE(terminal_action != nullptr);
		CHECK(std::string(ucl_object_tostring(terminal_action)) == action);
		CHECK(std::string(ucl_object_tostring(ucl_object_lookup(
				  ucl_object_lookup(payload.get(), "terminal"), "policy_recipient"))) == "recipient@example.org");
		CHECK((task->processed_stages & RSPAMD_TASK_STAGE_DONE) != 0);
	}

	TEST_CASE_FIXTURE(multistage_fixture, "deadline cancels unfinished checks and continues without a record")
	{
		rspamd_test::fake_clock clk(1000.0, loop);
		policy("reject");
		replay_replace(replay_field(cfg->cfg_ucl_obj, "multistage"), "timeout", ucl_object_fromdouble(1.0));
		add("EARLY", envelope, SYMBOL_TYPE_NORMAL, true, 0, 1);
		init();
		start();
		CHECK(replies == 0);
		clk.advance(0.5);
		ev_run(loop, EVRUN_NOWAIT);
		CHECK(replies == 0);
		clk.advance(1.0);
		ev_run(loop, EVRUN_NOWAIT);
		REQUIRE(replies == 1);
		auto payload = response();
		REQUIRE(payload != nullptr);
		CHECK(std::string(ucl_object_tostring(ucl_object_lookup(payload.get(), "decision"))) == "continue");
		CHECK(ucl_object_lookup(payload.get(), "record") == nullptr);
		CHECK(task->processed_stages == 0);
	}

	TEST_CASE_FIXTURE(multistage_fixture, "configuration rejects invalid keys and unsupported early actions")
	{
		policy("add header");
		CHECK_FALSE(rspamd_multistage_validate(cfg));
		policy("reject");
		CHECK(rspamd_multistage_validate(cfg));
		auto *policy = ucl_array_find_index(replay_field(replay_field(cfg->cfg_ucl_obj, "multistage"), "policies"), 0);
		auto *scope = ucl_object_typed_new(UCL_OBJECT);
		replay_replace(scope, "header", ucl_object_fromstring("Subject"));
		replay_replace(const_cast<ucl_object_t *>(policy), "match", scope);
		CHECK_FALSE(rspamd_multistage_validate(cfg));
		replay_replace(replay_field(cfg->cfg_ucl_obj, "multistage"), "key", ucl_object_fromstring("short"));
		CHECK_FALSE(rspamd_multistage_enabled(cfg));
		CHECK_FALSE(rspamd_multistage_validate(cfg));
	}

	TEST_CASE_FIXTURE(multistage_fixture, "reply decisions require the authenticated transaction and envelope")
	{
		transport_string binding{rspamd_multistage_binding(metadata.get(), id), &rspamd_fstring_free};
		REQUIRE(binding != nullptr);
		replay_record payload{ucl_object_typed_new(UCL_OBJECT), &ucl_object_unref};
		replay_replace(payload.get(), "version", ucl_object_fromint(1));
		replay_replace(payload.get(), "issued", ucl_object_fromdouble(ev_time()));
		replay_replace(payload.get(), "id", ucl_object_fromstring(id));
		replay_replace(payload.get(), "binding", ucl_object_fromlstring(binding->str, binding->len));
		replay_replace(payload.get(), "record", ucl_object_typed_new(UCL_OBJECT));

		for (const auto &[decision, expected]: {std::pair{"continue", RSPAMD_MULTISTAGE_CONTINUE},
												{"reject", RSPAMD_MULTISTAGE_REJECT},
												{"soft reject", RSPAMD_MULTISTAGE_TEMPFAIL},
												{"accept", RSPAMD_MULTISTAGE_CONTINUE}}) {
			replay_replace(payload.get(), "decision", ucl_object_fromstring(decision));
			auto *terminal = ucl_object_typed_new(UCL_OBJECT);
			replay_replace(terminal, "action", ucl_object_fromstring(decision));
			replay_replace(terminal, "reason", ucl_object_fromstring("policy response"));
			replay_replace(payload.get(), "terminal", terminal);
			transport_string wire{rspamd_multistage_seal(cfg, "data-response", payload.get()), &rspamd_fstring_free};
			REQUIRE(wire != nullptr);

			auto check_reply = [&](const char *expected_id, const rspamd_fstring_t *expected_binding, bool has_record) {
				rspamd_fstring_t *record = nullptr;
				rspamd_fstring_t *reason = nullptr;
				auto result =
					rspamd_multistage_check_reply(cfg, wire->str, wire->len, expected_id, expected_binding, &record, &reason);
				transport_string owned_record{record, &rspamd_fstring_free};
				transport_string owned_reason{reason, &rspamd_fstring_free};
				CHECK(bool(owned_record) == has_record);
				CHECK(bool(owned_reason) == (result != RSPAMD_MULTISTAGE_CONTINUE));

				if (reason) {
					CHECK(std::string(reason->str, reason->len) == "policy response");
				}

				if (record) {
					CHECK(std::string(record->str, record->len) == std::string(wire->str, wire->len));
				}

				return result;
			};

			CHECK(check_reply(id, binding.get(), strcmp(decision, "continue") == 0) == expected);
			CHECK(check_reply("1123456789abcdef0123456789abcdef", binding.get(), false) == RSPAMD_MULTISTAGE_CONTINUE);
			CHECK(check_reply(id, nullptr, false) == RSPAMD_MULTISTAGE_CONTINUE);

			binding->str[0] ^= 1;
			CHECK(check_reply(id, binding.get(), false) == RSPAMD_MULTISTAGE_CONTINUE);
			binding->str[0] ^= 1;
			wire->str[0] ^= 1;
			CHECK(check_reply(id, binding.get(), false) == RSPAMD_MULTISTAGE_CONTINUE);
		}
	}

	TEST_CASE_FIXTURE(multistage_fixture, "SMTP reasons are bounded single-line text")
	{
		policy("reject");
		auto *item = const_cast<ucl_object_t *>(ucl_array_find_index(
			replay_field(replay_field(cfg->cfg_ucl_obj, "multistage"), "policies"), 0));
		transport_string binding{rspamd_multistage_binding(metadata.get(), id), &rspamd_fstring_free};
		replay_record payload{ucl_object_typed_new(UCL_OBJECT), &ucl_object_unref};
		replay_replace(payload.get(), "version", ucl_object_fromint(1));
		replay_replace(payload.get(), "issued", ucl_object_fromdouble(ev_time()));
		replay_replace(payload.get(), "id", ucl_object_fromstring(id));
		replay_replace(payload.get(), "binding", ucl_object_fromlstring(binding->str, binding->len));
		replay_replace(payload.get(), "decision", ucl_object_fromstring("reject"));

		for (const auto &[text, valid]: {std::pair{std::string(500, 'x'), true},
										 {std::string(501, 'x'), false},
										 {std::string{}, false},
										 {std::string{"bad\r\n250 injected"}, false},
										 {std::string{"bad\0hidden", 10}, false},
										 {std::string{"bad\ttext"}, false}}) {
			replay_replace(item, "reason", ucl_object_fromlstring(text.data(), text.size()));
			CHECK(bool(rspamd_multistage_validate(cfg)) == valid);
			replay_replace(payload.get(), "terminal", ucl_object_ref(item));
			transport_string wire{rspamd_multistage_seal(cfg, "data-response", payload.get()), &rspamd_fstring_free};
			rspamd_fstring_t *record = nullptr, *reason = nullptr;
			CHECK(rspamd_multistage_check_reply(cfg, wire->str, wire->len, id, binding.get(), &record, &reason) == RSPAMD_MULTISTAGE_REJECT);
			transport_string owned_reason{reason, &rspamd_fstring_free};
			CHECK(record == nullptr);
			CHECK(bool(owned_reason) == valid);
		}
	}

	TEST_CASE_FIXTURE(multistage_fixture, "binding is canonical, transaction-specific and bounded")
	{
		auto *args = ucl_object_typed_new(UCL_OBJECT);
		replay_replace(args, "SIZE", ucl_object_fromstring("100"));
		replay_replace(args, "BODY", ucl_object_fromstring("8BITMIME"));
		replay_replace(metadata.get(), "mail_esmtp_args", args);
		transport_string first{rspamd_multistage_binding(metadata.get(), id), &rspamd_fstring_free};
		REQUIRE(first != nullptr);
		args = ucl_object_typed_new(UCL_OBJECT);
		replay_replace(args, "BODY", ucl_object_fromstring("8BITMIME"));
		replay_replace(args, "SIZE", ucl_object_fromstring("100"));
		replay_replace(metadata.get(), "mail_esmtp_args", args);
		transport_string second{rspamd_multistage_binding(metadata.get(), id), &rspamd_fstring_free};
		REQUIRE(second != nullptr);
		CHECK(std::string(first->str, first->len) == std::string(second->str, second->len));
		transport_string other{rspamd_multistage_binding(metadata.get(), "another-transaction"), &rspamd_fstring_free};
		CHECK(std::string(first->str, first->len) != std::string(other->str, other->len));
		auto *nested = ucl_object_fromstring("leaf");

		for (auto i = 0; i < 30; i++) {
			auto *array = ucl_object_typed_new(UCL_ARRAY);
			ucl_array_append(array, nested);
			nested = array;
		}

		replay_replace(metadata.get(), "headers", nested);
		CHECK(rspamd_multistage_binding(metadata.get(), id) == nullptr);
	}
}
#endif
