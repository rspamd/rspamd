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
		add("EARLY", envelope, SYMBOL_TYPE_NORMAL, false, 0, 1);
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
			transport_string wire{rspamd_multistage_seal(cfg, "data-response", payload.get()), &rspamd_fstring_free};
			REQUIRE(wire != nullptr);

			auto check_reply = [&](const char *expected_id, const rspamd_fstring_t *expected_binding, bool has_record) {
				rspamd_fstring_t *record = nullptr;
				auto result =
					rspamd_multistage_check_reply(cfg, wire->str, wire->len, expected_id, expected_binding, &record);
				transport_string owned_record{record, &rspamd_fstring_free};
				CHECK(bool(owned_record) == has_record);

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
