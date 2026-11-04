/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy at https://www.apache.org/licenses/LICENSE-2.0
 */
#ifndef RSPAMD_CXX_UNIT_ESMTP_ARGS_HXX
#define RSPAMD_CXX_UNIT_ESMTP_ARGS_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"
#include "libserver/task.h"
#include "libserver/protocol.h"
#include "libserver/http/http_message.h"
#include "libserver/cfg_file.h"
#include "libmime/email_addr.h"
#include "libutil/addr.h"
#include "libutil/fstring.h"
#include "libutil/str_util.h"
#include <cstring>
#include <initializer_list>
#include <memory>
#include <string>
#include <utility>

/* Run this suite under ASan/LSan: without protocol pool destructors the
 * parsing assertions pass, but the containers and their tokens leak.
 * No daemon, milter, deadline or external service is involved. */
namespace rspamd_esmtp_args_test {

using table_ptr = std::unique_ptr<GHashTable, decltype(&g_hash_table_unref)>;
using array_ptr = std::unique_ptr<GPtrArray, decltype(&g_ptr_array_unref)>;
using message_ptr = std::unique_ptr<rspamd_http_message,
								  decltype(&rspamd_http_message_unref)>;

static std::string lookup(GHashTable *args, const char *name)
{
	rspamd_ftok_t key;
	key.begin = name;
	key.len = strlen(name);
	REQUIRE(args != nullptr);
	auto *value = static_cast<const rspamd_ftok_t *>(g_hash_table_lookup(args, &key));
	REQUIRE(value != nullptr);
	return std::string(value->begin, value->len);
}

class task_holder {
public:
	explicit task_holder(bool external_pool = false, struct rspamd_config *cfg = nullptr)
	{
		loop = ev_loop_new(0);
		REQUIRE(loop != nullptr);
		if (external_pool) {
			pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "esmtp_test", 0);
		}
		task = rspamd_task_new(nullptr, cfg, pool, nullptr, loop, FALSE);
	}

	task_holder(const task_holder &) = delete;
	task_holder &operator=(const task_holder &) = delete;

	~task_holder()
	{
		close();
		ev_loop_destroy(loop);
	}

	void close()
	{
		if (task != nullptr) {
			rspamd_task_free(task);
			task = nullptr;
		}
		if (pool != nullptr) {
			rspamd_mempool_delete(pool);
			pool = nullptr;
		}
	}

	void headers(bool replace = false)
	{
		message_ptr msg{rspamd_http_new_message(HTTP_REQUEST), rspamd_http_message_unref};
		rspamd_http_message_add_header(msg.get(), "X-Rspamd-Mail-Esmtp-Args",
			replace ? "size=250" : "SIZE=100");
		rspamd_http_message_add_header(msg.get(), "X-Rspamd-Mail-Esmtp-Args", "RET=HDRS");
		rspamd_http_message_add_header(msg.get(), "X-Rspamd-Rcpt-Esmtp-Args",
			replace ? "0:notify=SUCCESS" : "0:NOTIFY=FAILURE");
		rspamd_http_message_add_header(msg.get(), "X-Rspamd-Rcpt-Esmtp-Args",
			"3:ORCPT=rfc822;dest@example.net");
		REQUIRE(rspamd_protocol_handle_headers(task, msg.get()));
	}

	/* One v2 request; repeated names keep their order, as on the wire */
	void send(std::initializer_list<std::pair<const char *, const char *>> hdrs)
	{
		message_ptr msg{rspamd_http_new_message(HTTP_REQUEST), rspamd_http_message_unref};
		for (const auto &hdr: hdrs) {
			rspamd_http_message_add_header(msg.get(), hdr.first, hdr.second);
		}
		REQUIRE(rspamd_protocol_handle_headers(task, msg.get()));
	}

	bool metadata(const char *json, bool with_message)
	{
		body = "--esmtp-test\r\nContent-Disposition: form-data; name=\"metadata\"\r\n"
			   "Content-Type: application/json\r\n\r\n";
		body += json;
		if (with_message) {
			body += "\r\n--esmtp-test\r\nContent-Disposition: form-data; name=\"message\"\r\n"
					"Content-Type: message/rfc822\r\n\r\nSubject: test\r\n\r\nbody\r\n";
		}
		body += "\r\n--esmtp-test--\r\n";
		message_ptr msg{rspamd_http_new_message(HTTP_REQUEST), rspamd_http_message_unref};
		rspamd_http_message_add_header(msg.get(), "Content-Type",
			"multipart/form-data; boundary=esmtp-test");
		return rspamd_protocol_handle_v3_request(task, msg.get(), body.data(), body.size());
	}

	struct rspamd_task *task = nullptr;

private:
	rspamd_mempool_t *pool = nullptr;
	struct ev_loop *loop;
	std::string body;
};

static unsigned borrowed_tokens_freed;

static void counted_token_free(gpointer token)
{
	borrowed_tokens_freed++;
	rspamd_fstring_mapped_ftok_free(token);
}

static void unref_table(gpointer table)
{
	if (table != nullptr) {
		g_hash_table_unref(static_cast<GHashTable *>(table));
	}
}

static table_ptr borrowed_args(const char *name, const char *value)
{
	table_ptr args{g_hash_table_new_full(rspamd_ftok_icase_hash,
		rspamd_ftok_icase_equal, counted_token_free, counted_token_free), g_hash_table_unref};
	g_hash_table_insert(args.get(),
		rspamd_ftok_map(rspamd_fstring_new_init(name, strlen(name))),
		rspamd_ftok_map(rspamd_fstring_new_init(value, strlen(value))));
	return args;
}

} // namespace rspamd_esmtp_args_test

TEST_SUITE("esmtp_args")
{
	TEST_CASE("v2 containers and retained references survive task cleanup")
	{
		using namespace rspamd_esmtp_args_test;
		bool external_pool = false;
		SUBCASE("task owns pool") {}
		SUBCASE("caller owns pool") { external_pool = true; }
		for (unsigned i = 0; i < 64; i++) {
			task_holder holder(external_pool);
			holder.headers();
			holder.headers(true);
			auto *task = holder.task;
			REQUIRE(task->mail_esmtp_args != nullptr);
			REQUIRE(task->rcpt_esmtp_args != nullptr);
			// Self-assignment must not create another cleanup obligation.
			rspamd_task_set_mail_esmtp_args(task, task->mail_esmtp_args);
			rspamd_task_set_rcpt_esmtp_args(task, task->rcpt_esmtp_args);
			table_ptr mail{g_hash_table_ref(task->mail_esmtp_args), g_hash_table_unref};
			array_ptr rcpts{g_ptr_array_ref(task->rcpt_esmtp_args), g_ptr_array_unref};
			CHECK(g_hash_table_size(mail.get()) == 2);
			holder.close();
			CHECK(lookup(mail.get(), "SIZE") == "250");
			REQUIRE(rcpts->len == 4);
			CHECK(g_ptr_array_index(rcpts.get(), 1) == nullptr);
			CHECK(g_ptr_array_index(rcpts.get(), 2) == nullptr);
			CHECK(lookup(static_cast<GHashTable *>(g_ptr_array_index(rcpts.get(), 0)), "NOTIFY") == "SUCCESS");
			CHECK(lookup(static_cast<GHashTable *>(g_ptr_array_index(rcpts.get(), 3)), "ORCPT") == "rfc822;dest@example.net");
		}
	}

	TEST_CASE("v3 sparse arrays, null-only arrays and rejected requests are reclaimed")
	{
		using namespace rspamd_esmtp_args_test;
		bool null_only = false, with_message = true;
		SUBCASE("sparse array") {}
		SUBCASE("null-only array") { null_only = true; }
		SUBCASE("missing message after metadata allocation") { with_message = false; }
		for (unsigned i = 0; i < 64; i++) {
			task_holder holder;
			const char *json = null_only
				? R"({"mail_esmtp_args":{"SIZE":"100"},"rcpt_esmtp_args":[null,null]})"
				: R"({"mail_esmtp_args":{"SIZE":"100"},"rcpt_esmtp_args":[null,{"NOTIFY":"FAILURE"},null,{"ORCPT":"rfc822;dest@example.net"}]})";
			CHECK(holder.metadata(json, with_message) == with_message);
			REQUIRE(holder.task->rcpt_esmtp_args != nullptr);
			table_ptr mail{g_hash_table_ref(holder.task->mail_esmtp_args), g_hash_table_unref};
			array_ptr rcpts{g_ptr_array_ref(holder.task->rcpt_esmtp_args), g_ptr_array_unref};
			if (!with_message) {
				REQUIRE(holder.task->err != nullptr);
				CHECK(std::string(holder.task->err->message).find("missing 'message'") != std::string::npos);
			}
			holder.close();
			CHECK(lookup(mail.get(), "size") == "100");
			REQUIRE(rcpts->len == (null_only ? 2 : 4));
			CHECK(g_ptr_array_index(rcpts.get(), 0) == nullptr);
			if (null_only) {
				CHECK(g_ptr_array_index(rcpts.get(), 1) == nullptr);
			}
			else {
				CHECK(lookup(static_cast<GHashTable *>(g_ptr_array_index(rcpts.get(), 1)), "notify") == "FAILURE");
			}
		}
	}

	TEST_CASE("setters borrow external containers and do not orphan protocol allocations")
	{
		using namespace rspamd_esmtp_args_test;
		borrowed_tokens_freed = 0;
		{
			auto mail = borrowed_args("SIZE", "500");
			array_ptr rcpts{g_ptr_array_new_with_free_func(unref_table), g_ptr_array_unref};
			auto first = borrowed_args("NOTIFY", "NEVER");
			auto third = borrowed_args("ORCPT", "rfc822;other@example.net");
			g_ptr_array_add(rcpts.get(), first.release());
			g_ptr_array_add(rcpts.get(), nullptr);
			g_ptr_array_add(rcpts.get(), third.release());
			task_holder holder;
			holder.headers();
			rspamd_task_set_mail_esmtp_args(holder.task, mail.get());
			rspamd_task_set_rcpt_esmtp_args(holder.task, rcpts.get());
			holder.close();
			CHECK(borrowed_tokens_freed == 0);
			CHECK(lookup(mail.get(), "size") == "500");
			REQUIRE(rcpts->len == 3);
			CHECK(lookup(static_cast<GHashTable *>(g_ptr_array_index(rcpts.get(), 0)), "notify") == "NEVER");
		}
		CHECK(borrowed_tokens_freed == 6);
	}

	/*
	 * The index used to go through strtol into an int: a negative one (or one
	 * that wraps to negative) read and wrote outside of the array, and a large
	 * one grew it to billions of slots.
	 */
	TEST_CASE("v2 malformed or out of range recipient indexes are rejected")
	{
		using namespace rspamd_esmtp_args_test;
		/* No config, so the built-in bound of 1024 recipients applies */
		const char *rejected[] = {
			"-1:NOTIFY=NEVER",
			"-2147483648:NOTIFY=NEVER",
			"4294967295:NOTIFY=NEVER",
			"2147483647:NOTIFY=NEVER",
			"18446744073709551616:NOTIFY=NEVER",
			"1024:NOTIFY=NEVER",
			"abc:NOTIFY=NEVER",
			"1x:NOTIFY=NEVER",
			" 1:NOTIFY=NEVER",
			"+1:NOTIFY=NEVER",
			":NOTIFY=NEVER",
		};

		for (const char *value: rejected) {
			CAPTURE(value);
			task_holder holder;
			holder.send({{"X-Rspamd-Rcpt-Esmtp-Args", value}});
			CHECK(holder.task->rcpt_esmtp_args == nullptr);
		}

		/* Next to valid indexes, bad ones must neither be read nor written */
		task_holder holder;
		holder.send({{"X-Rspamd-Rcpt-Esmtp-Args", "1:NOTIFY=NEVER"},
					 {"X-Rspamd-Rcpt-Esmtp-Args", "-1:ORCPT=rfc822;neg@example.net"},
					 {"X-Rspamd-Rcpt-Esmtp-Args", "4294967295:ORCPT=rfc822;wrap@example.net"},
					 {"X-Rspamd-Rcpt-Esmtp-Args", "1024:ORCPT=rfc822;over@example.net"},
					 {"X-Rspamd-Rcpt-Esmtp-Args", "1023:ORCPT=rfc822;last@example.net"}});
		auto *rcpts = holder.task->rcpt_esmtp_args;
		REQUIRE(rcpts != nullptr);
		REQUIRE(rcpts->len == 1024);
		CHECK(g_ptr_array_index(rcpts, 0) == nullptr);
		auto *second = static_cast<GHashTable *>(g_ptr_array_index(rcpts, 1));
		CHECK(g_hash_table_size(second) == 1);
		CHECK(lookup(second, "NOTIFY") == "NEVER");
		auto *last = static_cast<GHashTable *>(g_ptr_array_index(rcpts, 1023));
		CHECK(g_hash_table_size(last) == 1);
		CHECK(lookup(last, "ORCPT") == "rfc822;last@example.net");
	}

	TEST_CASE("recipient indexes are bounded by max_recipients in both protocols")
	{
		using namespace rspamd_esmtp_args_test;
		auto *cfg = rspamd_config_new(RSPAMD_CONFIG_INIT_DEFAULT);
		cfg->max_recipients = 4;
		{
			task_holder holder(false, cfg);
			holder.send({{"X-Rspamd-Rcpt-Esmtp-Args", "3:NOTIFY=NEVER"},
						 {"X-Rspamd-Rcpt-Esmtp-Args", "4:NOTIFY=DELAY"}});
			auto *rcpts = holder.task->rcpt_esmtp_args;
			REQUIRE(rcpts != nullptr);
			REQUIRE(rcpts->len == 4);
			CHECK(lookup(static_cast<GHashTable *>(g_ptr_array_index(rcpts, 3)), "NOTIFY") == "NEVER");
		}
		{
			/* v3 indexes are array positions: entries past the bound are dropped */
			task_holder holder(false, cfg);
			CHECK(holder.metadata(R"({"rcpt_esmtp_args":[null,null,null,{"NOTIFY":"NEVER"},{"NOTIFY":"DELAY"},null]})",
								  true));
			auto *rcpts = holder.task->rcpt_esmtp_args;
			REQUIRE(rcpts != nullptr);
			REQUIRE(rcpts->len == 4);
			CHECK(lookup(static_cast<GHashTable *>(g_ptr_array_index(rcpts, 3)), "NOTIFY") == "NEVER");
		}
		rspamd_config_free(cfg);

		/* Without a config the built-in bound applies to v3 as well */
		std::string json = R"({"rcpt_esmtp_args":[)";
		for (unsigned i = 0; i < 1030; i++) {
			json += "null,";
		}
		json += R"({"NOTIFY":"NEVER"}]})";
		task_holder holder;
		CHECK(holder.metadata(json.c_str(), true));
		REQUIRE(holder.task->rcpt_esmtp_args != nullptr);
		CHECK(holder.task->rcpt_esmtp_args->len == 1024);
	}

	/* Each repeated header used to overwrite, and leak, the previous address */
	TEST_CASE("v2 repeated From and IP headers keep the last good value")
	{
		using namespace rspamd_esmtp_args_test;
		task_holder holder;
		holder.send({{"From", "<first@example.com>"},
					 {"IP", "192.0.2.1"},
					 {"From", "<second@example.org>"},
					 {"IP", "198.51.100.7"},
					 /* Not an address: the previous one stays */
					 {"IP", "not-an-address"}});
		auto *task = holder.task;
		REQUIRE(task->from_envelope != nullptr);
		CHECK(std::string(task->from_envelope->addr, task->from_envelope->addr_len) ==
			  "second@example.org");
		REQUIRE(task->from_addr != nullptr);
		CHECK(std::string(rspamd_inet_address_to_string(task->from_addr)) == "198.51.100.7");
		CHECK((task->flags & RSPAMD_TASK_FLAG_NO_IP) == 0);
	}

	/* Milter passes a keyword without '=' (SMTPUTF8, REQUIRETLS) as is */
	TEST_CASE("v2 ESMTP keywords without a value are kept")
	{
		using namespace rspamd_esmtp_args_test;
		task_holder holder;
		holder.send({{"X-Rspamd-Mail-Esmtp-Args", "SMTPUTF8"},
					 {"X-Rspamd-Mail-Esmtp-Args", "SIZE=100"},
					 {"X-Rspamd-Mail-Esmtp-Args", "=nokey"},
					 {"X-Rspamd-Rcpt-Esmtp-Args", "0:REQUIRETLS"},
					 {"X-Rspamd-Rcpt-Esmtp-Args", "0:NOTIFY=NEVER"},
					 {"X-Rspamd-Rcpt-Esmtp-Args", "1:"},
					 {"X-Rspamd-Rcpt-Esmtp-Args", "1:=nokey"}});
		auto *mail = holder.task->mail_esmtp_args;
		REQUIRE(mail != nullptr);
		CHECK(g_hash_table_size(mail) == 2);
		CHECK(lookup(mail, "SMTPUTF8").empty());
		CHECK(lookup(mail, "SIZE") == "100");
		auto *rcpts = holder.task->rcpt_esmtp_args;
		REQUIRE(rcpts != nullptr);
		REQUIRE(rcpts->len == 1);
		auto *first = static_cast<GHashTable *>(g_ptr_array_index(rcpts, 0));
		CHECK(g_hash_table_size(first) == 2);
		CHECK(lookup(first, "REQUIRETLS").empty());
		CHECK(lookup(first, "NOTIFY") == "NEVER");
	}

	/* An empty value used to hit an assertion and abort the worker */
	TEST_CASE("v2 empty Deliver-To keeps the previous value")
	{
		using namespace rspamd_esmtp_args_test;
		task_holder holder;
		holder.send({{"Deliver-To", "<first@example.com>"},
					 {"Deliver-To", ""}});
		REQUIRE(holder.task->deliver_to != nullptr);
		CHECK(std::string(holder.task->deliver_to) == "first@example.com");

		task_holder braces;
		braces.send({{"Deliver-To", "<<<"}});
		REQUIRE(braces.task->deliver_to != nullptr);
		CHECK(std::string(braces.task->deliver_to).empty());
	}

	/*
	 * Settings elements are refcounted and live in the config pool, so a lost
	 * reference is invisible to LSan: count the references instead.
	 */
	TEST_CASE("v2 repeated Settings-ID headers keep one owned reference")
	{
		using namespace rspamd_esmtp_args_test;
		const char *last = nullptr;
		SUBCASE("known id last")
		{
			last = "second";
		}
		SUBCASE("unknown id last")
		{
			last = "missing";
		}

		auto *cfg = rspamd_config_new(RSPAMD_CONFIG_INIT_DEFAULT);
		rspamd_config_register_settings_id(cfg, "first", nullptr, nullptr,
										   RSPAMD_SETTINGS_POLICY_DEFAULT);
		rspamd_config_register_settings_id(cfg, "second", nullptr, nullptr,
										   RSPAMD_SETTINGS_POLICY_DEFAULT);
		auto *first = rspamd_config_find_settings_name_ref(cfg, "first", strlen("first"));
		auto *second = rspamd_config_find_settings_name_ref(cfg, "second", strlen("second"));
		REQUIRE(first != nullptr);
		REQUIRE(second != nullptr);
		const auto first_refs = first->ref.refcount;
		const auto second_refs = second->ref.refcount;

		{
			task_holder holder(false, cfg);
			holder.send({{"Settings-ID", "first"},
						 {"Settings-ID", "second"},
						 {"Settings-ID", last}});

			if (strcmp(last, "second") == 0) {
				CHECK(holder.task->settings_elt == second);
				CHECK(second->ref.refcount == second_refs + 1);
			}
			else {
				CHECK(holder.task->settings_elt == nullptr);
				CHECK(second->ref.refcount == second_refs);
			}

			CHECK(first->ref.refcount == first_refs);
			holder.close();
			CHECK(second->ref.refcount == second_refs);
		}

		REF_RELEASE(first);
		REF_RELEASE(second);
		rspamd_config_free(cfg);
	}
}

#endif
