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
#include "libutil/fstring.h"
#include "libutil/str_util.h"
#include <cstring>
#include <memory>
#include <string>

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
	explicit task_holder(bool external_pool = false)
	{
		loop = ev_loop_new(0);
		REQUIRE(loop != nullptr);
		if (external_pool) {
			pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "esmtp_test", 0);
		}
		task = rspamd_task_new(nullptr, nullptr, pool, nullptr, loop, FALSE);
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
}

#endif
