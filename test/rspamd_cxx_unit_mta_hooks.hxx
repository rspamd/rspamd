/* Copyright 2026 Vsevolod Stakhov. SPDX-License-Identifier: Apache-2.0 */
#ifndef RSPAMD_CXX_UNIT_MTA_HOOKS_HXX
#define RSPAMD_CXX_UNIT_MTA_HOOKS_HXX
#include "libserver/mta_hooks.h"
#include "libserver/cfg_file.h"
#include "libserver/http/http_private.h"
#include "libutil/str_util.h"
#include <memory>
#include <string>

namespace hooks_test {
using msg_ptr = std::unique_ptr<rspamd_http_message, decltype(&rspamd_http_message_unref)>;
static std::string request()
{
	return R"({"stage":"data","action":"accept","timestamp":"2026-09-05T12:00:00Z","protocol":{"version":"1.0"},"rawMessage":"U3ViamVjdDogdGVzdA0KDQpoZWxsbw0K","envelope":{"from":{"address":null,"parameters":{"SIZE":"24"}},"to":[{"address":"rcpt@example.com","parameters":{"ORCPT":"rfc822;rcpt@example.com"}}]},"client":{"ip":"192.0.2.1","ehlo":"mx.example.com"},"queue":{"id":"Q123"}})";
}
static msg_ptr decode(const std::string &s, size_t limit = 1024)
{
	GError *err = nullptr;
	msg_ptr m{rspamd_mta_hooks_decode(s.data(), s.size(), limit, &err), rspamd_http_message_unref};
	if (err) g_error_free(err);
	return m;
}
static msg_ptr encode(const char *s, bool rewritten = false)
{
	auto *p = ucl_parser_new(UCL_PARSER_SAFE_FLAGS);
	REQUIRE(ucl_parser_add_chunk(p, reinterpret_cast<const unsigned char *>(s), strlen(s)));
	auto *o = ucl_parser_get_object(p);
	ucl_parser_free(p);
	msg_ptr m{rspamd_mta_hooks_encode(o, rewritten), rspamd_http_message_unref};
	ucl_object_unref(o);
	return m;
}
static std::string body(rspamd_http_message *m)
{
	gsize n;
	auto *s = rspamd_http_message_get_body(m, &n);
	return {s ? s : "", n};
}
}// namespace hooks_test

TEST_SUITE("mta_hooks")
{
	TEST_CASE("DATA conversion preserves message and approved metadata")
	{
		auto m = hooks_test::decode(hooks_test::request());
		REQUIRE(m);
		CHECK(hooks_test::body(m.get()) == "Subject: test\r\n\r\nhello\r\n");
		CHECK(std::string(m->url->str, m->url->len) == "/checkv2");
		auto *from = rspamd_http_message_find_header(m.get(), "From");
		REQUIRE(from);
		CHECK(std::string(from->begin, from->len) == "<>");
		CHECK(rspamd_http_message_find_header(m.get(), "X-Rspamd-Rcpt-Esmtp-Args") != nullptr);
		CHECK(rspamd_http_message_find_header(m.get(), "Authorization") == nullptr);
		CHECK(rspamd_http_message_find_header(m.get(), "Settings") == nullptr);
	}
	TEST_CASE("untrusted UCL and bounded message")
	{
		CHECK_FALSE(hooks_test::decode(hooks_test::request(), 4));
		auto s = hooks_test::request();
		s.insert(1, "\"stage\":\"data\",");
		CHECK_FALSE(hooks_test::decode(s));
		s = hooks_test::request();
		s.insert(1, "\"st\\u0061ge\":\"data\",");
		CHECK_FALSE(hooks_test::decode(s));

		// No separate JSON grammar: safe UCL syntax is deliberately accepted.
		s = hooks_test::request();
		s.replace(s.find("\"stage\":\"data\""), strlen("\"stage\":\"data\""), "stage = \"data\"");
		CHECK(hooks_test::decode(s));
		s = hooks_test::request();
		s.insert(s.size() - 1, ",");
		CHECK(hooks_test::decode(s));
		s = hooks_test::request();
		s.insert(1, "\n.include \"/mta-hooks-does-not-exist\"\n");
		CHECK_FALSE(hooks_test::decode(s));// macros disabled, not executed

		s = hooks_test::request();
		s.insert(1, "\"extra\":" + std::string(20, '[') + "null" + std::string(20, ']') + ",");
		CHECK_FALSE(hooks_test::decode(s));// parser nesting budget
		s = hooks_test::request();
		s.insert(1, "\"" + std::string(257, 'k') + "\":0,");
		CHECK_FALSE(hooks_test::decode(s));// parser key budget
		std::string nodes = "\"extra\":[";
		for (int i = 0; i < 20001; ++i) {
			nodes += "0,";
		}
		nodes += "0],";
		s = hooks_test::request();
		s.insert(1, nodes);
		CHECK_FALSE(hooks_test::decode(s));// parser node budget, below HTTP size limit
		s = hooks_test::request();
		s.replace(s.find("U3Viam"), 1, "!");
		CHECK_FALSE(hooks_test::decode(s));
	}
	TEST_CASE("codec owns output but borrows length-delimited input")
	{
		const std::string bytes{"a\0b\xff\r\n", 6};
		gsize len;
		auto encoded = std::unique_ptr<char, decltype(&g_free)>{
			rspamd_encode_base64(reinterpret_cast<const unsigned char *>(bytes.data()), bytes.size(), 0, &len), g_free};
		auto source = hooks_test::request();
		source.replace(source.find("U3ViamVjdDogdGVzdA0KDQpoZWxsbw0K"), 32, encoded.get(), len);
		const auto request_len = source.size();
		source += "not part of the request";
		GError *error = nullptr;
		auto m = hooks_test::msg_ptr{
			rspamd_mta_hooks_decode(source.data(), request_len, 1024, &error), rspamd_http_message_unref};
		REQUIRE(error == nullptr);
		REQUIRE(m);
		source.assign(source.size(), '!');
		CHECK(hooks_test::body(m.get()) == bytes);
		auto *helo = rspamd_http_message_find_header(m.get(), "Helo");
		REQUIRE(helo);
		CHECK(std::string(helo->begin, helo->len) == "mx.example.com");
	}
	TEST_CASE("canonical base64 accepts padding and rejects junk")
	{
		for (auto raw: {"YQ==", "YWI=", "YWJj"}) {
			auto s = hooks_test::request();
			s.replace(s.find("U3ViamVjdDogdGVzdA0KDQpoZWxsbw0K"), 32, raw);
			CHECK(hooks_test::decode(s));
		}
		for (auto raw: {"YR==", "YWJ=", "YQ= ", "YQ==AAAA", "====", ""}) {
			auto s = hooks_test::request();
			s.replace(s.find("U3ViamVjdDogdGVzdA0KDQpoZWxsbw0K"), 32, raw);
			CHECK_FALSE(hooks_test::decode(s));
		}
	}
	TEST_CASE("typed decoding errors propagate through the C API")
	{
		for (auto pair: {std::pair{"\"stage\":\"data\"", "\"stage\":true"},
						 std::pair{"\"rawMessage\":\"U3ViamVjdDogdGVzdA0KDQpoZWxsbw0K\"", "\"rawMessage\":[]"},
						 std::pair{"\"address\":null", "\"address\":3"},
						 std::pair{"\"SIZE\":\"24\"", "\"SIZE\":24"},
						 std::pair{"\"ip\":\"192.0.2.1\"", "\"ip\":false"},
						 std::pair{"\"ehlo\":\"mx.example.com\"", "\"ehlo\":{}"},
						 std::pair{"\"id\":\"Q123\"", "\"id\":[]"}}) {
			auto s = hooks_test::request();
			s.replace(s.find(pair.first), strlen(pair.first), pair.second);
			GError *error = nullptr;
			auto m = hooks_test::msg_ptr{
				rspamd_mta_hooks_decode(s.data(), s.size(), 1024, &error), rspamd_http_message_unref};
			CHECK_FALSE(m);
			REQUIRE(error);
			CHECK(error->code == 400);
			CHECK(strlen(error->message) > 0);
			g_error_free(error);
		}
	}
	TEST_CASE("fast UTF-8 validation and UTC timestamps")
	{
		for (auto date: {"2026-02-30T12:00:00Z", "xxxx-09-05T12:00:00Z", "2026-09-05T24:00:00Z",
						 "2026-09-05T12:60:00Z", "2026-09-05T12:00:00.Z", "2026-09-05T12:00:00+01:00"}) {
			auto s = hooks_test::request();
			s.replace(s.find("2026-09-05T12:00:00Z"), 20, date);
			CHECK_FALSE(hooks_test::decode(s));
		}
		auto s = hooks_test::request();
		s.replace(s.find("2026-09-05T12:00:00Z"), 20, "2024-02-29T12:00:00.123Z");
		CHECK(hooks_test::decode(s));
		s = hooks_test::request();
		s.replace(s.find("mx.example.com"), 14, "m\xc3\xa9.example.com");
		CHECK(hooks_test::decode(s));
		s = hooks_test::request();
		s.replace(s.find("mx.example.com"), 14, "\xff");
		CHECK_FALSE(hooks_test::decode(s));
		CHECK(hooks_test::encode("{\"action\":\"no action\",\"milter\":{\"add_headers\":{\"X-Test\":\"m\xc3\xa9\"}}}")->code == 200);
		CHECK(hooks_test::encode("{\"action\":\"no action\",\"milter\":{\"add_headers\":{\"X-Test\":\"\xff\"}}}")->code == 503);
	}
	TEST_CASE("reject metadata injection and null recipients")
	{
		auto s = hooks_test::request();
		s.replace(s.find("mx.example.com"), strlen("mx.example.com"), "mx\\r\\nSettings: evil");
		CHECK_FALSE(hooks_test::decode(s));
		s = hooks_test::request();
		s.replace(s.find("\"rcpt@example.com\""), strlen("\"rcpt@example.com\""), "null");
		CHECK_FALSE(hooks_test::decode(s));
	}
	TEST_CASE("no action preserves previous decision")
	{
		auto m = hooks_test::encode(R"({"action":"no action"})");
		CHECK(m->code == 204);
		CHECK(hooks_test::body(m.get()).empty());
	}
	TEST_CASE("verdict and additive headers")
	{
		for (auto pair: {std::pair{"reject", "550"}, std::pair{"soft reject", "451"}}) {
			std::string s = "{\"action\":\"" + std::string(pair.first) + "\",\"messages\":{\"smtp_message\":\"Policy\"}}";
			auto m = hooks_test::encode(s.c_str());
			CHECK(m->code == 200);
			CHECK(hooks_test::body(m.get()).find(pair.second) != std::string::npos);
		}
		auto m = hooks_test::encode(R"({"action":"no action","milter":{"add_headers":{"X-Test":{"value":"yes","order":0}}}})");
		CHECK(m->code == 200);
		CHECK(hooks_test::body(m.get()).find("/message/headers") != std::string::npos);
	}
	TEST_CASE("unsupported changes fail atomically")
	{
		for (auto s: {R"({"action":"rewrite subject","subject":"spam"})",
					  R"({"action":"add header"})", R"({"action":"no action","dkim-signature":"sig"})",
					  R"({"action":"no action","milter":{"add_headers":{"X-Test":"yes"},"remove_headers":{"X-Test":0}}})",
					  R"({"action":"no action","milter":{"add_headers":{"X-Test":"a\r\nb"}}})"}) {
			auto m = hooks_test::encode(s);
			CHECK(m->code == 503);
			CHECK(hooks_test::body(m.get()).find("\"add\"") == std::string::npos);
		}
		CHECK(hooks_test::encode(R"({"action":"no action"})", true)->code == 503);
	}
	TEST_CASE("dedicated frontend requires TLS and bearer authentication")
	{
		rspamd_config cfg{};
		cfg.max_message = 1024 * 1024;
		auto *o = ucl_object_typed_new(UCL_OBJECT);
		ucl_object_insert_key(o, ucl_object_frombool(true), "enabled", 0, false);
		ucl_object_insert_key(o, ucl_object_fromstring("01234567890123456789012345678901"), "token", 0, false);
		ucl_object_insert_key(o, ucl_object_fromstring("127.0.0.1"), "redis_host", 0, false);
		GError *error = nullptr;
		auto c = std::unique_ptr<rspamd_mta_hooks_config, decltype(&rspamd_mta_hooks_config_free)>(
			rspamd_mta_hooks_config_new(o, &cfg, &error), rspamd_mta_hooks_config_free);
		ucl_object_unref(o);
		REQUIRE(error == nullptr);
		REQUIRE(c);
		auto request = hooks_test::msg_ptr{rspamd_http_new_message(HTTP_REQUEST), rspamd_http_message_unref};
		request->method = HTTP_GET;
		request->url = rspamd_fstring_append(request->url, "/checkv2", 8);
		auto run = [&](bool tls) {
			auto *r = rspamd_mta_hooks_request_new(c.get(), request.get(), tls, true);
			rspamd_http_message *response = nullptr;
			rspamd_mta_hooks_begin(r, [](rspamd_http_message *m, gboolean scan, gpointer ud) {
				CHECK_FALSE(scan);
				*static_cast<rspamd_http_message **>(ud) = m; }, &response);
			rspamd_mta_hooks_request_free(r);
			REQUIRE(response);
			return hooks_test::msg_ptr{response, rspamd_http_message_unref};
		};
		CHECK(run(false)->code == 403);// loopback alone does not bypass TLS
		CHECK(run(true)->code == 401);
		rspamd_http_message_add_header(request.get(), "Authorization", "Bearer 01234567890123456789012345678901");
		CHECK(run(true)->code == 404);// native scan interface is not exposed
		rspamd_http_message_add_header(request.get(), "Authorization", "Bearer second");
		CHECK(run(true)->code == 400);// ambiguous credentials are rejected
	}
}
#endif
