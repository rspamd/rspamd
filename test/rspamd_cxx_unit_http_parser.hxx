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

/* Bundled http-parser: request/response parsing and URL splitting */

#ifndef RSPAMD_CXX_UNIT_HTTP_PARSER_HXX
#define RSPAMD_CXX_UNIT_HTTP_PARSER_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "config.h"
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <string_view>

#include "http_parser.h"
#include "libserver/http/http_message.h"

namespace hp_test {

struct parse_result {
	std::string err;// http_errno_name()
	size_t used = 0;
	int begin = 0;
	int hc = 0;
	int mc = 0;
	size_t body = 0;
	std::string transcript;// U:/F:/V:/S:/B: callbacks, same-kind runs merged
	bool upgrade = false;
	int method = 0;
	unsigned flags = 0;
	int keep_alive = 0;// http_should_keep_alive() after the last byte
};

struct cb_state {
	parse_result *res;
	char last = 0;
};

static void cb_note(http_parser *p, char tag, const char *at, size_t len)
{
	auto *st = static_cast<cb_state *>(p->data);

	if (st->last != tag) {
		st->res->transcript += (st->res->transcript.empty() ? "" : "|");
		st->res->transcript += tag;
		st->res->transcript += ':';
		st->last = tag;
	}
	st->res->transcript.append(at, len);
}

static int cb_begin(http_parser *p)
{
	auto *st = static_cast<cb_state *>(p->data);
	st->res->begin++;
	st->last = 0;
	return 0;
}
static int cb_url(http_parser *p, const char *at, size_t len)
{
	cb_note(p, 'U', at, len);
	return 0;
}
static int cb_status(http_parser *p, const char *at, size_t len)
{
	cb_note(p, 'S', at, len);
	return 0;
}
static int cb_field(http_parser *p, const char *at, size_t len)
{
	cb_note(p, 'F', at, len);
	return 0;
}
static int cb_value(http_parser *p, const char *at, size_t len)
{
	cb_note(p, 'V', at, len);
	return 0;
}
static int cb_hc(http_parser *p)
{
	auto *st = static_cast<cb_state *>(p->data);
	st->res->hc++;
	st->last = 0;
	return 0;
}
static int cb_body(http_parser *p, const char *at, size_t len)
{
	auto *st = static_cast<cb_state *>(p->data);
	st->res->body += len;
	cb_note(p, 'B', at, len);
	return 0;
}
static int cb_mc(http_parser *p)
{
	auto *st = static_cast<cb_state *>(p->data);
	st->res->mc++;
	st->last = 0;
	return 0;
}

/* type: 0 request, 1 response. The wire is copied into an exact-size heap
 * buffer so that sanitizers see any read past its end. */
static parse_result parse(int type, std::string_view wire, bool bytewise, bool eof = true)
{
	parse_result res;
	cb_state st;
	st.res = &res;

	http_parser_settings s;
	std::memset(&s, 0, sizeof(s));
	s.on_message_begin = cb_begin;
	s.on_url = cb_url;
	s.on_status = cb_status;
	s.on_header_field = cb_field;
	s.on_header_value = cb_value;
	s.on_headers_complete = cb_hc;
	s.on_body = cb_body;
	s.on_message_complete = cb_mc;

	http_parser p;
	http_parser_init(&p, type == 0 ? HTTP_REQUEST : HTTP_RESPONSE);
	p.data = &st;

	std::unique_ptr<char[]> buf(new char[wire.size() ? wire.size() : 1]);
	if (!wire.empty()) {
		std::memcpy(buf.get(), wire.data(), wire.size());
	}

	bool failed = false;

	if (bytewise) {
		for (size_t i = 0; i < wire.size(); i++) {
			size_t r = http_parser_execute(&p, &s, buf.get() + i, 1);
			res.used += r;
			if (r != 1 || HTTP_PARSER_ERRNO(&p) != HPE_OK) {
				failed = true;
				break;
			}
		}
	}
	else if (!wire.empty()) {
		size_t r = http_parser_execute(&p, &s, buf.get(), wire.size());
		res.used = r;
		if (r != wire.size() || HTTP_PARSER_ERRNO(&p) != HPE_OK) {
			failed = true;
		}
	}

	if (!failed && eof) {
		http_parser_execute(&p, &s, nullptr, 0);
	}

	res.err = http_errno_name(HTTP_PARSER_ERRNO(&p));
	res.upgrade = p.upgrade != 0;
	res.method = p.method;
	res.flags = p.flags;
	res.keep_alive = http_should_keep_alive(&p);

	return res;
}

struct url_result {
	int rc;
	uint16_t set;
	uint16_t port;
	uint16_t raw_off[UF_MAX];
	uint16_t raw_len[UF_MAX];
	std::string field[UF_MAX];
	bool present[UF_MAX];
};

static url_result parse_url(std::string_view url, int is_connect, size_t buflen = std::string_view::npos)
{
	url_result r;
	struct http_parser_url u;

	std::memset(&u, 0xAA, sizeof(u));
	std::unique_ptr<char[]> buf(new char[url.size() ? url.size() : 1]);
	if (!url.empty()) {
		std::memcpy(buf.get(), url.data(), url.size());
	}
	if (buflen == std::string_view::npos) {
		buflen = url.size();
	}

	r.rc = http_parser_parse_url(buf.get(), buflen, is_connect, &u);
	r.set = u.field_set;
	r.port = u.port;
	for (int i = 0; i < UF_MAX; i++) {
		r.raw_off[i] = u.field_data[i].off;
		r.raw_len[i] = u.field_data[i].len;
		r.present[i] = (u.field_set & (1 << i)) != 0;
		if (r.present[i]) {
			r.field[i].assign(buf.get() + u.field_data[i].off, u.field_data[i].len);
		}
	}

	return r;
}

}// namespace hp_test

/* Whole buffer and byte at a time must agree on the outcome */
#define HP_CHECK_BOTH(type, wire, eof, expr_err, expr_body, expr_mc) \
	do {                                                             \
		auto whole_ = hp_test::parse((type), (wire), false, (eof));  \
		auto bytes_ = hp_test::parse((type), (wire), true, (eof));   \
		CHECK(whole_.err == (expr_err));                             \
		CHECK(bytes_.err == whole_.err);                             \
		CHECK(whole_.body == (size_t) (expr_body));                  \
		CHECK(bytes_.body == whole_.body);                           \
		CHECK(whole_.mc == (expr_mc));                               \
		CHECK(bytes_.mc == whole_.mc);                               \
		CHECK(bytes_.hc == whole_.hc);                               \
		CHECK(bytes_.method == whole_.method);                       \
		CHECK(bytes_.flags == whole_.flags);                         \
		CHECK(bytes_.keep_alive == whole_.keep_alive);               \
	} while (0)

TEST_SUITE("http_parser")
{
	TEST_CASE("http parser url: schema without host")
	{
		auto r = hp_test::parse_url("http:///x", 0);
		CHECK(r.rc == 1);
		CHECK(r.set == 0x9);
		CHECK(r.field[UF_PATH] == "/x");

		r = hp_test::parse_url("http://?q", 0);
		CHECK(r.rc == 1);
		CHECK(r.set == 0x11);
		CHECK(r.field[UF_QUERY] == "q");

		r = hp_test::parse_url("http:", 0);
		CHECK(r.rc == 1);
		CHECK(r.set == 0x1);

		r = hp_test::parse_url("h", 0);
		CHECK(r.rc == 1);
		CHECK(r.set == 0x1);

		/* The host data was never touched (the struct is prefilled with 0xAA) */
		for (const char *u: {"http:///x", "http://?q", "http:", "h"}) {
			r = hp_test::parse_url(u, 0);
			CHECK(r.raw_off[UF_HOST] == 0xAAAA);
			CHECK(r.raw_len[UF_HOST] == 0xAAAA);
		}
	}

	TEST_CASE("http parser url: well-formed absolute urls")
	{
		auto r = hp_test::parse_url("http://h/x", 0);
		CHECK(r.rc == 0);
		CHECK(r.set == 0xb);
		CHECK(r.field[UF_HOST] == "h");
		CHECK(r.field[UF_PATH] == "/x");

		r = hp_test::parse_url("http://h:8080/x?y#z", 0);
		CHECK(r.rc == 0);
		CHECK(r.set == 0x3f);
		CHECK(r.port == 8080);

		r = hp_test::parse_url("http://u@h:1/", 0);
		CHECK(r.rc == 0);
		CHECK(r.set == 0x4f);

		r = hp_test::parse_url("http://[::1]:80/", 0);
		CHECK(r.rc == 0);
		CHECK(r.field[UF_HOST] == "::1");
	}

	TEST_CASE("http parser url: connect and path callers")
	{
		auto r = hp_test::parse_url("h:80", 1);
		CHECK(r.rc == 0);
		CHECK(r.set == 0x6);
		CHECK(r.port == 80);

		/* Callers that pass is_connect for plain paths read the fields
		 * even though the call fails */
		r = hp_test::parse_url("/checkv2?x=1", 1);
		CHECK(r.rc == 1);
		CHECK(r.set == 0x18);
		CHECK(r.field[UF_PATH] == "/checkv2");
		CHECK(r.field[UF_QUERY] == "x=1");

		r = hp_test::parse_url("/checkv2?x=1", 0);
		CHECK(r.rc == 0);
		CHECK(r.set == 0x18);
	}

	TEST_CASE("http parser url: port parsing is bounded by the buffer")
	{
		auto r = hp_test::parse_url("http://example.com:8001", 0, 22);
		CHECK(r.rc == 0);
		CHECK(r.port == 800);

		r = hp_test::parse_url("http://example.com:8001", 0, 23);
		CHECK(r.rc == 0);
		CHECK(r.port == 8001);

		r = hp_test::parse_url("h:65535", 1);
		CHECK(r.rc == 0);
		CHECK(r.port == 65535);

		r = hp_test::parse_url("h:65536", 1);
		CHECK(r.rc == 1);
		CHECK(r.set == 0x6);
		CHECK(r.port == 0);

		r = hp_test::parse_url("h:12", 1, 3);
		CHECK(r.port == 1);
	}

	TEST_CASE("http parser: request with schema-only absolute url")
	{
		/* The request line parser does not validate the URL itself */
		HP_CHECK_BOTH(0, "GET http:///x HTTP/1.1\r\n\r\n", true, "HPE_OK", 0, 1);
		auto r = hp_test::parse(0, "GET http:///x HTTP/1.1\r\n\r\n", false);
		CHECK(r.transcript == "U:http:///x");
	}

	TEST_CASE("http parser: legacy invariants")
	{
		/* spamc/rspamc request lines, bare LF, any letter case */
		HP_CHECK_BOTH(0, "SYMBOLS RSPAMC/1.3\nContent-length: 5\n\nhello", false,
					  "HPE_OK", 5, 1);
		{
			auto r = hp_test::parse(0, "SYMBOLS RSPAMC/1.3\nContent-length: 5\n\nhello", false, false);
			CHECK(r.method == HTTP_SYMBOLS);
		}

		HP_CHECK_BOTH(0, "CHECK SPAMC/1.2\r\nContent-length: 5\r\nUser: x\r\n\r\nhello", true,
					  "HPE_OK", 5, 1);
		{
			auto r = hp_test::parse(0, "CHECK SPAMC/1.2\r\nContent-length: 5\r\nUser: x\r\n\r\nhello", false, true);
			CHECK(r.method == HTTP_CHECK);
			CHECK((r.flags & F_SPAMC) != 0);
		}

		HP_CHECK_BOTH(0, "SYMBOLS SPAMC/1.2\nContent-Length: 3\n\nabc", false,
					  "HPE_OK", 3, 1);

		/* EOF inside a counted body */
		HP_CHECK_BOTH(0, "SYMBOLS RSPAMC/1.3\nContent-length: 5\n\nhel", true,
					  "HPE_INVALID_EOF_STATE", 3, 0);

		/* A response without a length is completed by EOF */
		HP_CHECK_BOTH(1, "HTTP/1.1 200 OK\r\n\r\nbody", true, "HPE_OK", 4, 1);

		/* Keep-alive only with an explicit header */
		{
			std::string_view with = "POST /checkv2 HTTP/1.1\r\nConnection: keep-alive\r\n"
									"Content-Length: 3\r\n\r\nabc";
			std::string_view without = "POST /checkv2 HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc";

			for (bool bytewise: {false, true}) {
				auto a = hp_test::parse(0, with, bytewise, false);
				CHECK(a.err == "HPE_OK");
				CHECK(a.mc == 1);
				CHECK(a.keep_alive == 1);

				auto b = hp_test::parse(0, without, bytewise, false);
				CHECK(b.err == "HPE_OK");
				CHECK(b.mc == 1);
				CHECK(b.keep_alive == 0);
			}
		}
	}
}

#endif
