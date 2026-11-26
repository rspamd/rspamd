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
	unsigned http_major = 0;
	unsigned http_minor = 0;
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
	res.http_major = p.http_major;
	res.http_minor = p.http_minor;

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


/* Value of the first header called name in a transcript ("F:X|V:y|..."),
 * or "<none>" */
static std::string header_value(const std::string &tr, const std::string &name)
{
	std::string key = "F:" + name + "|V:";
	auto pos = tr.find(key);

	if (pos == std::string::npos) {
		return "<none>";
	}
	pos += key.size();
	auto end = tr.find('|', pos);

	return tr.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
}

}// namespace hp_test

/* A literal that may contain NUL bytes */
#define HP_SV(lit) std::string_view((lit), sizeof(lit) - 1)

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

	TEST_CASE("http parser: method matching is position exact")
	{
		/* Used to read past the end of "SYMBOLS" */
		HP_CHECK_BOTH(0, "SUBSCRIBY RSPAMC/1.3\r\n\r\n", false, "HPE_INVALID_METHOD", 0, 0);
		HP_CHECK_BOTH(0, "SUBSCRIBEY RSPAMC/1.3\r\n\r\n", false, "HPE_INVALID_METHOD", 0, 0);
		HP_CHECK_BOTH(0, "SUBSCRIBYXX RSPAMC/1.3\r\n\r\n", false, "HPE_INVALID_METHOD", 0, 0);
		HP_CHECK_BOTH(0, "SUBSCRIYX /a HTTP/1.1\r\n\r\n", false, "HPE_INVALID_METHOD", 0, 0);
		/* The method must be refused at the offending byte itself */
		for (bool bw: {false, true}) {
			CHECK(hp_test::parse(0, "SUBSCRIBY RSPAMC/1.3\r\n\r\n", bw).used == 8);
			CHECK(hp_test::parse(0, "SUBSCRIBEY RSPAMC/1.3\r\n\r\n", bw).used == 9);
			CHECK(hp_test::parse(0, "SUBSCRIBYXX RSPAMC/1.3\r\n\r\n", bw).used == 8);
			CHECK(hp_test::parse(0, "SUBSCRIYX /a HTTP/1.1\r\n\r\n", bw).used == 7);
		}
		/* Used to be accepted as SYMBOLS */
		HP_CHECK_BOTH(0, "SUBYOLS RSPAMC/1.3\r\n\r\n", false, "HPE_INVALID_METHOD", 0, 0);

		HP_CHECK_BOTH(0, "CHECKOUT /a HTTP/1.1\r\n\r\n", false, "HPE_INVALID_METHOD", 0, 0);
		HP_CHECK_BOTH(0, "GXT /a HTTP/1.1\r\n\r\n", false, "HPE_INVALID_METHOD", 0, 0);
		HP_CHECK_BOTH(0, "DXLETE /a HTTP/1.1\r\n\r\n", false, "HPE_INVALID_METHOD", 0, 0);

		HP_CHECK_BOTH(0, "SYMBOLS RSPAMC/1.3\r\nContent-Length: 3\r\n\r\nabc", true,
					  "HPE_OK", 3, 1);
		{
			auto r = hp_test::parse(0, "SYMBOLS RSPAMC/1.3\r\nContent-Length: 3\r\n\r\nabc", false);
			CHECK(r.method == HTTP_SYMBOLS);
		}

		HP_CHECK_BOTH(0, "CHECK SPAMC/1.2\r\nContent-length: 3\r\n\r\nabc", true,
					  "HPE_OK", 3, 1);
		{
			auto r = hp_test::parse(0, "CHECK SPAMC/1.2\r\nContent-length: 3\r\n\r\nabc", false);
			CHECK(r.method == HTTP_CHECK);
			CHECK((r.flags & F_SPAMC) != 0);
		}
	}

	TEST_CASE("http parser: every method parses to itself")
	{
		const char *methods[] = {"DELETE", "GET", "HEAD", "POST", "PUT", "CONNECT", "OPTIONS",
								 "TRACE", "COPY", "LOCK", "MKCOL", "MOVE", "PROPFIND",
								 "PROPPATCH", "SEARCH", "UNLOCK", "REPORT", "MKACTIVITY",
								 "MERGE", "M-SEARCH", "NOTIFY", "SUBSCRIBE", "UNSUBSCRIBE",
								 "PATCH", "PURGE"};

		for (const char *m: methods) {
			CAPTURE(m);
			std::string wire = m;
			wire += std::string_view(m) == "CONNECT" ? " h:80 HTTP/1.1\r\n\r\n"
													 : " /a HTTP/1.1\r\n\r\n";
			HP_CHECK_BOTH(0, wire, true, "HPE_OK", 0, 1);
			auto r = hp_test::parse(0, wire, false);
			CHECK(std::string_view(http_method_str((enum http_method) r.method)) == m);
		}
	}

	TEST_CASE("http parser: Upgrade header does not end the message")
	{
		std::string_view w1 = "POST /checkv2 HTTP/1.1\r\nUpgrade: h2c\r\nContent-Length: 3\r\n\r\nabc";
		HP_CHECK_BOTH(0, w1, true, "HPE_OK", 3, 1);
		for (bool bw: {false, true}) {
			auto r = hp_test::parse(0, w1, bw);
			CHECK(r.used == w1.size());
			CHECK(r.used == 62);
			/* the field is always 0 now; the checks on mc and used are the real ones */
			CHECK(!r.upgrade);
			CHECK(r.mc == 1);
		}

		std::string_view w2 = "POST /checkv2 HTTP/1.1\r\nConnection: Upgrade, HTTP2-Settings\r\n"
							  "Upgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAoAAAAAIAAAAA\r\n"
							  "Content-Length: 3\r\n\r\nabc";
		HP_CHECK_BOTH(0, w2, true, "HPE_OK", 3, 1);
		for (bool bw: {false, true}) {
			auto r = hp_test::parse(0, w2, bw);
			CHECK(r.used == w2.size());
			CHECK(r.used == 141);
		}

		/* Pipelined request after a keep-alive request with Upgrade */
		std::string_view w3 = "POST /a HTTP/1.1\r\nConnection: keep-alive\r\nUpgrade: h2c\r\n"
							  "Content-Length: 3\r\n\r\nabcGET /b HTTP/1.1\r\n\r\n";
		HP_CHECK_BOTH(0, w3, true, "HPE_OK", 3, 2);
		for (bool bw: {false, true}) {
			auto r = hp_test::parse(0, w3, bw);
			CHECK(r.used == w3.size());
			CHECK(r.used == 99);
			CHECK(r.begin == 2);
		}

		/* The body must not be parsed as a second request */
		std::string_view w4 = "POST /a HTTP/1.1\r\nConnection: keep-alive\r\nUpgrade: x\r\n"
							  "Content-Length: 20\r\n\r\nGET /evil HTTP/1.1\r\n\r\n";
		HP_CHECK_BOTH(0, w4, true, "HPE_OK", 20, 1);
		for (bool bw: {false, true}) {
			auto r = hp_test::parse(0, w4, bw);
			CHECK(r.begin == 1);
			CHECK(r.mc == 1);
			CHECK(r.body == 20);
		}

		std::string_view w5 = "POST /a HTTP/1.1\r\nUpgrade: h2c\r\nTransfer-Encoding: chunked\r\n\r\n"
							  "3\r\nabc\r\n0\r\n\r\n";
		HP_CHECK_BOTH(0, w5, true, "HPE_OK", 3, 1);
		for (bool bw: {false, true}) {
			CHECK(hp_test::parse(0, w5, bw).used == w5.size());
		}

		/* EOF inside the body is an error now */
		HP_CHECK_BOTH(0, "POST /a HTTP/1.1\r\nUpgrade: h2c\r\nContent-Length: 3\r\n\r\nab", true,
					  "HPE_INVALID_EOF_STATE", 2, 0);

		/* The second request is only seen if Upgrade does not end the parse */
		for (bool bw: {false, true}) {
			auto r = hp_test::parse(0,
									"GET /ping HTTP/1.1\r\nUpgrade: websocket\r\nConnection: keep-alive\r\n\r\n"
									"GET /pong HTTP/1.1\r\n\r\n",
									bw);
			CHECK(r.err == "HPE_OK");
			CHECK(r.mc == 2);
		}

		/* Legacy request lines */
		std::string_view w6 = "CHECK SPAMC/1.2\r\nContent-length: 3\r\nUpgrade: x\r\n\r\nabc";
		HP_CHECK_BOTH(0, w6, true, "HPE_OK", 3, 1);
		for (bool bw: {false, true}) {
			auto r = hp_test::parse(0, w6, bw);
			CHECK(r.used == w6.size());
			CHECK(r.used == 53);
			CHECK(r.method == HTTP_CHECK);
			CHECK((r.flags & F_SPAMC) != 0);
		}
		HP_CHECK_BOTH(0, "SYMBOLS SPAMC/1.2\nUpgrade: x\nContent-length: 3\n\nabc", true,
					  "HPE_OK", 3, 1);
	}

	TEST_CASE("http parser: Upgrade header in responses")
	{
		std::string_view w1 = "HTTP/1.1 200 OK\r\nUpgrade: h2,h2c\r\nConnection: Upgrade\r\n"
							  "Content-Length: 3\r\n\r\nabc";
		HP_CHECK_BOTH(1, w1, true, "HPE_OK", 3, 1);
		for (bool bw: {false, true}) {
			auto r = hp_test::parse(1, w1, bw);
			CHECK(r.used == w1.size());
			CHECK(r.used == 79);
		}

		HP_CHECK_BOTH(1, "HTTP/1.1 200 OK\r\nUpgrade: h2\r\n\r\nbody-till-eof", true,
					  "HPE_OK", 13, 1);

		/* 101 is a body-less 1xx message; what follows closes the connection */
		std::string_view w2 = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\n"
							  "Connection: Upgrade\r\n\r\nxyz";
		HP_CHECK_BOTH(1, w2, false, "HPE_CLOSED_CONNECTION", 0, 1);
		for (bool bw: {false, true}) {
			auto r = hp_test::parse(1, w2, bw, false);
			CHECK(r.mc == 1);
			CHECK(r.used == 71);
			CHECK(w2.size() == 74);
		}
	}

	namespace hp_test_reinit {
	static int reinit_hc_calls;
	static int reinit_mc_calls;
	static int reinit_hc(http_parser *p)
	{
		reinit_hc_calls++;
		if (reinit_hc_calls == 1) {
			void *d = p->data;
			http_parser_init(p, HTTP_RESPONSE);
			p->data = d;
			return 1;
		}
		return 0;
	}
	static int reinit_mc(http_parser *)
	{
		reinit_mc_calls++;
		return 0;
	}
	}// namespace hp_test_reinit

	TEST_CASE("http parser: re-init inside on_headers_complete")
	{
		std::string_view w = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n";
		http_parser_settings s;
		std::memset(&s, 0, sizeof(s));
		s.on_headers_complete = hp_test_reinit::reinit_hc;
		s.on_message_complete = hp_test_reinit::reinit_mc;
		for (bool bytewise: {false, true}) {
			hp_test_reinit::reinit_hc_calls = 0;
			hp_test_reinit::reinit_mc_calls = 0;

			http_parser p;
			http_parser_init(&p, HTTP_RESPONSE);
			size_t r = 0;
			if (bytewise) {
				for (size_t i = 0; i < w.size(); i++) {
					std::unique_ptr<char[]> one(new char[1]);
					one[0] = w[i];
					r += http_parser_execute(&p, &s, one.get(), 1);
				}
			}
			else {
				std::unique_ptr<char[]> buf(new char[w.size()]);
				std::memcpy(buf.get(), w.data(), w.size());
				r = http_parser_execute(&p, &s, buf.get(), w.size());
			}
			CAPTURE(bytewise);
			CHECK(HTTP_PARSER_ERRNO(&p) == HPE_OK);
			CHECK(r == w.size());
			CHECK(r == 65);
			CHECK(hp_test_reinit::reinit_hc_calls == 2);
			/* The 204 completes; the reset parser must not report a message for the first one */
			CHECK(hp_test_reinit::reinit_mc_calls == 1);
		}
	}

	namespace hp_test_reinit_mc {
	static int hc_calls;
	static int mc_calls;
	static int hc(http_parser *)
	{
		hc_calls++;
		return 0;
	}
	static int mc(http_parser *p)
	{
		mc_calls++;
		if (mc_calls == 1) {
			void *d = p->data;
			http_parser_init(p, HTTP_RESPONSE);
			p->data = d;
		}
		return 0;
	}
	}// namespace hp_test_reinit_mc

	TEST_CASE("http parser: re-init inside on_message_complete")
	{
		/* An interim reply is completed and the parser is re-armed from the callback */
		std::string_view w = "HTTP/1.1 100 Continue\r\nContent-Length: 3\r\n\r\n"
							 "HTTP/1.1 500 Err\r\nContent-Length: 0\r\n\r\n";
		http_parser_settings s;
		std::memset(&s, 0, sizeof(s));
		s.on_headers_complete = hp_test_reinit_mc::hc;
		s.on_message_complete = hp_test_reinit_mc::mc;
		for (bool bytewise: {false, true}) {
			hp_test_reinit_mc::hc_calls = 0;
			hp_test_reinit_mc::mc_calls = 0;

			http_parser p;
			http_parser_init(&p, HTTP_RESPONSE);
			size_t r = 0;
			if (bytewise) {
				for (size_t i = 0; i < w.size(); i++) {
					char one = w[i];
					r += http_parser_execute(&p, &s, &one, 1);
				}
			}
			else {
				std::unique_ptr<char[]> buf(new char[w.size()]);
				std::memcpy(buf.get(), w.data(), w.size());
				r = http_parser_execute(&p, &s, buf.get(), w.size());
			}
			CAPTURE(bytewise);
			CHECK(HTTP_PARSER_ERRNO(&p) == HPE_OK);
			CHECK(r == w.size());
			CHECK(hp_test_reinit_mc::hc_calls == 2);
			CHECK(hp_test_reinit_mc::mc_calls == 2);
		}
	}

	TEST_CASE("http parser: obs-fold in header values")
	{
		for (bool bw: {false, true}) {
			auto r = hp_test::parse(0, "GET /a HTTP/1.1\r\nX: a\r\n\tb\r\n\r\n", bw);
			CHECK(r.err == "HPE_OK");
			CHECK(hp_test::header_value(r.transcript, "X") == "a\tb");
		}

		std::string_view crlf = "GET / HTTP/1.1\r\n"
								"Line1:   abc\r\n"
								"\tdef\r\n"
								" ghi\r\n"
								"\t\tjkl\r\n"
								"  mno \r\n"
								"\t \tqrs\r\n"
								"Line2: \t line2\t\r\n"
								"Line3:\r\n"
								" line3\r\n"
								"Line4: \r\n"
								" \r\n"
								"Connection:\r\n"
								" close\r\n"
								"\r\n";
		std::string_view lf = "GET / HTTP/1.1\n"
							  "Line1:   abc\n"
							  "\tdef\n"
							  " ghi\n"
							  "\t\tjkl\n"
							  "  mno \n"
							  "\t \tqrs\n"
							  "Line2: \t line2\t\n"
							  "Line3:\n"
							  " line3\n"
							  "Line4: \n"
							  " \n"
							  "Connection:\n"
							  " close\n"
							  "\n";
		for (auto w: {crlf, lf}) {
			HP_CHECK_BOTH(0, w, true, "HPE_OK", 0, 1);
			for (bool bw: {false, true}) {
				auto r = hp_test::parse(0, w, bw);
				CHECK(hp_test::header_value(r.transcript, "Line1") == "abc\tdef ghi\t\tjkl  mno \t \tqrs");
				CHECK(hp_test::header_value(r.transcript, "Line2") == "line2\t");
				CHECK(hp_test::header_value(r.transcript, "Line3") == "line3");
				CHECK(hp_test::header_value(r.transcript, "Line4") == "");
				CHECK(hp_test::header_value(r.transcript, "Connection") == "close");
				CHECK(r.keep_alive == 0);
			}
		}

		for (bool bw: {false, true}) {
			auto r = hp_test::parse(0, "GET / HTTP/1.1\nLine3:\n line3\n\n", bw);
			CHECK(r.err == "HPE_OK");
			CHECK(hp_test::header_value(r.transcript, "Line3") == "line3");
		}

		/* A fold that starts the value is honoured for the framing headers */
		HP_CHECK_BOTH(0, "POST /a HTTP/1.1\r\nTransfer-Encoding:\r\n chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
					  true, "HPE_OK", 3, 1);
		HP_CHECK_BOTH(0, "POST /a HTTP/1.1\r\nTransfer-Encoding:\r\n chunked\r\nContent-Length: 3\r\n\r\nabc",
					  true, "HPE_INVALID_CONTENT_LENGTH", 0, 0);
		HP_CHECK_BOTH(0, "POST /a HTTP/1.1\r\nContent-Length: 3\r\nTransfer-Encoding:\r\n chunked\r\n\r\nabc",
					  true, "HPE_INVALID_CONTENT_LENGTH", 0, 0);
		HP_CHECK_BOTH(0, "POST /a HTTP/1.1\r\nContent-Length:\r\n 5\r\n\r\nabcde", true, "HPE_OK", 5, 1);
		HP_CHECK_BOTH(0, "POST /a HTTP/1.1\r\nContent-Length: 1\r\n 2\r\n\r\nabcdefghijklmnop", true,
					  "HPE_INVALID_CONTENT_LENGTH", 0, 0);

		/* A folded chunked value is refused, never read as a plain body */
		HP_CHECK_BOTH(0, "POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n \r\n\r\n3\r\nabc\r\n0\r\n\r\n",
					  true, "HPE_INVALID_TRANSFER_ENCODING", 0, 0);
		HP_CHECK_BOTH(0, "POST /a HTTP/1.1\r\nTransfer-Encoding: chun\r\n ked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
					  true, "HPE_INVALID_TRANSFER_ENCODING", 0, 0);

		for (bool bw: {false, true}) {
			auto r = hp_test::parse(0, "POST /a HTTP/1.1\r\nConnection:\r\n keep-alive\r\nContent-Length: 0\r\n\r\n", bw);
			CHECK(r.err == "HPE_OK");
			CHECK(r.keep_alive == 1);
		}

		/* An empty header still gives a zero-length value */
		for (bool bw: {false, true}) {
			auto r = hp_test::parse(1, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nX-Empty:\r\nY: z\r\n\r\nabc", bw);
			CHECK(r.err == "HPE_OK");
			CHECK(r.body == 3);
			CHECK(hp_test::header_value(r.transcript, "X-Empty") == "");
			CHECK(hp_test::header_value(r.transcript, "Y") == "z");
		}

		/* A bare CR between header lines is not a line end */
		HP_CHECK_BOTH(0, "GET / HTTP/1.1\r\nFoo: 1\rBar: 1\r\n\r\n", true, "HPE_STRICT", 0, 0);
		HP_CHECK_BOTH(0, "GET / HTTP/1.1\r\nFoo: 1\rBar: 1", true, "HPE_STRICT", 0, 0);

		/* Half-close inside headers, and after a complete empty-valued header */
		HP_CHECK_BOTH(0, "GET / HTTP/1.1\r\nX:\r\n", true, "HPE_INVALID_EOF_STATE", 0, 0);
		HP_CHECK_BOTH(0, "GET / HTTP/1.1\r\nX:\r\n\r\n", true, "HPE_OK", 0, 1);
	}

	TEST_CASE("http parser: control characters in header values")
	{
		HP_CHECK_BOTH(0, HP_SV("GET /a HTTP/1.1\r\nX: a\x00"
							   "b\r\n\r\n"),
					  true, "HPE_INVALID_HEADER_TOKEN", 0, 0);
		HP_CHECK_BOTH(0, HP_SV("GET /a HTTP/1.1\r\nX: a\x01"
							   "b\r\n\r\n"),
					  true, "HPE_INVALID_HEADER_TOKEN", 0, 0);
		HP_CHECK_BOTH(0, HP_SV("GET /a HTTP/1.1\r\nX: a\x7f"
							   "b\r\n\r\n"),
					  true, "HPE_INVALID_HEADER_TOKEN", 0, 0);
		HP_CHECK_BOTH(0, HP_SV("GET /a HTTP/1.1\r\nX: a\r\n \x01\r\n\r\n"), true, "HPE_INVALID_HEADER_TOKEN", 0, 0);

		for (bool bw: {false, true}) {
			auto r = hp_test::parse(0, "GET /a HTTP/1.1\r\nX: a\tb\r\n\r\n", bw);
			CHECK(r.err == "HPE_OK");
			CHECK(hp_test::header_value(r.transcript, "X") == "a\tb");

			r = hp_test::parse(0, "GET /a HTTP/1.1\r\nX: \xc3\xa9t\xc3\xa9\r\n\r\n", bw);
			CHECK(r.err == "HPE_OK");
			CHECK(hp_test::header_value(r.transcript, "X") == "\xc3\xa9t\xc3\xa9");

			r = hp_test::parse(0, "GET /a HTTP/1.1\r\nX: \xff\r\n\r\n", bw);
			CHECK(r.err == "HPE_OK");
			CHECK(hp_test::header_value(r.transcript, "X") == "\xff");
		}

		HP_CHECK_BOTH(1, "HTTP/1.1 200 OK\r\nX: a\x01"
						 "b\r\nContent-Length: 1\r\n\r\nz",
					  true,
					  "HPE_INVALID_HEADER_TOKEN", 0, 0);

		/* Legacy request lines */
		HP_CHECK_BOTH(0, "CHECK SPAMC/1.2\nContent-length: 3\nUser: x\n\nabc", true, "HPE_OK", 3, 1);
		HP_CHECK_BOTH(0, "CHECK SPAMC/1.2\nContent-length: 3\nUser: x\x01y\n\nabc", true,
					  "HPE_INVALID_HEADER_TOKEN", 0, 0);
	}

	TEST_CASE("http message: control bytes in outgoing header values")
	{
		auto *msg = rspamd_http_new_message(HTTP_REQUEST);

		rspamd_http_message_add_header_len(msg, "X", "a\x01"
													 "b\r\nc",
										   6);
		rspamd_http_message_add_header_len(msg, "Y", "caf\xc3\xa9", 5);
		rspamd_http_message_add_header_len(msg, "Z", "a\tb", 3);
		rspamd_http_message_add_header_len(msg, "D", "a\x7f"
													 "b",
										   3);

		auto get = [&](const char *name) {
			auto *t = rspamd_http_message_find_header(msg, name);
			return t ? std::string(t->begin, t->len) : std::string("<none>");
		};

		CHECK(get("X") == "a b  c");
		CHECK(get("Y") == "caf\xc3\xa9");
		CHECK(get("Z") == "a\tb");
		CHECK(get("D") == "a b");

		auto *fs = rspamd_fstring_new_init("p\r\nq\x01", 5);
		rspamd_http_message_add_header_fstr(msg, "F", fs);
		CHECK(get("F") == "p  q ");
		rspamd_fstring_free(fs);

		rspamd_http_message_unref(msg);
	}

	TEST_CASE("http parser: ambiguous Content-Length is refused")
	{
		const char *dup = "HPE_UNEXPECTED_CONTENT_LENGTH";
		const char *bad = "HPE_INVALID_CONTENT_LENGTH";

		/* Two Content-Length headers, even identical ones */
		HP_CHECK_BOTH(0, "POST /a HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 1\r\n\r\nz", true, dup, 0, 0);
		HP_CHECK_BOTH(0, "POST /a HTTP/1.1\r\nContent-Length: 5\r\nContent-length: 5\r\n\r\nabcde", true, dup, 0, 0);
		HP_CHECK_BOTH(0, "POST /a HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 5\r\n\r\nabcde", true, dup, 0, 0);
		HP_CHECK_BOTH(1, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabcd", true, dup, 0, 0);
		{
			auto r = hp_test::parse(0, "POST /a HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 1\r\n\r\nz", false);
			CHECK(r.used == 53);
			CHECK(r.hc == 0);
		}

		/* Blanks inside the number */
		HP_CHECK_BOTH(0, "POST /a HTTP/1.1\r\nContent-Length: 1 2\r\n\r\nabcdefghijkl", true, bad, 0, 0);
		HP_CHECK_BOTH(0, "POST /a HTTP/1.1\r\nContent-Length: 4 2\r\n\r\nabcdefghijkl", true, bad, 0, 0);
		HP_CHECK_BOTH(0, "POST /a HTTP/1.1\r\nContent-Length: 13 37\r\n\r\nabcdefghijkl", true, bad, 0, 0);
		{
			auto r = hp_test::parse(0, "POST /a HTTP/1.1\r\nContent-Length: 1 2\r\n\r\nabcdefghijkl", false);
			CHECK(r.used == 36);
		}

		/* Digits continued over a fold */
		HP_CHECK_BOTH(0, "POST /a HTTP/1.1\r\nContent-Length: 1\r\n 2\r\n\r\nabcdefghijkl", true, bad, 0, 0);
		HP_CHECK_BOTH(0, "POST /a HTTP/1.1\r\nContent-Length: 5\r\n\t5\r\n\r\nabcde", true, bad, 0, 0);
		HP_CHECK_BOTH(0, "POST /a HTTP/1.1\nContent-Length: 5\n 5\n\nabcde", true, bad, 0, 0);
		HP_CHECK_BOTH(0, "POST /a HTTP/1.1\r\nContent-Length: 3\r\n \t\r\n\r\nabc", true, bad, 0, 0);
		{
			auto r = hp_test::parse(0, "POST /a HTTP/1.1\r\nContent-Length: 1\r\n 2\r\n\r\nabcdefghijkl", false);
			CHECK(r.used == 38);
		}

		/* Empty values */
		HP_CHECK_BOTH(0, "POST /a HTTP/1.1\r\nContent-Length:\r\n\r\nabcde", true, bad, 0, 0);
		{
			auto r = hp_test::parse(0, "POST /a HTTP/1.1\r\nContent-Length:\r\n\r\nabcde", false);
			CHECK(r.used == 35);
			CHECK(r.hc == 0);
		}
		HP_CHECK_BOTH(0, "POST /a HTTP/1.1\r\nContent-Length:   \r\n\r\nabc", true, bad, 0, 0);
		HP_CHECK_BOTH(0, "POST /a HTTP/1.1\nContent-length:\n\nabc", true, bad, 0, 0);
		HP_CHECK_BOTH(0, "POST /a HTTP/1.1\r\nContent-Length:\r\n \r\n\r\nabc", true, bad, 0, 0);
		HP_CHECK_BOTH(0, "CHECK SPAMC/1.2\r\nContent-length:\r\n\r\nabc", true, bad, 0, 0);
		HP_CHECK_BOTH(0, "POST /a HTTP/1.1\r\nContent-Length: 18446744073709551615\r\n\r\n", true, bad, 0, 0);
		HP_CHECK_BOTH(0, "POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nContent-Length:\r\n\r\n",
					  true, bad, 3, 0);

		/* Both framings, in either order */
		HP_CHECK_BOTH(0, "POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\nabc", true, bad, 0, 0);
		HP_CHECK_BOTH(0, "POST /a HTTP/1.1\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\nabc", true, bad, 0, 0);

		/* Still accepted */
		HP_CHECK_BOTH(0, "POST /a HTTP/1.1\r\nContent-Length: 3\r\n \r\n\r\nabc", true, "HPE_OK", 3, 1);
		HP_CHECK_BOTH(0, "POST /a HTTP/1.1\r\nContent-Length: 3 \r\n  \r\n\r\nabc", true, "HPE_OK", 3, 1);
		HP_CHECK_BOTH(0, "POST /a HTTP/1.1\r\nContent-Length:\r\n 5\r\n\r\nabcde", true, "HPE_OK", 5, 1);
		HP_CHECK_BOTH(0, "POST /a HTTP/1.1\r\nContent-Length: 5 \r\n\r\nabcde", true, "HPE_OK", 5, 1);
		for (bool bw: {false, true}) {
			auto r = hp_test::parse(0, "POST /a HTTP/1.1\r\nContent-Length:  42 \r\n\r\n", bw);
			CHECK(r.hc == 1);
			CHECK(r.err == "HPE_INVALID_EOF_STATE");
		}
		/* EOF right after the number and its trailing blank */
		HP_CHECK_BOTH(0, "CHECK SPAMC/1.2\r\nContent-length: 3 ", true, "HPE_INVALID_EOF_STATE", 0, 0);
		/* The length state is reset between messages */
		HP_CHECK_BOTH(0, "POST /a HTTP/1.1\r\nConnection: keep-alive\r\nContent-Length: 3\r\n\r\nabc"
						 "POST /b HTTP/1.1\r\nConnection: keep-alive\r\nContent-Length: 2\r\n\r\nxy",
					  true, "HPE_OK", 5, 2);
		HP_CHECK_BOTH(1, "HTTP/1.1 100 Continue\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n"
						 "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc",
					  true, "HPE_OK", 3, 2);
		HP_CHECK_BOTH(0, "POST /a HTTP/1.1\r\nContent-Lengthy: 7\r\nContent-Length: 3\r\n\r\nabc", true, "HPE_OK", 3, 1);
		HP_CHECK_BOTH(1, "HTTP/1.1 200 OK\r\nContent-Length-X: 0\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nOK\r\n0\r\n\r\n",
					  true, "HPE_OK", 2, 1);
		HP_CHECK_BOTH(0, "POST /a HTTP/1.1\r\nX:\r\n\r\n", true, "HPE_OK", 0, 1);
		HP_CHECK_BOTH(0, "SYMBOLS RSPAMC/1.3\r\nContent-length: 3 \r\nUser: x\r\n\r\nabc", true, "HPE_OK", 3, 1);
		HP_CHECK_BOTH(0, "CHECK SPAMC/1.2\r\nContent-length: 3\r\n\r\nabc", true, "HPE_OK", 3, 1);
	}

	TEST_CASE("http parser: Transfer-Encoding lists")
	{
		const char *bad = "HPE_INVALID_TRANSFER_ENCODING";
		const char *badcl = "HPE_INVALID_CONTENT_LENGTH";
		const std::string head = "POST /a HTTP/1.1\r\n";
		const std::string body = "\r\n\r\n3\r\nabc\r\n0\r\n\r\n";

		/* chunked is the last coding */
		for (const char *te: {"gzip, chunked", "compress, chunked", "deflate,\r\n chunked", "gzip\r\n , chunked",
							  "gzip,\tchunked", "CHUNKED", "chu, chunked", "\r\n chunked", "gzip ,chunked ",
							  ",chunked", "gzip,,chunked"}) {
			std::string w = head + "Transfer-Encoding: " + te + body;
			HP_CHECK_BOTH(0, w, true, "HPE_OK", 3, 1);
		}
		HP_CHECK_BOTH(0, head + "Transfer-Encoding:\r\n chunked" + body, true, "HPE_OK", 3, 1);
		HP_CHECK_BOTH(0, head + "Transfer-Encoding: gzip\r\nTransfer-Encoding: chunked" + body, true, "HPE_OK", 3, 1);
		HP_CHECK_BOTH(0, "POST /a HTTP/1.1\nTransfer-Encoding: gzip, chunked\n\n3\r\nabc\r\n0\r\n\r\n", true, "HPE_OK", 3, 1);

		/* anything else is refused before the headers callback */
		for (const char *te: {"chunked, gzip", "gzip", "identity", "xchunked", "chunked;q=1", "\"chunked\"", "",
							  "chunked, chunked", "chunked, gzip, chunked", "chunked,", "chunkedx", "chunke",
							  "chunked\r\n , gzip", "chunked\r\n ", "chunked\r\n \r\n", "gzip, chunked x"}) {
			std::string w = head + "Transfer-Encoding: " + te + body;
			for (bool bw: {false, true}) {
				auto r = hp_test::parse(0, w, bw);
				CHECK(r.err == bad);
				CHECK(r.hc == 0);
				CHECK(r.mc == 0);
			}
		}
		HP_CHECK_BOTH(0, head + "Transfer-Encoding: chunked\r\nTransfer-Encoding: gzip" + body, true, bad, 0, 0);
		HP_CHECK_BOTH(0, head + "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked" + body, true, bad, 0, 0);
		for (bool bw: {false, true}) {
			auto r = hp_test::parse(0, head + "Transfer-Encoding: chunked\r\nTransfer-Encoding: gzip" + body, bw);
			CHECK(r.hc == 0);
			r = hp_test::parse(0, "SYMBOLS RSPAMC/1.3\r\nTransfer-Encoding: gzip\r\n\r\n", bw);
			CHECK(r.err == bad);
			CHECK(r.hc == 0);
		}
		HP_CHECK_BOTH(0, "SYMBOLS RSPAMC/1.3\r\nTransfer-Encoding: gzip\r\n\r\n", true, bad, 0, 0);

		/* both framings */
		HP_CHECK_BOTH(0, head + "Transfer-Encoding: identity\r\nContent-Length: 3\r\n\r\nabc", true, badcl, 0, 0);
		HP_CHECK_BOTH(0, head + "Content-Length: 3\r\nTransfer-Encoding: gzip, chunked\r\n\r\nabc", true, badcl, 0, 0);
		HP_CHECK_BOTH(0, head + "Transfer-Encoding: gzip, chunked\r\nContent-Length: 3\r\n\r\nabc", true, badcl, 0, 0);

		/* only the exact field name counts */
		HP_CHECK_BOTH(0, head + "Transfer-Encodingx: y\r\nContent-Length: 3\r\n\r\nabc", true, "HPE_OK", 3, 1);
		HP_CHECK_BOTH(0, head + "Transfer-Encodin: y\r\nContent-Length: 3\r\n\r\nabc", true, "HPE_OK", 3, 1);

		/* pipelined message after a list-framed one */
		{
			std::string w = head + "Connection: keep-alive\r\nTransfer-Encoding: gzip, chunked" + body +
							"GET /b HTTP/1.1\r\n\r\n";
			HP_CHECK_BOTH(0, w, true, "HPE_OK", 3, 2);
			auto r = hp_test::parse(0, w, false);
			CHECK(r.begin == 2);
		}
		/* a trailer does not change the framing */
		HP_CHECK_BOTH(0,
					  head + "Connection: keep-alive\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n"
							 "Transfer-Encoding: gzip\r\n\r\nGET /b HTTP/1.1\r\n\r\n",
					  true, "HPE_OK", 3, 2);

		/* responses */
		const std::string rhead = "HTTP/1.1 200 OK\r\n";
		HP_CHECK_BOTH(1, rhead + "Transfer-Encoding: gzip, chunked" + body, true, "HPE_OK", 3, 1);
		HP_CHECK_BOTH(1, rhead + "Transfer-Encoding: deflate,\r\n chunked" + body, true, "HPE_OK", 3, 1);
		for (bool bw: {false, true}) {
			auto r = hp_test::parse(1, rhead + "Transfer-Encoding: gzip\r\n\r\nabc", bw, false);
			CHECK(r.err == "HPE_OK");
			CHECK(r.body == 3);
			CHECK(r.mc == 0);
			/* keep-alive is only asked for through http_message_needs_eof() */
			r = hp_test::parse(1, rhead + "Connection: keep-alive\r\nTransfer-Encoding: gzip\r\n\r\nabc", bw, true);
			CHECK(r.err == "HPE_OK");
			CHECK(r.body == 3);
			CHECK(r.mc == 1);
			CHECK(r.keep_alive == 0);
			r = hp_test::parse(1, "HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: gzip\r\n\r\n", bw, false);
			CHECK(r.err == "HPE_OK");
			CHECK(r.mc == 1);
		}
		/* a second Transfer-Encoding line after chunked fails responses too */
		HP_CHECK_BOTH(1, rhead + "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked" + body, true,
					  "HPE_INVALID_TRANSFER_ENCODING", 0, 0);
		HP_CHECK_BOTH(1, rhead + "Transfer-Encoding: chunked\r\nTransfer-Encoding: gzip" + body, true,
					  "HPE_INVALID_TRANSFER_ENCODING", 0, 0);
		HP_CHECK_BOTH(1, rhead + "Transfer-Encoding: gzip\r\nContent-Length: 3\r\n\r\nabcdef", true, badcl, 0, 0);
		HP_CHECK_BOTH(1, "HTTP/1.1 204 No Content\r\nTransfer-Encoding: gzip\r\n\r\n", true, "HPE_OK", 0, 1);
		/* 204 and 304 with a non-chunked Transfer-Encoding and no length have no body (upstream reads a 204 to EOF) */
		HP_CHECK_BOTH(1, "HTTP/1.1 204 No Content\r\nTransfer-Encoding: gzip\r\n\r\n", false, "HPE_OK", 0, 1);
		HP_CHECK_BOTH(1, "HTTP/1.1 204 No Content\r\nTransfer-Encoding: gzip\r\nConnection: keep-alive\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nz", true, "HPE_OK", 1, 2);
		HP_CHECK_BOTH(1, "HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: gzip\r\nConnection: keep-alive\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nz", true, "HPE_OK", 1, 2);
	}

	TEST_CASE("http parser: HTTP version is one digit each")
	{
		const char *ver = "HPE_INVALID_VERSION";

		struct bad_case {
			int type;
			std::string_view wire;
			size_t used;
		};
		const bad_case bad[] = {
			{0, "GET /a HTTP/1.10\r\n\r\n", 15},
			{0, "GET /a HTTP/11.1\r\n\r\n", 13},
			{0, "GET /a HTTP/1.01\r\n\r\n", 15},
			{0, "GET /a HTTP/1.1 \r\n", 15},
			{0, "GET /a HTTP/0.9\r\n\r\n", 12},
			{1, "HTTP/1.10 200 OK\r\nContent-Length: 3\r\n\r\nabc", 8},
			{1, "HTTP/11.1 200 OK\r\n\r\n", 6},
			{1, "HTTP/1.1\t200", 8},
		};

		for (const auto &c: bad) {
			HP_CHECK_BOTH(c.type, c.wire, true, ver, 0, 0);
			auto r = hp_test::parse(c.type, c.wire, false);
			CHECK(r.used == c.used);
			CHECK(r.hc == 0);
		}

		/* Bare LF, version 1.0 and the version-less form still work */
		{
			auto r = hp_test::parse(0, "GET /a HTTP/1.1\n\n", false);
			CHECK(r.err == "HPE_OK");
			CHECK(r.http_major == 1);
			CHECK(r.http_minor == 1);
			HP_CHECK_BOTH(0, "GET /a HTTP/1.1\n\n", true, "HPE_OK", 0, 1);
		}
		{
			std::string_view w = "GET /a HTTP/1.0\r\nContent-Length: 0\r\n\r\n";
			HP_CHECK_BOTH(0, w, true, "HPE_OK", 0, 1);
			auto r = hp_test::parse(0, w, false);
			CHECK(r.http_major == 1);
			CHECK(r.http_minor == 0);
		}
		{
			std::string_view w = "GET /a\r\n\r\n";
			HP_CHECK_BOTH(0, w, true, "HPE_OK", 0, 1);
			auto r = hp_test::parse(0, w, false);
			CHECK(r.http_major == 0);
			CHECK(r.http_minor == 9);
		}
		{
			std::string_view w = "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n";
			HP_CHECK_BOTH(1, w, true, "HPE_OK", 0, 1);
			auto r = hp_test::parse(1, w, false);
			CHECK(r.http_major == 1);
			CHECK(r.http_minor == 0);
		}

		/* spamc/rspamc lines never reach the version states */
		HP_CHECK_BOTH(0, "SYMBOLS RSPAMC/1.3\r\nContent-length: 2\r\n\r\nab", true, "HPE_OK", 2, 1);
		HP_CHECK_BOTH(0, "CHECK SPAMC/1.2\nContent-length: 2\n\nab", true, "HPE_OK", 2, 1);
		HP_CHECK_BOTH(0, "SYMBOLS SPAMC/1.2\nContent-Length: 2\n\nab", true, "HPE_OK", 2, 1);
	}

	TEST_CASE("http parser: empty reason phrase reaches on_status")
	{
		for (bool bytewise: {false, true}) {
			auto r = hp_test::parse(1, "HTTP/1.1 500\r\nContent-Length: 2\r\n\r\nab", bytewise);
			CHECK(r.err == "HPE_OK");
			CHECK(r.transcript.rfind("S:|F:Content-Length|V:2|", 0) == 0);
			CHECK(r.body == 2);
			CHECK(r.mc == 1);

			auto lf = hp_test::parse(1, "HTTP/1.1 500\nContent-Length: 2\n\nab", bytewise);
			CHECK(lf.err == "HPE_OK");
			CHECK(lf.transcript.rfind("S:|F:Content-Length|V:2|", 0) == 0);
			CHECK(lf.body == 2);

			auto sp = hp_test::parse(1, "HTTP/1.1 500 \r\n\r\n", bytewise);
			CHECK(sp.err == "HPE_OK");
			CHECK(sp.transcript == "S:");
			CHECK(sp.mc == 1);

			auto ok = hp_test::parse(1, "HTTP/1.1 200 OK\r\n\r\n", bytewise);
			CHECK(ok.err == "HPE_OK");
			CHECK(ok.transcript == "S:OK");
		}
	}

	TEST_CASE("http parser: CONNECT is framed like any request")
	{
		std::string_view w = "CONNECT host:80 HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc";
		for (bool bw: {false, true}) {
			auto r = hp_test::parse(0, w, bw);
			CHECK(r.err == "HPE_OK");
			CHECK(r.used == 50);
			CHECK(w.size() == 50);
			CHECK(r.body == 3);
			CHECK(r.mc == 1);
		}
		HP_CHECK_BOTH(0, w, true, "HPE_OK", 3, 1);

		HP_CHECK_BOTH(0,
					  "CONNECT /x HTTP/1.1\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\n"
					  "helloGET /b HTTP/1.1\r\n\r\n",
					  true, "HPE_OK", 5, 2);
	}

	TEST_CASE("http parser: 1xx and 304 responses ignore their framing")
	{
		std::string_view w1 = "HTTP/1.1 304 Not Modified\r\nContent-Length: 3\r\n\r\n";
		HP_CHECK_BOTH(1, w1, true, "HPE_OK", 0, 1);
		HP_CHECK_BOTH(1, w1, false, "HPE_OK", 0, 1);

		/* The next response is not eaten as the body of the 304 */
		HP_CHECK_BOTH(1,
					  "HTTP/1.1 304 Not Modified\r\nContent-Length: 3\r\nConnection: keep-alive\r\n\r\n"
					  "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: keep-alive\r\n\r\nz",
					  true, "HPE_OK", 1, 2);

		/*
		 * A 204 keeps its framing: rspamd's controller sends 204 replies
		 * with a JSON body and rspamc reads it
		 */
		std::string_view w2 = "HTTP/1.1 204 No Content\r\nContent-Length: 3\r\nConnection: keep-alive\r\n\r\nabc";
		HP_CHECK_BOTH(1, w2, true, "HPE_OK", 3, 1);

		HP_CHECK_BOTH(1, "HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\n", true,
					  "HPE_OK", 0, 1);
		HP_CHECK_BOTH(1, "HTTP/1.1 100 Continue\r\nContent-Length: 3\r\n\r\n", false,
					  "HPE_OK", 0, 1);

		HP_CHECK_BOTH(1, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc", true, "HPE_OK", 3, 1);
	}

	TEST_CASE("http parser: header size limit covers header-side states")
	{
		const size_t max = HTTP_MAX_HEADER_SIZE;
		const std::string tail = "\r\nabc\r\n0\r\n\r\n";
		const std::string heads[2] = {
			"POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
			"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
		};

		for (bool bw: {false, true}) {
			CAPTURE(bw);

			/* blanks after the colon of an otherwise empty-looking header */
			const std::string pre = "GET /a HTTP/1.1\r\nX:";
			auto r = hp_test::parse(0, pre + std::string(max - pre.size(), ' ') + "v\r\n\r\n", bw);
			CHECK(r.err == "HPE_HEADER_OVERFLOW");
			CHECK(r.used == max);

			/* controls: exactly at the limit is fine */
			r = hp_test::parse(0, pre + std::string(max - pre.size() - 5, ' ') + "v\r\n\r\n", bw);
			CHECK(r.err == "HPE_OK");
			CHECK(r.mc == 1);

			for (int type: {0, 1}) {
				CAPTURE(type);
				const auto &head = heads[type];

				/* optional whitespace after the chunk size */
				r = hp_test::parse(type, head + "3" + std::string(max - 1, ' ') + tail, bw);
				CHECK(r.err == "HPE_HEADER_OVERFLOW");
				CHECK(r.used == head.size() + max);

				/* chunk extension */
				r = hp_test::parse(type, head + "3;" + std::string(max - 2, 'a') + tail, bw);
				CHECK(r.err == "HPE_HEADER_OVERFLOW");
				CHECK(r.used == head.size() + max);

				r = hp_test::parse(type, head + "3" + std::string(100, ' ') + tail, bw);
				CHECK(r.err == "HPE_OK");
				CHECK(r.body == 3);
			}

			/* body bytes are not counted */
			for (const char *start: {"POST /a HTTP/1.1\r\nContent-Length: 100000\r\n\r\n",
									 "SYMBOLS RSPAMC/1.3\r\nContent-length: 100000\r\n\r\n"}) {
				r = hp_test::parse(0, std::string(start) + std::string(100000, 'b'), bw);
				CHECK(r.err == "HPE_OK");
				CHECK(r.body == 100000);
			}
		}
	}

	TEST_CASE("http parser: chunk-size line is strict")
	{
		const char *bad = "HPE_INVALID_CHUNK_SIZE";
		const std::string rtail = "abc\r\n0\r\n\r\n";

		for (int type: {0, 1}) {
			std::string head = type == 0 ? "POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
										 : "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";

			HP_CHECK_BOTH(type, head + "3;a\nb\r\n" + rtail, true, bad, 0, 0);
			HP_CHECK_BOTH(type, head + std::string("3;\x00\r\n", 5) + rtail, true, bad, 0, 0);
			HP_CHECK_BOTH(type, head + "3;a\x01\r\n" + rtail, true, bad, 0, 0);
			HP_CHECK_BOTH(type, head + "3 x\r\n" + rtail, true, bad, 0, 0);
			HP_CHECK_BOTH(type, head + "3 \nabc\r\n0\r\n\r\n", true, bad, 0, 0);

			HP_CHECK_BOTH(type, head + "3;name=val\r\n" + rtail, true, "HPE_OK", 3, 1);
			HP_CHECK_BOTH(type, head + "3 \r\n" + rtail, true, "HPE_OK", 3, 1);
			HP_CHECK_BOTH(type, head + "3\t;x\r\n" + rtail, true, "HPE_OK", 3, 1);
			HP_CHECK_BOTH(type, head + "3 ;x\r\n" + rtail, true, "HPE_OK", 3, 1);
			HP_CHECK_BOTH(type, head + "3\r\n" + rtail, true, "HPE_OK", 3, 1);
		}
	}

	TEST_CASE("http parser: only HTTP/1.0 and HTTP/1.1")
	{
		const char *ver = "HPE_INVALID_VERSION";

		HP_CHECK_BOTH(0, "GET /a HTTP/2.0\r\n\r\n", true, ver, 0, 0);
		HP_CHECK_BOTH(0, "GET /a HTTP/1.2\r\n\r\n", true, ver, 0, 0);
		HP_CHECK_BOTH(1, "HTTP/2.0 200 OK\r\n\r\n", true, ver, 0, 0);
		HP_CHECK_BOTH(1, "HTTP/0.9 200 OK\r\n\r\n", true, ver, 0, 0);
		HP_CHECK_BOTH(1, "HTTP/1.2 200 OK\r\n\r\n", true, ver, 0, 0);
		HP_CHECK_BOTH(0, "GET /a HTTP/1.0\r\n\r\n", true, "HPE_OK", 0, 1);
		HP_CHECK_BOTH(0, "GET /a HTTP/1.1\r\n\r\n", true, "HPE_OK", 0, 1);
		HP_CHECK_BOTH(1, "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n", true, "HPE_OK", 0, 1);
		/* a request with no version at all is still taken */
		HP_CHECK_BOTH(0, "GET /a\r\n\r\n", true, "HPE_OK", 0, 1);
	}

	TEST_CASE("http parser: status code has three digits")
	{
		const char *st = "HPE_INVALID_STATUS";

		HP_CHECK_BOTH(1, "HTTP/1.1 20 OK\r\n\r\n", true, st, 0, 0);
		HP_CHECK_BOTH(1, "HTTP/1.1 2\r\n\r\n", true, st, 0, 0);
		HP_CHECK_BOTH(1, "HTTP/1.1 0200 OK\r\n\r\n", true, st, 0, 0);
		HP_CHECK_BOTH(1, "HTTP/1.1 20\n\n", true, st, 0, 0);
		/* leading zeros must not wrap the digit counter */
		HP_CHECK_BOTH(1, "HTTP/1.1 " + std::string(259, '0') + " OK\r\n\r\n", true, st, 0, 0);
		HP_CHECK_BOTH(1, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", true, "HPE_OK", 0, 1);
		HP_CHECK_BOTH(1, "HTTP/1.1 500\r\n\r\n", true, "HPE_OK", 0, 1);
	}

	TEST_CASE("http parser: control bytes in value starts and reasons")
	{
		const char *tok = "HPE_INVALID_HEADER_TOKEN";
		const char *st = "HPE_INVALID_STATUS";
		const std::string pre = "GET /a HTTP/1.1\r\n";

		HP_CHECK_BOTH(0, pre + "X: \x01z\r\n\r\n", true, tok, 0, 0);
		HP_CHECK_BOTH(0, pre + std::string("X:\x00", 3), true, tok, 0, 0);
		HP_CHECK_BOTH(0, pre + "X: \x7f\r\n\r\n", true, tok, 0, 0);
		HP_CHECK_BOTH(0, pre + "Connection: \x01keep-alive\r\n\r\n", true, tok, 0, 0);
		HP_CHECK_BOTH(0, pre + "X:\r\n \x01z\r\n\r\n", true, tok, 0, 0);
		HP_CHECK_BOTH(0, pre + "X: \tb\r\n\r\n", true, "HPE_OK", 0, 1);
		HP_CHECK_BOTH(0, pre + "X: \xc3\xa9\r\n\r\n", true, "HPE_OK", 0, 1);
		HP_CHECK_BOTH(0, pre + "X:\r\n  b\r\n\r\n", true, "HPE_OK", 0, 1);

		HP_CHECK_BOTH(1, std::string("HTTP/1.1 200 \x00\x01OK\r\n\r\n", 21), true, st, 0, 0);
		HP_CHECK_BOTH(1, "HTTP/1.1 200 O\x01K\r\n\r\n", true, st, 0, 0);
		HP_CHECK_BOTH(1, "HTTP/1.1 200 OK\x7f\r\n\r\n", true, st, 0, 0);
		HP_CHECK_BOTH(1, "HTTP/1.1 200 \xc3\xa9\r\n\r\n", true, "HPE_OK", 0, 1);
	}

	TEST_CASE("http parser url: over 64K is refused")
	{
		std::string big = "/stat" + std::string(65536, 'x');
		auto r = hp_test::parse_url(big, 1);
		CHECK(r.rc == 1);
		CHECK(r.set == 0);

		auto edge = hp_test::parse_url("/" + std::string(65534, 'x'), 0);
		CHECK(edge.rc == 0);
		CHECK(edge.present[UF_PATH]);
		CHECK(edge.field[UF_PATH].size() == 65535);

		/* 65536 bytes is the first length the 16-bit offsets cannot hold */
		for (int conn = 0; conn < 2; conn++) {
			auto lim = hp_test::parse_url("/" + std::string(65535, 'x'), conn);
			CHECK(lim.rc == 1);
			CHECK(lim.set == 0);
		}
	}

	TEST_CASE("http parser: control bytes in the spamc request line")
	{
		const char *c = "HPE_INVALID_CONSTANT";

		HP_CHECK_BOTH(0, std::string("CHECK S\x00garbage\r\n\r\n", 19), true, c, 0, 0);
		HP_CHECK_BOTH(0, "SYMBOLS RSPAMC/1.3\x01\r\n\r\n", true, c, 0, 0);
		HP_CHECK_BOTH(0, "SYMBOLS RSPAMC/1.3\x7f\r\n\r\n", true, c, 0, 0);
		HP_CHECK_BOTH(0, "SYMBOLS RSPAMC/1.3\r\n\r\n", true, "HPE_OK", 0, 1);
		HP_CHECK_BOTH(0, "CHECK SPAMC/1.2\n\n", true, "HPE_OK", 0, 1);
		HP_CHECK_BOTH(0, "CHECK SPAMC/1.2 \t\xc3\xa9\r\n\r\n", true, "HPE_OK", 0, 1);
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
