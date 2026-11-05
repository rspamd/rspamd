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

/*
 * Header values that the HTTP connection parses as it reads them: `Date` and
 * `Last-Modified` go to rspamd_http_parse_date, the key in `Key` goes to
 * rspamd_pubkey_from_base32.
 *
 * A header value is a token inside the header storage, which is not
 * NUL-terminated, and an empty value is a token of length 0. Both parsers used
 * to take a length of 0 for "NUL-terminated, measure it", so an empty value had
 * them run strlen past the end of the header storage.
 */

#ifndef RSPAMD_CXX_UNIT_HTTP_HEADER_VALUES_HXX
#define RSPAMD_CXX_UNIT_HTTP_HEADER_VALUES_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "libserver/http/http_connection.h"
#include "libserver/http/http_context.h"
#include "libserver/http/http_message.h"
#include "libserver/http/http_private.h"
#include "libserver/http/http_util.h"
#include "libcryptobox/keypair.h"
#include "libutil/util.h"
#include "contrib/libev/ev.h"

#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <memory>
#include <string>

namespace http_date_test {

/* 784111777 is the example date of RFC 9110, in its three formats */
static constexpr time_t example_date = 784111777;

/* A copy of `s` in a heap buffer of exactly its size, with no NUL after it */
static std::unique_ptr<char[]>
unterminated(const std::string &s)
{
	std::unique_ptr<char[]> buf(new char[s.size()]);
	memcpy(buf.get(), s.data(), s.size());

	return buf;
}

struct date_state {
	int errors = 0;
	int finishes = 0;
	time_t date = 0;
	time_t last_modified = 0;
	bool peer_key = false;
};

static void
record_error(struct rspamd_http_connection *conn, GError *)
{
	auto *st = static_cast<date_state *>(conn->ud);
	st->errors++;
	st->peer_key = rspamd_http_connection_get_peer_key(conn) != nullptr;
}

static int
record_finish(struct rspamd_http_connection *conn, struct rspamd_http_message *msg)
{
	auto *st = static_cast<date_state *>(conn->ud);
	st->finishes++;
	st->date = msg->date;
	st->last_modified = msg->last_modified;
	st->peer_key = rspamd_http_connection_get_peer_key(conn) != nullptr;

	return 0;
}

struct date_fixture {
	struct ev_loop *loop = nullptr;
	struct rspamd_http_context *ctx = nullptr;
	struct rspamd_http_connection *conn = nullptr;
	int local_fd = -1;
	int remote_fd = -1;
	date_state state;

	explicit date_fixture(bool client)
	{
		loop = ev_loop_new(EVFLAG_AUTO);
		REQUIRE(loop != nullptr);

		struct rspamd_http_context_cfg cfg;
		memset(&cfg, 0, sizeof(cfg));
		ctx = rspamd_http_context_create_config(&cfg, loop, nullptr);
		REQUIRE(ctx != nullptr);

		int fds[2];
		REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
		local_fd = fds[0];
		remote_fd = fds[1];
		rspamd_socket_nonblocking(local_fd);
		rspamd_socket_nonblocking(remote_fd);

		if (client) {
			conn = rspamd_http_connection_new_client_socket(ctx, nullptr,
															record_error, record_finish,
															RSPAMD_HTTP_CLIENT_SIMPLE, local_fd);
		}
		else {
			conn = rspamd_http_connection_new_server(ctx, local_fd,
													 nullptr, record_error, record_finish, 0);
		}

		REQUIRE(conn != nullptr);
	}

	~date_fixture()
	{
		rspamd_http_connection_unref(conn);
		rspamd_http_context_free(ctx);
		close(remote_fd);
		close(local_fd);
		ev_loop_destroy(loop);
	}

	date_fixture(const date_fixture &) = delete;
	date_fixture &operator=(const date_fixture &) = delete;

	void spin()
	{
		for (int i = 0; i < 16 && state.errors == 0 && state.finishes == 0; i++) {
			ev_run(loop, EVRUN_NOWAIT);
		}
	}

	/* What the connection has sent so far is read and dropped */
	void drain()
	{
		char buf[4096];

		for (int i = 0; i < 4; i++) {
			ev_run(loop, EVRUN_NOWAIT);

			while (read(remote_fd, buf, sizeof(buf)) > 0) {
			}
		}
	}

	void push(const std::string &data)
	{
		REQUIRE(write(remote_fd, data.data(), data.size()) == (ssize_t) data.size());
		spin();
	}
};

}// namespace http_date_test

TEST_SUITE("http_header_values")
{
	TEST_CASE("an empty date is not measured with strlen")
	{
		using namespace http_date_test;
		/*
		 * What follows an empty value in memory must not be parsed. A valid
		 * date right there makes the old strlen fallback visible without a
		 * sanitizer: it used to return the date.
		 */
		static const char after_empty[] = "Sun, 06 Nov 1994 08:49:37 GMT";

		CHECK(rspamd_http_parse_date(after_empty, 0) == (time_t) -1);
	}

	TEST_CASE("dates are parsed from exactly their length")
	{
		using namespace http_date_test;

		for (const std::string s: {"Sun, 06 Nov 1994 08:49:37 GMT",
								   "Sunday, 06-Nov-94 08:49:37 GMT",
								   "Sun Nov  6 08:49:37 1994"}) {
			CAPTURE(s);
			auto buf = unterminated(s);
			CHECK(rspamd_http_parse_date(buf.get(), s.size()) == example_date);
		}

		/* Cut short: each prefix fails without reading past it */
		std::string full = "Sun, 06 Nov 1994 08:49:37 GMT";

		for (std::size_t len = 1; len < sizeof("Sun, 06 Nov 1994 08:49:37") - 1; len++) {
			CAPTURE(len);
			auto buf = unterminated(full.substr(0, len));
			CHECK(rspamd_http_parse_date(buf.get(), len) == (time_t) -1);
		}
	}

	TEST_CASE("server: empty Date and Last-Modified in a request")
	{
		using namespace http_date_test;
		date_fixture t(false);

		rspamd_http_connection_read_message(t.conn, &t.state, 1000.0);
		/* Whitespace only is an empty value for the parser too */
		t.push("GET / HTTP/1.1\r\nDate:\r\nLast-Modified:   \r\n\r\n");

		CHECK(t.state.errors == 0);
		REQUIRE(t.state.finishes == 1);
		CHECK(t.state.date == (time_t) -1);
		CHECK(t.state.last_modified == (time_t) -1);
	}

	TEST_CASE("client: empty Date in a response")
	{
		using namespace http_date_test;
		date_fixture t(true);

		auto *msg = rspamd_http_message_from_url("http://example.com/");
		REQUIRE(msg != nullptr);
		REQUIRE(rspamd_http_connection_write_message(t.conn, msg, "example.com", nullptr,
													 &t.state, 1000.0));
		t.drain();

		t.push("HTTP/1.1 200 OK\r\nDate:\r\nContent-Length: 0\r\n\r\n");

		CHECK(t.state.errors == 0);
		REQUIRE(t.state.finishes == 1);
		CHECK(t.state.date == (time_t) -1);
	}

	TEST_CASE("server: Key header with an empty key")
	{
		using namespace http_date_test;
		std::unique_ptr<struct rspamd_cryptobox_keypair, decltype(&rspamd_keypair_unref)>
			kp{rspamd_keypair_new(RSPAMD_KEYPAIR_KEX), rspamd_keypair_unref};
		date_fixture t(false);

		rspamd_http_connection_set_key(t.conn, kp.get());
		rspamd_http_connection_read_message(t.conn, &t.state, 1000.0);
		/* A short id that decodes to enough bytes, then nothing after '=' */
		t.push("POST /check HTTP/1.1\r\nKey: aaaaaaaaaaaaaaaa=\r\nContent-Length: 0\r\n\r\n");

		/* No key to decrypt with, so the request fails like any bad key */
		CHECK(t.state.finishes + t.state.errors == 1);
		CHECK_FALSE(t.state.peer_key);
	}
}

#endif
