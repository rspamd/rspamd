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
 * Lifecycle tests for the milter library. The library owns the transport
 * reference, so every way a connection ends (QUIT, EOF, timeout) has to reach
 * the close callback exactly once, and the finish callback only ever sees
 * complete messages. A message completed with TEMPFAIL, either from the
 * end-of-body callback or later from outside of the IO dispatch (as the proxy
 * does from a backend callback), must leave the connection usable for the
 * next transaction. A MAIL or CONNECT repeated without ABORT or QUIT_NC
 * replaces the previous state instead of leaking or mixing it.
 */

#ifndef RSPAMD_CXX_UNIT_MILTER_LIFECYCLE_HXX
#define RSPAMD_CXX_UNIT_MILTER_LIFECYCLE_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "libserver/milter.h"
#include "libmime/email_addr.h"
#include "libutil/addr.h"
#include "libutil/util.h"
#include "rspamd_test_fake_time.hxx"
#include "contrib/libev/ev.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <string>

namespace milter_lifecycle_test {

using namespace std::string_literals;

enum class eob_mode {
	tempfail_now,
	defer,
};

struct milter_state {
	eob_mode mode = eob_mode::defer;
	int finishes = 0;
	int closes = 0;
	bool close_had_error = false;
	int close_code = 0;
	struct rspamd_milter_session *session = nullptr;
};

static void
on_finish(int fd, struct rspamd_milter_session *session, void *ud)
{
	auto *st = static_cast<milter_state *>(ud);
	st->finishes++;
	st->session = session;

	if (st->mode == eob_mode::tempfail_now) {
		rspamd_milter_send_tempfail(session);
	}
}

static void
on_close(int fd, struct rspamd_milter_session *session, void *ud, GError *err)
{
	auto *st = static_cast<milter_state *>(ud);
	st->closes++;
	st->session = nullptr;
	st->close_had_error = err != nullptr;
	st->close_code = err ? err->code : 0;
}

static std::string
milter_cmd(char cmd, const std::string &data = {})
{
	uint32_t len = htonl(data.size() + 1);
	std::string out(reinterpret_cast<const char *>(&len), sizeof(len));

	out += cmd;
	out += data;

	return out;
}

static std::string
milter_connect(const std::string &host, char family,
			   uint16_t port = 0, const std::string &addr = {})
{
	std::string data = host + '\0' + family;

	if (family != 'U') {
		uint16_t nport = htons(port);

		data.append(reinterpret_cast<const char *>(&nport), sizeof(nport));
		data += addr + '\0';
	}

	return milter_cmd('C', data);
}

static std::string
milter_message(const std::string &from)
{
	return milter_cmd('M', "<" + from + ">" + '\0') +
		   milter_cmd('R', "<rcpt@example.com>\0"s) +
		   milter_cmd('L', "Subject\0test\0"s) +
		   milter_cmd('N') +
		   milter_cmd('B', "hello\r\n") +
		   milter_cmd('E');
}

struct milter_fixture {
	struct ev_loop *loop = nullptr;
	int server_fd = -1;
	int client_fd = -1;
	milter_state state;

	milter_fixture()
	{
		static struct rspamd_milter_context ctx;

		loop = ev_loop_new(EVFLAG_AUTO);
		REQUIRE(loop != nullptr);
		memset(&ctx, 0, sizeof(ctx));
		rspamd_milter_init_library(&ctx);

		int fds[2];
		REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
		server_fd = fds[0];
		client_fd = fds[1];
		rspamd_socket_nonblocking(server_fd);
		rspamd_socket_nonblocking(client_fd);
	}

	~milter_fixture()
	{
		/* Let the library see EOF and free a session a test left open */
		if (client_fd != -1) {
			close(client_fd);
			pump();
		}

		close(server_fd);
		ev_loop_destroy(loop);
	}

	milter_fixture(const milter_fixture &) = delete;
	milter_fixture &operator=(const milter_fixture &) = delete;

	void start(double timeout = 0.0)
	{
		/* The library works on its own dup of the descriptor */
		rspamd_milter_handle_socket(server_fd, timeout, nullptr, loop,
									on_finish, on_close, &state);
	}

	void send(const std::string &data)
	{
		REQUIRE(write(client_fd, data.data(), data.size()) == (ssize_t) data.size());
	}

	void pump()
	{
		for (int i = 0; i < 8; i++) {
			ev_run(loop, EVRUN_NOWAIT);
		}
	}

	/* Command codes of all replies written so far */
	std::string replies()
	{
		std::string buf, cmds;
		char tmp[4096];
		ssize_t r;

		while ((r = read(client_fd, tmp, sizeof(tmp))) > 0) {
			buf.append(tmp, r);
		}

		size_t pos = 0;

		while (pos + sizeof(uint32_t) < buf.size()) {
			uint32_t len;

			memcpy(&len, buf.data() + pos, sizeof(len));
			len = ntohl(len);
			REQUIRE(len >= 1);
			REQUIRE(pos + sizeof(len) + len <= buf.size());
			cmds += buf[pos + sizeof(len)];
			pos += sizeof(len) + len;
		}

		CHECK(pos == buf.size());

		return cmds;
	}
};

TEST_SUITE("milter_lifecycle")
{
	TEST_CASE("QUIT closes the connection through the close callback only")
	{
		milter_fixture t;
		t.start();
		t.send(milter_cmd('Q'));
		t.pump();
		CHECK(t.state.finishes == 0);
		CHECK(t.state.closes == 1);
		CHECK_FALSE(t.state.close_had_error);
	}

	TEST_CASE("EOF is reported once")
	{
		milter_fixture t;
		t.start();
		close(t.client_fd);
		t.client_fd = -1;
		t.pump();
		CHECK(t.state.finishes == 0);
		CHECK(t.state.closes == 1);
		CHECK(t.state.close_code == ECONNRESET);
	}

	TEST_CASE("timeout closes the connection once")
	{
		milter_fixture t;
		rspamd_test::fake_clock clk(1000.0, t.loop);
		t.start(5.0);
		t.pump();
		clk.advance(4.0);
		t.pump();
		CHECK(t.state.closes == 0);
		clk.advance(2.0);
		t.pump();
		CHECK(t.state.closes == 1);
		CHECK(t.state.close_code == ETIMEDOUT);
		clk.advance(10.0);
		t.pump();
		CHECK(t.state.closes == 1);
	}

	TEST_CASE("TEMPFAIL from the end-of-body callback keeps the connection")
	{
		milter_fixture t;
		t.state.mode = eob_mode::tempfail_now;
		t.start();
		t.send(milter_message("first@example.com"));
		t.pump();
		CHECK(t.state.finishes == 1);
		CHECK(t.replies() == "t");
		t.send(milter_message("second@example.com"));
		t.pump();
		CHECK(t.state.finishes == 2);
		CHECK(t.replies() == "t");
		CHECK(t.state.closes == 0);
		t.send(milter_cmd('Q'));
		t.pump();
		CHECK(t.state.closes == 1);
		CHECK_FALSE(t.state.close_had_error);
	}

	TEST_CASE("deferred TEMPFAIL resets the transaction and keeps the connection")
	{
		milter_fixture t;
		t.start();
		t.send(milter_message("first@example.com"));
		t.pump();
		REQUIRE(t.state.finishes == 1);
		REQUIRE(t.state.session != nullptr);
		CHECK(t.replies().empty());
		/* As the proxy does from a backend callback, outside of milter IO */
		rspamd_milter_send_tempfail(t.state.session);
		CHECK(t.state.session->from == nullptr);
		CHECK(t.state.session->rcpts == nullptr);
		t.pump();
		CHECK(t.replies() == "t");
		CHECK(t.state.closes == 0);
		t.send(milter_message("second@example.com"));
		t.pump();
		REQUIRE(t.state.finishes == 2);
		REQUIRE(t.state.session != nullptr);
		REQUIRE(t.state.session->rcpts != nullptr);
		CHECK(t.state.session->rcpts->len == 1);
		rspamd_milter_send_tempfail(t.state.session);
		t.pump();
		CHECK(t.replies() == "t");
		t.send(milter_cmd('Q'));
		t.pump();
		CHECK(t.state.closes == 1);
	}

	TEST_CASE("QUIT behind a queued reply drains it before closing")
	{
		milter_fixture t;
		t.state.mode = eob_mode::tempfail_now;
		t.start();
		t.send(milter_message("first@example.com") + milter_cmd('Q'));
		t.pump();
		CHECK(t.state.finishes == 1);
		CHECK(t.state.closes == 1);
		CHECK_FALSE(t.state.close_had_error);
		CHECK(t.replies() == "t");
	}

	TEST_CASE("MAIL without ABORT drops the unfinished transaction")
	{
		milter_fixture t;
		t.start();
		/* Two transactions are abandoned without ABORT */
		t.send(milter_cmd('M', "<first@example.com>\0SIZE=100\0"s) +
			   milter_cmd('R', "<rcpt1@example.com>\0NOTIFY=NEVER\0"s) +
			   milter_cmd('T') +
			   milter_cmd('L', "X-First\0yes\0"s));
		t.send(milter_cmd('M', "<second@example.com>\0BODY=8BITMIME\0"s));
		t.send(milter_cmd('M', "<third@example.com>\0"s) +
			   milter_cmd('R', "<rcpt3@example.com>\0"s) +
			   milter_cmd('L', "Subject\0test\0"s) +
			   milter_cmd('N') +
			   milter_cmd('B', "hello\r\n") +
			   milter_cmd('E'));
		t.pump();
		REQUIRE(t.state.finishes == 1);
		auto *session = t.state.session;
		REQUIRE(session != nullptr);
		REQUIRE(session->from != nullptr);
		CHECK(std::string(session->from->addr, session->from->addr_len) ==
			  "third@example.com");
		/* SIZE and BODY belonged to the abandoned transactions */
		CHECK(session->mail_esmtp_args == nullptr);
		REQUIRE(session->rcpts != nullptr);
		REQUIRE(session->rcpts->len == 1);
		auto *rcpt = static_cast<struct rspamd_email_address *>(
			g_ptr_array_index(session->rcpts, 0));
		CHECK(std::string(rcpt->addr, rcpt->addr_len) == "rcpt3@example.com");
		REQUIRE(session->rcpt_esmtp_args != nullptr);
		REQUIRE(session->rcpt_esmtp_args->len == 1);
		CHECK(g_ptr_array_index(session->rcpt_esmtp_args, 0) == nullptr);
		REQUIRE(session->message != nullptr);
		CHECK(std::string(session->message->str, session->message->len) ==
			  "Subject: test\r\n\r\nhello\r\n");
		rspamd_milter_send_tempfail(session);
		t.pump();
		CHECK(t.replies() == "t");
		/* The arguments of the current MAIL are kept */
		t.send(milter_cmd('M', "<fourth@example.com>\0SIZE=5\0"s) +
			   milter_cmd('R', "<rcpt4@example.com>\0"s) +
			   milter_cmd('E'));
		t.pump();
		REQUIRE(t.state.finishes == 2);
		session = t.state.session;
		REQUIRE(session != nullptr);
		REQUIRE(session->from != nullptr);
		CHECK(std::string(session->from->addr, session->from->addr_len) ==
			  "fourth@example.com");
		REQUIRE(session->mail_esmtp_args != nullptr);
		CHECK(g_hash_table_size(session->mail_esmtp_args) == 1);
		REQUIRE(session->rcpts != nullptr);
		CHECK(session->rcpts->len == 1);
		rspamd_milter_send_tempfail(session);
		t.pump();
		CHECK(t.replies() == "t");
		t.send(milter_cmd('Q'));
		t.pump();
		CHECK(t.state.closes == 1);
	}

	TEST_CASE("repeated CONNECT replaces the address")
	{
		milter_fixture t;
		t.start();
		t.send(milter_connect("mx1.example.com", '4', 25, "192.0.2.1") +
			   milter_connect("mx2.example.com", '6', 587, "2001:db8::1") +
			   milter_message("first@example.com"));
		t.pump();
		REQUIRE(t.state.finishes == 1);
		REQUIRE(t.state.session != nullptr);
		REQUIRE(t.state.session->addr != nullptr);
		CHECK(std::string(rspamd_inet_address_to_string(t.state.session->addr)) ==
			  "2001:db8::1");
		CHECK(rspamd_inet_address_get_port(t.state.session->addr) == 587);
		rspamd_milter_send_tempfail(t.state.session);
		t.pump();
		CHECK(t.replies() == "t");
		/* An unknown peer must not inherit the previous address */
		t.send(milter_connect("unknown", 'U') +
			   milter_message("second@example.com"));
		t.pump();
		REQUIRE(t.state.finishes == 2);
		REQUIRE(t.state.session != nullptr);
		CHECK(t.state.session->addr == nullptr);
		REQUIRE(t.state.session->hostname != nullptr);
		CHECK(std::string(t.state.session->hostname->str,
						  t.state.session->hostname->len) == "unknown");
		rspamd_milter_send_tempfail(t.state.session);
		t.pump();
		CHECK(t.replies() == "t");
		t.send(milter_cmd('Q'));
		t.pump();
		CHECK(t.state.closes == 1);
	}

	/*
	 * The finish callback owns a message until it is replied: a second end
	 * of body used to start another scan of the same proxy session, which
	 * freed the session under the first one.
	 */
	TEST_CASE("end of body before the previous reply is a protocol error")
	{
		milter_fixture t;
		t.start();
		t.send(milter_message("first@example.com") + milter_cmd('E'));
		t.pump();
		CHECK(t.state.finishes == 1);
		CHECK(t.state.closes == 1);
		CHECK(t.state.close_had_error);
		CHECK(t.state.close_code == EINVAL);
	}

	TEST_CASE("end of body after the previous reply starts a new message")
	{
		milter_fixture t;
		t.start();
		t.send(milter_message("first@example.com"));
		t.pump();
		REQUIRE(t.state.finishes == 1);
		REQUIRE(t.state.session != nullptr);
		rspamd_milter_send_tempfail(t.state.session);
		t.pump();
		CHECK(t.replies() == "t");
		/* ABORT does not end the pending end of body, the reply does */
		t.send(milter_message("second@example.com"));
		t.pump();
		REQUIRE(t.state.finishes == 2);
		t.send(milter_cmd('A') + milter_cmd('E'));
		t.pump();
		CHECK(t.state.finishes == 2);
		CHECK(t.state.closes == 1);
		CHECK(t.state.close_had_error);
	}
}

}// namespace milter_lifecycle_test

#endif /* RSPAMD_CXX_UNIT_MILTER_LIFECYCLE_HXX */
