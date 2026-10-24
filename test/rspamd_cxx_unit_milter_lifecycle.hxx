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
 * next transaction.
 */

#ifndef RSPAMD_CXX_UNIT_MILTER_LIFECYCLE_HXX
#define RSPAMD_CXX_UNIT_MILTER_LIFECYCLE_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "libserver/milter.h"
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
}

}// namespace milter_lifecycle_test

#endif /* RSPAMD_CXX_UNIT_MILTER_LIFECYCLE_HXX */
