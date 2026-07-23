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
 * Lifecycle tests for the HTTP connection read-timeout handler. The read
 * timer is a one-shot ev_timer; when it expires while data is already
 * waiting in the socket, the handler drains and parses that data. These
 * tests pin down what must happen next: a message completed by the drained
 * bytes is salvaged, anything still incomplete gets a 408 — the connection
 * must never continue with only the I/O watcher and no deadline.
 */

#ifndef RSPAMD_CXX_UNIT_HTTP_TIMEOUT_HXX
#define RSPAMD_CXX_UNIT_HTTP_TIMEOUT_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "libserver/http/http_connection.h"
#include "libserver/http/http_context.h"
#include "libutil/util.h"
#include "rspamd_test_fake_time.hxx"
#include "contrib/libev/ev.h"

#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <string>

namespace http_timeout_test {

struct handler_state {
	int errors = 0;
	int finishes = 0;
	int last_error_code = 0;
};

static void
record_error(struct rspamd_http_connection *conn, GError *err)
{
	auto *st = static_cast<handler_state *>(conn->ud);
	st->errors++;
	st->last_error_code = err->code;
}

static int
record_finish(struct rspamd_http_connection *conn, struct rspamd_http_message *msg)
{
	auto *st = static_cast<handler_state *>(conn->ud);
	st->finishes++;

	return 0;
}

/*
 * Writes its payload from a max-priority ev_check watcher, i.e. after the
 * loop has polled fds but before pending timer callbacks run. Combined
 * with the fake clock this lands the bytes deterministically in the exact
 * window where the read timer has expired while data is already waiting
 * in the socket, with no sleeps and no reliance on pending-queue order.
 */
struct expiry_writer {
	ev_check check;
	int fd = -1;
	std::string payload;
	bool pending = false;

	static void cb(struct ev_loop *, ev_check *w, int)
	{
		auto *self = static_cast<expiry_writer *>(w->data);

		if (self->pending) {
			self->pending = false;
			REQUIRE(write(self->fd, self->payload.data(), self->payload.size()) ==
					(ssize_t) self->payload.size());
		}
	}

	void start(struct ev_loop *loop, int write_fd)
	{
		fd = write_fd;
		ev_check_init(&check, &expiry_writer::cb);
		ev_set_priority(&check, EV_MAXPRI);
		check.data = this;
		ev_check_start(loop, &check);
	}

	void arm(std::string data)
	{
		payload = std::move(data);
		pending = true;
	}
};

struct http_conn_fixture {
	struct ev_loop *loop = nullptr;
	struct rspamd_http_context *ctx = nullptr;
	struct rspamd_http_connection *conn = nullptr;
	int server_fd = -1;
	int client_fd = -1;
	handler_state state;
	expiry_writer writer;

	http_conn_fixture()
	{
		loop = ev_loop_new(EVFLAG_AUTO);
		REQUIRE(loop != nullptr);

		struct rspamd_http_context_cfg cfg;
		memset(&cfg, 0, sizeof(cfg));
		ctx = rspamd_http_context_create_config(&cfg, loop, nullptr);
		REQUIRE(ctx != nullptr);

		int fds[2];
		REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
		server_fd = fds[0];
		client_fd = fds[1];
		rspamd_socket_nonblocking(server_fd);
		rspamd_socket_nonblocking(client_fd);

		conn = rspamd_http_connection_new_server(ctx, server_fd,
												 nullptr, record_error, record_finish, 0);
		REQUIRE(conn != nullptr);

		writer.start(loop, client_fd);
	}

	~http_conn_fixture()
	{
		ev_check_stop(loop, &writer.check);
		rspamd_http_connection_unref(conn);
		rspamd_http_context_free(ctx);
		close(client_fd);
		close(server_fd);
		ev_loop_destroy(loop);
	}

	http_conn_fixture(const http_conn_fixture &) = delete;
	http_conn_fixture &operator=(const http_conn_fixture &) = delete;
};

TEST_SUITE("http_timeout")
{
	TEST_CASE("partial data at timer expiry still enforces the deadline")
	{
		http_conn_fixture t;
		rspamd_test::fake_clock clk(1000.0, t.loop);

		rspamd_http_connection_read_message(t.conn, &t.state, 5.0);

		/* Headers plus a truncated body: parses cleanly, never completes */
		t.writer.arm("POST /check HTTP/1.1\r\n"
					 "Content-Length: 100\r\n"
					 "\r\n"
					 "partial body");
		clk.advance(6.0);
		ev_run(t.loop, EVRUN_ONCE);

		CHECK(t.state.errors == 1);
		CHECK(t.state.last_error_code == 408);
		CHECK(t.state.finishes == 0);

		/* The watcher must be fully stopped: further client bytes may not
		 * resurrect the request */
		REQUIRE(write(t.client_fd, "more", 4) == 4);
		ev_run(t.loop, EVRUN_NOWAIT);
		CHECK(t.state.errors == 1);
		CHECK(t.state.finishes == 0);
	}

	TEST_CASE("message completed at timer expiry is salvaged")
	{
		http_conn_fixture t;
		rspamd_test::fake_clock clk(1000.0, t.loop);

		rspamd_http_connection_read_message(t.conn, &t.state, 5.0);

		t.writer.arm("POST /check HTTP/1.1\r\n"
					 "Content-Length: 4\r\n"
					 "\r\n"
					 "done");
		clk.advance(6.0);
		ev_run(t.loop, EVRUN_ONCE);

		CHECK(t.state.finishes == 1);
		CHECK(t.state.errors == 0);
	}

	TEST_CASE("timer expiry with no pending data reports 408")
	{
		http_conn_fixture t;
		rspamd_test::fake_clock clk(1000.0, t.loop);

		rspamd_http_connection_read_message(t.conn, &t.state, 5.0);

		clk.advance(6.0);
		ev_run(t.loop, EVRUN_ONCE);

		CHECK(t.state.errors == 1);
		CHECK(t.state.last_error_code == 408);
		CHECK(t.state.finishes == 0);
	}
}

}// namespace http_timeout_test

#endif /* RSPAMD_CXX_UNIT_HTTP_TIMEOUT_HXX */
