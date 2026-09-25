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
#include "libserver/http/http_private.h"
#include "libserver/ssl_util.h"
#include "libutil/util.h"
#include "rspamd_test_fake_time.hxx"
#include "contrib/libev/ev.h"

#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <string>
#include <memory>
#include <openssl/ssl.h>

namespace http_timeout_test {

struct handler_state {
	int errors = 0;
	int finishes = 0;
	int last_error_code = 0;
	std::string last_error;
};

static void
record_error(struct rspamd_http_connection *conn, GError *err)
{
	auto *st = static_cast<handler_state *>(conn->ud);
	st->errors++;
	st->last_error_code = err->code;
	st->last_error = err->message;
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

/* A local TLS peer driven synchronously alongside libev. Virtual time only
 * advances after the handshake/request, so no wall-clock sleeps are needed. */
struct client_fixture : http_conn_fixture {
	SSL_CTX *tls_ctx = nullptr;
	SSL *peer = nullptr;
	bool tls;

	explicit client_fixture(bool use_tls) : tls(use_tls)
	{
		rspamd_http_connection_unref(conn);
		conn = rspamd_http_connection_new_client_socket(ctx, nullptr,
														record_error, record_finish, RSPAMD_HTTP_CLIENT_SIMPLE | (tls ? RSPAMD_HTTP_CLIENT_SSL : 0), server_fd);
		REQUIRE(conn != nullptr);
		int sndbuf = 4096;
		REQUIRE(setsockopt(server_fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) == 0);

		if (tls) {
			tls_ctx = SSL_CTX_new(TLS_server_method());
			REQUIRE(tls_ctx != nullptr);
			std::string path = __FILE__;
			path = path.substr(0, path.find_last_of('/')) + "/functional/util/server.pem";
			REQUIRE(SSL_CTX_use_certificate_chain_file(tls_ctx, path.c_str()) == 1);
			REQUIRE(SSL_CTX_use_PrivateKey_file(tls_ctx, path.c_str(), SSL_FILETYPE_PEM) == 1);
			peer = SSL_new(tls_ctx);
			REQUIRE(peer != nullptr);
			REQUIRE(SSL_set_fd(peer, client_fd) == 1);
			SSL_set_accept_state(peer);
		}
	}

	~client_fixture()
	{
		if (peer) SSL_free(peer);
		if (tls_ctx) SSL_CTX_free(tls_ctx);
	}

	void start(double connect, double handshake, double write_timeout,
			   double read_timeout, double timeout = 10.0, bool large_body = false)
	{
		rspamd_http_connection_set_timeouts(conn, connect, handshake, write_timeout, read_timeout);
		auto *msg = rspamd_http_message_from_url(tls ? "https://localhost/" : "http://localhost/");
		REQUIRE(msg != nullptr);
		msg->flags |= RSPAMD_HTTP_FLAG_SSL_NOVERIFY;
		if (large_body) {
			std::string body(1024 * 1024, 'x');
			REQUIRE(rspamd_http_message_set_body(msg, body.data(), body.size()));
		}
		REQUIRE(rspamd_http_connection_write_message(conn, msg, "localhost", nullptr, &state, timeout));
	}

	void handshake()
	{
		if (peer) {
			for (int i = 0; i < 100 && !SSL_is_init_finished(peer); i++) {
				int ret = SSL_accept(peer);
				if (ret != 1) {
					int err = SSL_get_error(peer, ret);
					REQUIRE((err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE));
				}
				ev_run(loop, EVRUN_NOWAIT);
			}
			REQUIRE(SSL_is_init_finished(peer));
		}
		ev_run(loop, EVRUN_NOWAIT);
		REQUIRE(state.errors == 0);
	}

	void receive_request()
	{
		char buf[4096];
		int n = peer ? SSL_read(peer, buf, sizeof(buf)) : read(client_fd, buf, sizeof(buf));
		REQUIRE(n > 0);
		REQUIRE(std::string(buf, n).find("\r\n\r\n") != std::string::npos);
	}

	void respond()
	{
		const std::string response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
		int n = peer ? SSL_write(peer, response.data(), response.size()) : write(client_fd, response.data(), response.size());
		REQUIRE(n == response.size());
		ev_run(loop, EVRUN_NOWAIT);
	}
};

TEST_SUITE("http_timeout")
{
	TEST_CASE("response read outlives connect and TLS handshake timeouts")
	{
		for (bool tls: {false, true}) {
			for (bool explicit_read: {false, true}) {
				CAPTURE(tls);
				CAPTURE(explicit_read);
				client_fixture t(tls);
				rspamd_test::fake_clock clk(1000.0, t.loop);
				t.start(1.0, explicit_read ? 2.0 : 0.0, 0.0, explicit_read ? 6.0 : 0.0, 7.0);
				t.handshake();
				t.receive_request();
				clk.advance(4.0);
				ev_run(t.loop, EVRUN_NOWAIT);
				CHECK(t.state.errors == 0);
				if (t.state.errors == 0) t.respond();
				CHECK(t.state.finishes == 1);
			}
		}
	}

	TEST_CASE("read stage enforces its own deadline")
	{
		for (bool tls: {false, true}) {
			CAPTURE(tls);
			client_fixture t(tls);
			rspamd_test::fake_clock clk(1000.0, t.loop);
			t.start(8.0, 8.0, 0.0, 2.0);
			t.handshake();
			t.receive_request();
			clk.advance(3.0);
			ev_run(t.loop, EVRUN_NOWAIT);
			CHECK(t.state.errors == 1);
			CHECK(t.state.last_error_code == 408);
			CHECK(t.state.last_error == "IO timeout");
		}
	}

	TEST_CASE("blocked fresh writes use the write stage deadline")
	{
		for (bool tls: {false, true}) {
			for (bool longer_write: {false, true}) {
				CAPTURE(tls);
				CAPTURE(longer_write);
				client_fixture t(tls);
				rspamd_test::fake_clock clk(1000.0, t.loop);
				t.start(longer_write ? 2.0 : 6.0, longer_write ? 2.0 : 6.0,
						longer_write ? 6.0 : 2.0, 10.0, 10.0, true);
				t.handshake();
				clk.advance(3.0);
				ev_run(t.loop, EVRUN_NOWAIT);
				if (longer_write) {
					CHECK(t.state.errors == 0);
					clk.advance(4.0);
					ev_run(t.loop, EVRUN_NOWAIT);
				}
				CHECK(t.state.errors == 1);
				CHECK(t.state.last_error_code == 408);
				CHECK(t.state.last_error == "IO timeout");
				CHECK(t.state.finishes == 0);
			}
		}
	}

	TEST_CASE("reused TLS connection gets a new write deadline")
	{
		client_fixture t(true);
		rspamd_test::fake_clock clk(1000.0, t.loop);
		t.start(1.0, 1.0, 6.0, 2.0);
		t.handshake();
		t.receive_request();
		t.respond();
		REQUIRE(t.state.finishes == 1);
		rspamd_http_connection_reset(t.conn);
		t.start(1.0, 1.0, 6.0, 2.0, 10.0, true);
		ev_run(t.loop, EVRUN_NOWAIT);
		clk.advance(3.0);
		ev_run(t.loop, EVRUN_NOWAIT);
		CHECK(t.state.errors == 0);
		/* Make more write progress without allowing it to extend the deadline. */
		char buf[16384];
		int received = -1;
		for (int i = 0; i < 100 && received <= 0; i++) {
			received = SSL_read(t.peer, buf, sizeof(buf));
			if (received <= 0) {
				REQUIRE(SSL_get_error(t.peer, received) == SSL_ERROR_WANT_READ);
			}
			ev_run(t.loop, EVRUN_NOWAIT);
		}
		REQUIRE(received > 0);
		clk.advance(4.0);
		ev_run(t.loop, EVRUN_NOWAIT);
		CHECK(t.state.errors == 1);
		CHECK(t.state.last_error == "IO timeout");
		CHECK(t.state.finishes == 1);
	}

	TEST_CASE("TLS server response uses the write deadline")
	{
		std::string path = __FILE__;
		path = path.substr(0, path.find_last_of('/')) + "/functional/util/server.pem";
		std::unique_ptr<void, decltype(&rspamd_ssl_ctx_free)> server_ctx(
			rspamd_init_ssl_ctx_server(path.c_str(), path.c_str()), rspamd_ssl_ctx_free);
		REQUIRE(server_ctx != nullptr);
		/* The SSL context must outlive the connection that borrows it. */
		http_conn_fixture t;
		rspamd_test::fake_clock clk(1000.0, t.loop);
		std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> client_ctx(SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
		REQUIRE(client_ctx != nullptr);
		std::unique_ptr<SSL, decltype(&SSL_free)> peer(SSL_new(client_ctx.get()), SSL_free);
		REQUIRE(peer != nullptr);
		REQUIRE(SSL_set_fd(peer.get(), t.client_fd) == 1);
		int sndbuf = 4096;
		REQUIRE(setsockopt(t.server_fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) == 0);
		rspamd_http_connection_set_timeouts(t.conn, 0.0, 0.0, 6.0, 2.0);
		REQUIRE(rspamd_http_connection_accept_ssl(t.conn, server_ctx.get(), &t.state, 1.0));
		for (int i = 0; i < 100 && !SSL_is_init_finished(peer.get()); i++) {
			int ret = SSL_connect(peer.get());
			if (ret != 1) {
				int err = SSL_get_error(peer.get(), ret);
				REQUIRE((err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE));
			}
			ev_run(t.loop, EVRUN_NOWAIT);
		}
		REQUIRE(SSL_is_init_finished(peer.get()));
		const std::string request = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
		REQUIRE(SSL_write(peer.get(), request.data(), request.size()) == request.size());
		ev_run(t.loop, EVRUN_NOWAIT);
		REQUIRE(t.state.finishes == 1);
		rspamd_http_connection_reset(t.conn);
		auto *msg = rspamd_http_new_message(HTTP_RESPONSE);
		std::string body(1024 * 1024, 'x');
		REQUIRE(rspamd_http_message_set_body(msg, body.data(), body.size()));
		REQUIRE(rspamd_http_connection_write_message(t.conn, msg, nullptr, nullptr, &t.state, 10.0));
		ev_run(t.loop, EVRUN_NOWAIT);
		clk.advance(3.0);
		ev_run(t.loop, EVRUN_NOWAIT);
		CHECK(t.state.errors == 0);
		clk.advance(4.0);
		ev_run(t.loop, EVRUN_NOWAIT);
		CHECK(t.state.errors == 1);
		CHECK(t.state.last_error == "IO timeout");
		CHECK(t.state.finishes == 1);
	}

	TEST_CASE("single timeout does not restart on initial plain write")
	{
		client_fixture t(false);
		rspamd_test::fake_clock clk(1000.0, t.loop);
		t.start(0.0, 0.0, 0.0, 0.0, 2.0, true);
		clk.advance(1.0);
		t.handshake();
		clk.advance(1.5);
		ev_run(t.loop, EVRUN_NOWAIT);
		CHECK(t.state.errors == 1);
		CHECK(t.state.last_error_code == 408);
	}

	TEST_CASE("stalled TLS handshake retains its handshake deadline")
	{
		client_fixture t(true);
		rspamd_test::fake_clock clk(1000.0, t.loop);
		t.start(8.0, 2.0, 6.0, 6.0);
		clk.advance(3.0);
		ev_run(t.loop, EVRUN_NOWAIT);
		CHECK(t.state.errors == 1);
		CHECK(t.state.last_error_code == 408);
		CHECK(t.state.last_error == "ssl connection timed out");
	}

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
