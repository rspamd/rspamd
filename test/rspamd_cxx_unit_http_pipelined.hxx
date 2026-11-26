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
 * Bytes that follow a completed message in the same read.
 *
 * Completing a message hands it to the application, and the parser used to go
 * on over the rest of the read: with keepalive it was ready for another
 * message, and a reply written from the finish handler re-armed it through
 * rspamd_http_connection_reset. The callbacks then appended to the message that
 * had been handed over, or to the reply being written, and the headers of the
 * second message freed a body that a running scan or the pending write still
 * used. Such bytes are ignored now.
 */

#ifndef RSPAMD_CXX_UNIT_HTTP_PIPELINED_HXX
#define RSPAMD_CXX_UNIT_HTTP_PIPELINED_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "libserver/http/http_connection.h"
#include "libserver/http/http_context.h"
#include "libserver/http/http_message.h"
#include "libserver/http/http_private.h"
#include "libserver/http/http_util.h"
#include "libcryptobox/keypair.h"
#include "libcryptobox/cryptobox.h"
#include "libutil/util.h"
#include "contrib/libev/ev.h"
#include "contrib/uthash/utlist.h"

#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <memory>
#include <string>

namespace http_pipelined_test {

struct pipe_state {
	int errors = 0;
	int bodies = 0;
	int finishes = 0;
	/* Reply the finish handler sends at once, if any */
	bool reply = false;
	/* What the body handler was given: the application keeps this pointer */
	const char *kept = nullptr;
	size_t kept_len = 0;
	std::string kept_copy;
	/* The message that was handed over, held until the fixture goes */
	struct rspamd_http_message *msg = nullptr;
	/* The reply as the end of its write sees it */
	size_t reply_url_len = SIZE_MAX;
	size_t reply_body_len = SIZE_MAX;
	std::string reply_body;
};

static void
pipe_error(struct rspamd_http_connection *conn, GError *)
{
	static_cast<pipe_state *>(conn->ud)->errors++;
}

static int
pipe_body(struct rspamd_http_connection *conn, struct rspamd_http_message *,
		  const char *chunk, gsize len)
{
	auto *st = static_cast<pipe_state *>(conn->ud);

	st->bodies++;
	st->kept = chunk;
	st->kept_len = len;
	st->kept_copy.assign(chunk, len);

	return 0;
}

static int
pipe_finish(struct rspamd_http_connection *conn, struct rspamd_http_message *msg)
{
	auto *st = static_cast<pipe_state *>(conn->ud);

	st->finishes++;

	if (st->finishes == 1 && st->msg == nullptr) {
		st->msg = rspamd_http_message_ref(msg);
	}

	if (st->finishes == 2) {
		st->reply_url_len = msg->url ? msg->url->len : 0;
		st->reply_body_len = msg->body_buf.len;
		st->reply_body.assign(msg->body_buf.begin, msg->body_buf.len);
	}

	/* The second call is the end of the reply write */
	if (st->reply && st->finishes == 1) {
		/* What a worker does for a request it can answer on the spot */
		rspamd_http_connection_reset(conn);

		auto *reply = rspamd_http_new_message(HTTP_RESPONSE);
		reply->code = 200;
		rspamd_http_message_set_body(reply, "pong", 4);
		rspamd_http_connection_write_message(conn, reply, nullptr, "text/plain",
											 st, 1000.0);
	}

	return 0;
}

struct pipe_fixture {
	struct ev_loop *loop = nullptr;
	struct rspamd_http_context *ctx = nullptr;
	struct rspamd_http_connection *conn = nullptr;
	int local_fd = -1;
	int remote_fd = -1;
	pipe_state state;

	explicit pipe_fixture(bool client)
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
															pipe_error, pipe_finish,
															RSPAMD_HTTP_CLIENT_SIMPLE, local_fd);
		}
		else {
			conn = rspamd_http_connection_new_server(ctx, local_fd,
													 pipe_body, pipe_error, pipe_finish, 0);
			conn->ud = &state;
			rspamd_http_connection_read_message(conn, &state, 1000.0);
		}

		REQUIRE(conn != nullptr);
	}

	~pipe_fixture()
	{
		if (state.msg) {
			rspamd_http_message_unref(state.msg);
		}

		rspamd_http_connection_unref(conn);
		rspamd_http_context_free(ctx);
		close(remote_fd);
		close(local_fd);
		ev_loop_destroy(loop);
	}

	pipe_fixture(const pipe_fixture &) = delete;
	pipe_fixture &operator=(const pipe_fixture &) = delete;

	void run(int rounds = 8)
	{
		for (int i = 0; i < rounds; i++) {
			ev_run(loop, EVRUN_NOWAIT);
		}
	}

	void push(const std::string &data, bool half_close = false)
	{
		REQUIRE(write(remote_fd, data.data(), data.size()) == (ssize_t) data.size());

		if (half_close) {
			shutdown(remote_fd, SHUT_WR);
		}

		run();
	}

	/* Everything the connection has sent so far */
	std::string sent()
	{
		std::string out;
		char buf[4096];

		run();

		ssize_t r;
		while ((r = read(remote_fd, buf, sizeof(buf))) > 0) {
			out.append(buf, r);
		}

		return out;
	}
};

static std::string
body_of(const std::string &reply)
{
	auto pos = reply.find("\r\n\r\n");

	return pos == std::string::npos ? std::string() : reply.substr(pos + 4);
}

}// namespace http_pipelined_test

TEST_SUITE("http_pipelined")
{
	TEST_CASE("server: a request after a kept-alive one does not touch the first")
	{
		const char *firsts[] = {"Connection: keep-alive\r\n", "Proxy-Connection: keep-alive\r\n"};

		for (auto *hdr: firsts) {
			using namespace http_pipelined_test;
			pipe_fixture t(false);

			/* The finish handler does not reply: the scan is still running */
			t.push(std::string("POST /checkv2 HTTP/1.1\r\n") + hdr +
				   "Content-Length: 10\r\n\r\nAAAAAAAAAA"
				   "POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\nBBBBB");

			REQUIRE(t.state.finishes == 1);
			REQUIRE(t.state.msg != nullptr);
			CHECK(t.state.bodies == 1);
			CHECK(t.state.errors == 0);

			/* The body the application keeps, and the message it was handed */
			CHECK(t.state.kept_copy == "AAAAAAAAAA");
			CHECK(std::string(t.state.kept, t.state.kept_len) == "AAAAAAAAAA");
			CHECK(std::string(t.state.msg->url->str, t.state.msg->url->len) == "/checkv2");
			CHECK(t.state.msg->body_buf.len == 10);
			CHECK(memcmp(t.state.msg->body_buf.begin, "AAAAAAAAAA", 10) == 0);
			CHECK(t.state.msg->method == HTTP_POST);
		}
	}

	TEST_CASE("server: a request after one answered at once does not touch the reply")
	{
		const char *firsts[] = {
			"GET /ping HTTP/1.1\r\n\r\n",
			"POST /checkv2 HTTP/1.1\r\nConnection: close\r\nContent-Length: 2\r\n\r\nhi",
			"SYMBOLS SPAMC/1.2\r\nContent-length: 2\r\n\r\nhi",
			"SYMBOLS SPAMC/1.2\nContent-length: 2\n\nhi",
		};

		for (auto *first: firsts) {
			for (bool half_close: {false, true}) {
				using namespace http_pipelined_test;
				pipe_fixture t(false);
				t.state.reply = true;

				t.push(std::string(first) +
						   "POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\nBBBBB",
					   half_close);

				auto reply = t.sent();

				/* The request, then the end of the reply write */
				CHECK(t.state.finishes == 2);
				CHECK(t.state.errors == 0);
				CHECK(reply.rfind("HTTP/1.1 200", 0) == 0);
				/* Exactly the reply: nothing of the second request in it */
				CHECK(body_of(reply) == "pong");
				/* The reply itself was left alone too */
				CHECK(t.state.reply_url_len == 0);
				CHECK(t.state.reply_body == "pong");
			}
		}
	}

	TEST_CASE("client: a reply after a completed one does not touch the first")
	{
		using namespace http_pipelined_test;
		pipe_fixture t(true);

		auto *msg = rspamd_http_message_from_url("http://example.com/");
		REQUIRE(msg != nullptr);
		REQUIRE(rspamd_http_connection_write_message(t.conn, msg, "example.com", nullptr,
													 &t.state, 1000.0));
		t.sent();

		t.push("HTTP/1.1 200 OK\r\nProxy-Connection: keep-alive\r\nContent-Length: 2\r\n\r\nok"
			   "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nEVIL!");

		REQUIRE(t.state.finishes == 1);
		REQUIRE(t.state.msg != nullptr);
		CHECK(t.state.errors == 0);
		CHECK(t.state.msg->code == 200);
		CHECK(t.state.msg->body_buf.len == 2);
		CHECK(memcmp(t.state.msg->body_buf.begin, "ok", 2) == 0);
	}

	TEST_CASE("server: an encrypted request with an outer HEAD line is parsed once")
	{
		using namespace http_pipelined_test;
		rspamd_cryptobox_init();

		using kp_ptr = std::unique_ptr<struct rspamd_cryptobox_keypair,
									   decltype(&rspamd_keypair_unref)>;
		kp_ptr skp{rspamd_keypair_new(RSPAMD_KEYPAIR_KEX), rspamd_keypair_unref};
		kp_ptr ckp{rspamd_keypair_new(RSPAMD_KEYPAIR_KEX), rspamd_keypair_unref};
		unsigned int pklen;
		const unsigned char *pk = rspamd_keypair_component(skp.get(),
														   RSPAMD_KEYPAIR_COMPONENT_PK, &pklen);

		/* A real encrypted request, produced by the client side */
		std::string wire;
		{
			pipe_fixture c(true);
			rspamd_http_connection_set_key(c.conn, ckp.get());

			auto *msg = rspamd_http_message_from_url("http://example.com/checkv2");
			REQUIRE(msg != nullptr);
			msg->method = HTTP_POST;
			rspamd_http_message_set_body(msg, "0123456789", 10);
			auto *spk = rspamd_pubkey_from_bin(pk, pklen, RSPAMD_KEYPAIR_KEX);
			REQUIRE(spk != nullptr);
			rspamd_http_message_set_peer_key(msg, spk);
			REQUIRE(rspamd_http_connection_write_message(c.conn, msg, "example.com",
														 nullptr, &c.state, 1000.0));
			wire = c.sent();
			rspamd_pubkey_unref(spk);
		}

		REQUIRE(wire.rfind("POST ", 0) == 0);

		/* The outer request line is not authenticated */
		wire.replace(0, 4, "HEAD");

		for (bool reply: {false, true}) {
			pipe_fixture t(false);
			rspamd_http_connection_set_key(t.conn, skp.get());
			t.state.reply = reply;
			t.push(wire);

			CHECK(t.state.errors == 0);
			CHECK(t.state.bodies == 1);
			CHECK(t.state.kept_copy == "0123456789");
			/* The request, and with a reply the end of its write */
			CHECK(t.state.finishes == (reply ? 2 : 1));
			REQUIRE(t.state.msg != nullptr);
			CHECK(t.state.msg->method == HTTP_POST);
			CHECK(std::string(t.state.msg->url->str, t.state.msg->url->len) == "/checkv2");
		}
	}

	TEST_CASE("server: legacy requests with a half-closed socket still get a reply")
	{
		const char *requests[] = {
			"SYMBOLS SPAMC/1.2\r\nContent-length: 2\r\n\r\nhi",
			"SYMBOLS SPAMC/1.2\nContent-length: 2\n\nhi",
			"CHECK SPAMC/1.2\r\nContent-length: 2\r\n\r\nhi",
		};

		for (auto *req: requests) {
			using namespace http_pipelined_test;
			pipe_fixture t(false);
			t.state.reply = true;

			t.push(req, true);

			CHECK(t.state.errors == 0);
			CHECK(t.state.finishes == 2);
			CHECK(body_of(t.sent()) == "pong");
		}
	}

	TEST_CASE("server: end of file in the middle of a body is still an error")
	{
		using namespace http_pipelined_test;
		pipe_fixture t(false);
		t.state.reply = true;

		t.push("SYMBOLS SPAMC/1.2\r\nContent-length: 10\r\n\r\nhi", true);

		CHECK(t.state.finishes == 0);
		CHECK(t.state.errors == 1);
	}
}

#endif
