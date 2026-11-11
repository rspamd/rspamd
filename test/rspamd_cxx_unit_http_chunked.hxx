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
 * Chunked transfer-encoding tests for the HTTP connection.
 *
 * With `Transfer-Encoding: chunked` the parser reports no content length when
 * the headers end, so the body storage is created from the first body callback
 * instead. There `parser->content_length` is whatever is left *of the current
 * chunk*, i.e. a number the peer picked: it sizes an allocation, so it has to
 * be bounded before it is used, and the chunk size itself has to be rejected
 * when it does not fit into 64 bits.
 *
 * These tests also pin down the two observable ends of chunk handling: the body
 * has to be reassembled without the chunk framing, and trailers have to reach
 * the finished message like any other header.
 */

#ifndef RSPAMD_CXX_UNIT_HTTP_CHUNKED_HXX
#define RSPAMD_CXX_UNIT_HTTP_CHUNKED_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "libserver/http/http_connection.h"
#include "libserver/http/http_context.h"
#include "libserver/http/http_message.h"
#include "libutil/util.h"
#include "contrib/libev/ev.h"

#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <string>

namespace http_chunked_test {

struct handler_state {
	int errors = 0;
	int finishes = 0;
	int last_error_code = 0;
	std::string body;
	std::string trailer;
	bool trailer_seen = false;
	/* Release the message from the finish handler, as keepalive does */
	bool reset_on_finish = false;
	/* Replace the body from the finish handler, as the proxy does */
	bool replace_body_on_finish = false;
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

	gsize blen = 0;
	auto *bstart = rspamd_http_message_get_body(msg, &blen);

	if (bstart != nullptr) {
		st->body.assign(bstart, blen);
	}

	auto *tok = rspamd_http_message_find_header(msg, "X-Trailer");

	if (tok != nullptr) {
		st->trailer_seen = true;
		st->trailer.assign(tok->begin, tok->len);
	}

	if (st->replace_body_on_finish) {
		/*
		 * What proxy_backend_master_finish_handler does through
		 * proxy_request_decompress: the previous body storage is freed here
		 */
		rspamd_http_message_set_body(msg, "x", 1);
	}

	if (st->reset_on_finish) {
		rspamd_http_connection_reset(conn);
	}

	return 0;
}

struct chunked_fixture {
	struct ev_loop *loop = nullptr;
	struct rspamd_http_context *ctx = nullptr;
	struct rspamd_http_connection *conn = nullptr;
	int server_fd = -1;
	int client_fd = -1;
	handler_state state;

	chunked_fixture()
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
	}

	~chunked_fixture()
	{
		rspamd_http_connection_unref(conn);
		rspamd_http_context_free(ctx);
		close(client_fd);
		close(server_fd);
		ev_loop_destroy(loop);
	}

	chunked_fixture(const chunked_fixture &) = delete;
	chunked_fixture &operator=(const chunked_fixture &) = delete;

	/*
	 * Pushes a whole request into the socket and lets the loop drain it. The
	 * read timeout is large enough never to fire, so the only thing that can
	 * end the loop is the request being finished or rejected.
	 */
	void feed(const std::string &payload, gsize max_size = 0)
	{
		if (max_size > 0) {
			rspamd_http_connection_set_max_size(conn, max_size);
		}

		rspamd_http_connection_read_message(conn, &state, 1000.0);
		REQUIRE(write(client_fd, payload.data(), payload.size()) ==
				(ssize_t) payload.size());

		for (int i = 0; i < 16; i++) {
			if (state.finishes > 0 || state.errors > 0) {
				break;
			}

			ev_run(loop, EVRUN_NOWAIT);
		}
	}

	/* One write, then let the loop pick it up as its own read */
	void push(const std::string &part)
	{
		REQUIRE(write(client_fd, part.data(), part.size()) ==
				(ssize_t) part.size());

		for (int i = 0; i < 4; i++) {
			ev_run(loop, EVRUN_NOWAIT);
		}
	}
};

TEST_SUITE("http_chunked")
{
	/*
	 * A chunk size of 0xfffffffffffffff1 is accepted by the parser (it fits
	 * into 64 bits), and after the first data byte is accounted for, what is
	 * left of the chunk is 0xfffffffffffffff0. Sizing the body storage from
	 * that number overflows `len + sizeof(rspamd_fstring_t)`, which yields a
	 * tiny allocation that claims to be enormous, and the very first body byte
	 * is then written outside of it.
	 *
	 * `max_size` is set so that the request has a definite outcome to check,
	 * but it is not what makes the case safe: the allocation used to be made
	 * from the announced size before the limit was ever consulted.
	 */
	TEST_CASE("huge chunk size must not overflow the body allocation")
	{
		chunked_fixture t;

		t.feed("POST /check HTTP/1.1\r\n"
			   "Transfer-Encoding: chunked\r\n"
			   "\r\n"
			   "fffffffffffffff1\r\n"
			   "A",
			   4096);

		CHECK(t.state.finishes == 0);
		CHECK(t.state.errors == 1);
	}

	/*
	 * Same shape, but the size only has to be large rather than adversarial:
	 * a chunk that cannot possibly be allocated must be reported as an error
	 * instead of taking the whole process down inside malloc.
	 */
	TEST_CASE("unallocatable chunk size is reported rather than fatal")
	{
		chunked_fixture t;

		t.feed("POST /check HTTP/1.1\r\n"
			   "Transfer-Encoding: chunked\r\n"
			   "\r\n"
			   "1fffffffffffff\r\n"
			   "A",
			   4096);

		CHECK(t.state.finishes == 0);
		CHECK(t.state.errors == 1);
	}

	/*
	 * `max_size` is the configured ceiling for a message, so a chunk that
	 * announces more than that must be refused, and refused before the body
	 * storage is sized from it.
	 */
	TEST_CASE("chunk size beyond max_size is refused")
	{
		chunked_fixture t;

		t.feed("POST /check HTTP/1.1\r\n"
			   "Transfer-Encoding: chunked\r\n"
			   "\r\n"
			   "100000\r\n"
			   "A",
			   1024);

		CHECK(t.state.finishes == 0);
		CHECK(t.state.errors == 1);
	}

	/*
	 * 17 hex digits cannot fit into a 64 bit chunk size. The multiply-and-add
	 * overflow check must catch it: comparing the wrapped result against the
	 * previous value alone does not, because wrapping does not always produce
	 * a smaller number.
	 */
	TEST_CASE("chunk size wider than 64 bits is rejected")
	{
		chunked_fixture t;

		t.feed("POST /check HTTP/1.1\r\n"
			   "Transfer-Encoding: chunked\r\n"
			   "\r\n"
			   "12000000000000000\r\n"
			   "A",
			   4096);

		CHECK(t.state.finishes == 0);
		CHECK(t.state.errors == 1);
	}

	/* The framing must not end up in the body, and no payload may be lost */
	TEST_CASE("multi chunk body is reassembled without framing")
	{
		chunked_fixture t;

		t.feed("POST /check HTTP/1.1\r\n"
			   "Transfer-Encoding: chunked\r\n"
			   "\r\n"
			   "5\r\nhello\r\n"
			   "1\r\n \r\n"
			   "5\r\nworld\r\n"
			   "0\r\n\r\n");

		CHECK(t.state.errors == 0);
		REQUIRE(t.state.finishes == 1);
		CHECK(t.state.body == "hello world");
	}

	/*
	 * Once a read lands entirely inside the body, the connection switches to
	 * reading straight into the message's body storage, and the parser is then
	 * handed a buffer it does not own. Completing the message runs application
	 * code that can release the message -- which is exactly what the library's
	 * own keepalive path does, resetting the connection from inside
	 * `on_message_complete` -- while the parser still has the bytes that
	 * followed the message to walk over. Those bytes live in the buffer that
	 * has just been freed.
	 *
	 * Sending this in three writes puts each stage in its own read: the last
	 * one carries the end of the body, the terminating chunk and a pipelined
	 * request, all inside the body storage.
	 */
	TEST_CASE("message released at completion does not strand the parser")
	{
		chunked_fixture t;

		t.state.reset_on_finish = true;
		rspamd_http_connection_read_message(t.conn, &t.state, 1000.0);

		t.push("POST /check HTTP/1.1\r\n"
			   "Transfer-Encoding: chunked\r\n"
			   "\r\n"
			   "10\r\n");
		/* A read that is nothing but body: this is what turns zero-copy on */
		t.push("0123456789abcdef");
		/* End of chunk, terminating chunk, then a pipelined request */
		t.push("\r\n0\r\n\r\n"
			   "GET /next HTTP/1.1\r\nHost: x\r\n\r\n");

		CHECK(t.state.finishes == 1);
	}

	/*
	 * Transfer-Encoding wins over Content-Length for framing, and the parser
	 * duly ignores the length -- but it has already parsed it, and it is still
	 * sitting in `content_length` when the headers-complete callback runs. Body
	 * storage sized from it there escapes the bound that the body callback
	 * applies, so the announced length must be bounded wherever it is used, and
	 * a message carrying both framings is not one to make room for at all.
	 */
	TEST_CASE("chunked framing with a conflicting Content-Length is refused")
	{
		chunked_fixture t;

		t.feed("POST /check HTTP/1.1\r\n"
			   "Transfer-Encoding: chunked\r\n"
			   "Content-Length: 9000000000000000\r\n"
			   "\r\n"
			   "4\r\nbody\r\n"
			   "0\r\n\r\n");

		CHECK(t.state.finishes == 0);
		CHECK(t.state.errors == 1);
	}

	/*
	 * A zero-copy read goes straight into the body storage, so the parser is
	 * handed memory the message owns. Holding the message is not enough: a
	 * completion callback may keep the message and replace its body, which frees
	 * exactly that memory -- the proxy does this when it decompresses a reply.
	 * If the zero-copy window reached past the end of the body, the bytes that
	 * followed the message are in there too, and the parser walks into them
	 * after the callback has freed them.
	 *
	 * The writes below are shaped to arm zero-copy with room to spare: a chunk
	 * larger than its first fragment sizes the storage, the fragment that fills
	 * it turns zero-copy on, and the read after that grows the storage by a
	 * whole buffer -- leaving a window far past the end of the chunk for the
	 * terminating chunk and a pipelined request to land in.
	 */
	TEST_CASE("zero copy reads never reach past the end of the body")
	{
		chunked_fixture t;

		t.state.replace_body_on_finish = true;
		rspamd_http_connection_read_message(t.conn, &t.state, 1000.0);

		t.push("POST /check HTTP/1.1\r\n"
			   "Transfer-Encoding: chunked\r\n"
			   "\r\n"
			   "1000\r\n");
		/* First fragment: sizes the storage from the rest of the chunk */
		t.push(std::string(100, 'a'));
		/* Fills the storage exactly, so the next read has to grow it */
		t.push(std::string(4096 - 100, 'b'));
		/* End of chunk, terminating chunk, then a pipelined request */
		t.push("\r\n0\r\n\r\n"
			   "GET /next HTTP/1.1\r\nHost: x\r\n\r\n");

		CHECK(t.state.finishes == 1);
	}

	/* A trailer is a header: it has to be attached to the finished message */
	TEST_CASE("trailer reaches the finished message")
	{
		chunked_fixture t;

		t.feed("POST /check HTTP/1.1\r\n"
			   "Transfer-Encoding: chunked\r\n"
			   "\r\n"
			   "4\r\nbody\r\n"
			   "0\r\n"
			   "X-Trailer: tvalue\r\n"
			   "\r\n");

		CHECK(t.state.errors == 0);
		REQUIRE(t.state.finishes == 1);
		CHECK(t.state.body == "body");
		CHECK(t.state.trailer_seen == true);
		CHECK(t.state.trailer == "tvalue");
	}
}

}// namespace http_chunked_test

#endif /* RSPAMD_CXX_UNIT_HTTP_CHUNKED_HXX */
