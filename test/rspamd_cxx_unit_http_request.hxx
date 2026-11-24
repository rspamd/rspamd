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
 * The request that the HTTP client writes, and the methods that a server
 * takes.
 *
 * Host is the first field after the request line (RFC 9112 3.2), and
 * Content-Length is sent only with content or for a method that anticipates
 * it (RFC 9110 8.6). QUERY (RFC 10008) is sent and parsed, and the check
 * commands of the protocol take GET and POST only: any other method gets 405.
 */

#ifndef RSPAMD_CXX_UNIT_HTTP_REQUEST_HXX
#define RSPAMD_CXX_UNIT_HTTP_REQUEST_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "libserver/http/http_connection.h"
#include "libserver/http/http_context.h"
#include "libserver/http/http_message.h"
#include "libserver/http/http_private.h"
#include "libserver/protocol.h"
#include "libserver/task.h"
#include "libcryptobox/keypair.h"
#include "libutil/mem_pool.h"
#include "libutil/util.h"
#include "contrib/libev/ev.h"

#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <memory>
#include <string>
#include <utility>

namespace http_request_test {

struct request_state {
	int errors = 0;
	int finishes = 0;
	int method = -1;
};

static void
record_error(struct rspamd_http_connection *conn, GError *)
{
	static_cast<request_state *>(conn->ud)->errors++;
}

static int
record_finish(struct rspamd_http_connection *conn, struct rspamd_http_message *msg)
{
	auto *st = static_cast<request_state *>(conn->ud);
	st->finishes++;
	st->method = msg->method;

	return 0;
}

struct request_fixture {
	struct ev_loop *loop = nullptr;
	struct rspamd_http_context *ctx = nullptr;
	struct rspamd_http_connection *conn = nullptr;
	int local_fd = -1;
	int remote_fd = -1;
	request_state state;

	explicit request_fixture(bool client)
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

	~request_fixture()
	{
		rspamd_http_connection_unref(conn);
		rspamd_http_context_free(ctx);
		close(remote_fd);
		close(local_fd);
		ev_loop_destroy(loop);
	}

	request_fixture(const request_fixture &) = delete;
	request_fixture &operator=(const request_fixture &) = delete;

	/* What the connection has sent so far is read and returned */
	std::string sent()
	{
		std::string out;
		char buf[4096];
		ssize_t r;

		for (int i = 0; i < 4; i++) {
			ev_run(loop, EVRUN_NOWAIT);

			while ((r = read(remote_fd, buf, sizeof(buf))) > 0) {
				out.append(buf, r);
			}
		}

		return out;
	}

	void push(const std::string &data)
	{
		REQUIRE(::write(remote_fd, data.data(), data.size()) == (ssize_t) data.size());

		for (int i = 0; i < 16 && state.errors == 0 && state.finishes == 0; i++) {
			ev_run(loop, EVRUN_NOWAIT);
		}
	}

	/* The request that the client writes for `msg` */
	std::string request(struct rspamd_http_message *msg, const char *host,
						const char *mime_type = nullptr)
	{
		REQUIRE(rspamd_http_connection_write_message(conn, msg, host, mime_type,
													 &state, 1000.0));

		return sent();
	}
};

struct protocol_fixture {
	rspamd_mempool_t *pool;
	struct rspamd_task *task;
	struct rspamd_http_message *msg;

	protocol_fixture(enum http_method method, const char *path)
	{
		pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "http_request", 0);
		task = rspamd_task_new(nullptr, nullptr, pool, nullptr, nullptr, FALSE);
		msg = rspamd_http_message_from_url((std::string("http://localhost/") + path).c_str());
		REQUIRE(msg != nullptr);
		msg->method = method;
	}

	~protocol_fixture()
	{
		rspamd_http_message_unref(msg);
		rspamd_task_free(task);
		rspamd_mempool_delete(pool);
	}

	protocol_fixture(const protocol_fixture &) = delete;
	protocol_fixture &operator=(const protocol_fixture &) = delete;
};

}// namespace http_request_test

TEST_SUITE("http_request")
{
	using namespace http_request_test;

	TEST_CASE("client: a request without content has no Content-Length")
	{
		for (auto method: {HTTP_GET, HTTP_HEAD}) {
			CAPTURE(http_method_str(method));
			request_fixture t(true);

			auto *msg = rspamd_http_message_from_url("http://example.com/path");
			REQUIRE(msg != nullptr);
			msg->method = method;

			CHECK(t.request(msg, "example.com") == std::string(http_method_str(method)) +
													   " /path HTTP/1.1\r\n"
													   "Host: example.com\r\n"
													   "Connection: close\r\n"
													   "\r\n");
		}
	}

	TEST_CASE("client: Host goes first, with a non-standard port")
	{
		request_fixture t(true);

		auto *msg = rspamd_http_message_from_url("http://example.com:8080/");
		REQUIRE(msg != nullptr);
		rspamd_http_message_add_header(msg, "Accept", "*/*");

		CHECK(t.request(msg, "example.com") == "GET / HTTP/1.1\r\n"
											   "Host: example.com:8080\r\n"
											   "Connection: close\r\n"
											   "Accept: */*\r\n"
											   "\r\n");
	}

	TEST_CASE("client: a Host set by the caller goes first")
	{
		request_fixture t(true);

		auto *msg = rspamd_http_message_from_url("http://192.0.2.1/");
		REQUIRE(msg != nullptr);
		msg->flags |= RSPAMD_HTTP_FLAG_ORDERED_HEADERS;
		rspamd_http_message_add_header(msg, "Accept", "*/*");
		rspamd_http_message_add_header(msg, "host", "vhost.example.com");

		CHECK(t.request(msg, "192.0.2.1") == "GET / HTTP/1.1\r\n"
											 "Host: vhost.example.com\r\n"
											 "Connection: close\r\n"
											 "Accept: */*\r\n"
											 "\r\n");
	}

	TEST_CASE("client: POST and QUERY keep Content-Length, even without content")
	{
		for (auto method: {HTTP_POST, HTTP_QUERY}) {
			for (const std::string body: {"", "ok"}) {
				CAPTURE(http_method_str(method));
				CAPTURE(body);
				request_fixture t(true);

				auto *msg = rspamd_http_message_from_url("http://example.com/");
				REQUIRE(msg != nullptr);
				msg->method = method;

				if (!body.empty()) {
					rspamd_http_message_set_body(msg, body.data(), body.size());
				}

				std::string expected = std::string(http_method_str(method)) +
									   " / HTTP/1.1\r\n"
									   "Host: example.com\r\n"
									   "Connection: close\r\n"
									   "Content-Length: " +
									   std::to_string(body.size()) + "\r\n";

				if (!body.empty()) {
					expected += "Content-Type: text/plain\r\n";
				}

				CHECK(t.request(msg, "example.com", "text/plain") == expected + "\r\n" + body);
			}
		}
	}

	TEST_CASE("a method is set by its name, an unknown name is refused")
	{
		auto *msg = rspamd_http_message_from_url("http://example.com/");
		REQUIRE(msg != nullptr);

		CHECK(rspamd_http_message_set_method(msg, "query"));
		CHECK(msg->method == HTTP_QUERY);
		CHECK_FALSE(rspamd_http_message_set_method(msg, "FOO"));
		CHECK(msg->method == HTTP_QUERY);

		/* The legacy protocol methods are not HTTP ones */
		CHECK_FALSE(rspamd_http_message_set_method(msg, "SYMBOLS"));
		CHECK_FALSE(rspamd_http_message_set_method(msg, "CHECK"));
		CHECK(msg->method == HTTP_QUERY);

		rspamd_http_message_unref(msg);
	}

	TEST_CASE("server: a QUERY request is parsed")
	{
		request_fixture t(false);

		rspamd_http_connection_read_message(t.conn, &t.state, 1000.0);
		t.push("QUERY / HTTP/1.1\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok");

		CHECK(t.state.errors == 0);
		REQUIRE(t.state.finishes == 1);
		CHECK(t.state.method == HTTP_QUERY);
	}

	TEST_CASE("an encrypted request keeps its method")
	{
		std::unique_ptr<struct rspamd_cryptobox_keypair, decltype(&rspamd_keypair_unref)>
			server_kp{rspamd_keypair_new(RSPAMD_KEYPAIR_KEX), rspamd_keypair_unref};
		unsigned int pklen;
		auto *pk = rspamd_keypair_component(server_kp.get(), RSPAMD_KEYPAIR_COMPONENT_PK, &pklen);

		/* A request without a method gets POST, as it has a body */
		for (auto [method, expected]: {std::pair{HTTP_PUT, HTTP_PUT},
									   std::pair{HTTP_QUERY, HTTP_QUERY},
									   std::pair{HTTP_INVALID, HTTP_POST}}) {
			CAPTURE(http_method_str(expected));
			request_fixture client(true);
			request_fixture server(false);

			auto *msg = rspamd_http_message_from_url("http://localhost/checkv2");
			REQUIRE(msg != nullptr);
			msg->method = method;
			rspamd_http_message_set_body(msg, "ok", 2);
			auto *server_pk = rspamd_pubkey_from_bin(pk, pklen, RSPAMD_KEYPAIR_KEX);
			REQUIRE(server_pk != nullptr);
			rspamd_http_message_set_peer_key(msg, server_pk);
			rspamd_pubkey_unref(server_pk);

			auto request = client.request(msg, "localhost");
			REQUIRE(request.find("Key: ") != std::string::npos);

			rspamd_http_connection_set_key(server.conn, server_kp.get());
			rspamd_http_connection_read_message(server.conn, &server.state, 1000.0);
			server.push(request);

			CHECK(server.state.errors == 0);
			REQUIRE(server.state.finishes == 1);
			CHECK(server.state.method == expected);
		}
	}
}

TEST_SUITE("protocol methods")
{
	using namespace http_request_test;

	static const char *const check_commands[] = {
		"check", "checkv2", "checkv3", "scan", "symbols",
		"process", "report", "report_ifspam"};

	TEST_CASE("check commands take GET and POST")
	{
		for (auto *cmd: check_commands) {
			for (auto method: {HTTP_GET, HTTP_POST}) {
				CAPTURE(cmd);
				CAPTURE(http_method_str(method));
				protocol_fixture f(method, cmd);

				CHECK(rspamd_protocol_handle_request(f.task, f.msg));
				CHECK(f.task->err == nullptr);
			}
		}
	}

	TEST_CASE("check commands refuse any other method with 405")
	{
		for (auto *cmd: check_commands) {
			for (auto method: {HTTP_QUERY, HTTP_PUT, HTTP_DELETE, HTTP_HEAD}) {
				CAPTURE(cmd);
				CAPTURE(http_method_str(method));
				protocol_fixture f(method, cmd);

				CHECK_FALSE(rspamd_protocol_handle_request(f.task, f.msg));
				REQUIRE(f.task->err != nullptr);
				CHECK(f.task->err->code == 405);
				CHECK((f.task->protocol_flags & RSPAMD_TASK_PROTOCOL_FLAG_VERBATIM_ERR_CODE) != 0);
			}
		}
	}

	TEST_CASE("other commands take any method")
	{
		protocol_fixture f(HTTP_PUT, "ping");

		CHECK(rspamd_protocol_handle_request(f.task, f.msg));
		CHECK(f.task->err == nullptr);
	}
}

#endif
