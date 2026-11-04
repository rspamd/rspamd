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
 * `Key` header handling of the HTTP connection.
 *
 * The header carries the public key the peer encrypted the message with, and
 * a message keeps the first peer key it gets. A repeated header used to
 * replace the key and leak the reference; on a client, where the expected
 * server key is installed before the reply is read, a plaintext header in the
 * reply could replace the key the reply is then decrypted with.
 *
 * Both messages below have no body, so they fail with "cannot decrypt
 * message", which is where the key the connection settled on is recorded.
 */

#ifndef RSPAMD_CXX_UNIT_HTTP_KEY_HXX
#define RSPAMD_CXX_UNIT_HTTP_KEY_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "libserver/http/http_connection.h"
#include "libserver/http/http_context.h"
#include "libserver/http/http_message.h"
#include "libcryptobox/keypair.h"
#include "libutil/util.h"
#include "contrib/libev/ev.h"

#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <memory>
#include <string>

namespace http_key_test {

using keypair_ptr = std::unique_ptr<struct rspamd_cryptobox_keypair, decltype(&rspamd_keypair_unref)>;

static keypair_ptr
new_keypair()
{
	return keypair_ptr{rspamd_keypair_new(RSPAMD_KEYPAIR_KEX), rspamd_keypair_unref};
}

static std::string
print_keypair(struct rspamd_cryptobox_keypair *kp, unsigned int how)
{
	GString *out = rspamd_keypair_print(kp, RSPAMD_KEYPAIR_ENCODING_DEFAULT, how);
	std::string res(out->str, out->len);
	g_string_free(out, TRUE);

	return res;
}

/* `Key: <short id of the receiver>=<public key of the sender>` */
static std::string
key_header(struct rspamd_cryptobox_keypair *receiver, struct rspamd_cryptobox_keypair *sender)
{
	return "Key: " + print_keypair(receiver, RSPAMD_KEYPAIR_ID_SHORT) + "=" +
		   print_keypair(sender, RSPAMD_KEYPAIR_PUBKEY) + "\r\n";
}

static std::string
raw_pk(struct rspamd_cryptobox_keypair *kp)
{
	unsigned int len;
	auto *pk = rspamd_keypair_component(kp, RSPAMD_KEYPAIR_COMPONENT_PK, &len);

	return std::string(reinterpret_cast<const char *>(pk), len);
}

struct key_state {
	int errors = 0;
	int finishes = 0;
	/* Raw peer key the connection holds when the message fails */
	std::string peer_pk;
	std::string error;
};

static void
record_error(struct rspamd_http_connection *conn, GError *err)
{
	auto *st = static_cast<key_state *>(conn->ud);
	st->errors++;
	st->error = err ? err->message : "";

	auto *pk = const_cast<struct rspamd_cryptobox_pubkey *>(rspamd_http_connection_get_peer_key(conn));

	if (pk != nullptr) {
		unsigned int len;
		auto *raw = rspamd_pubkey_get_pk(pk, &len);
		st->peer_pk.assign(reinterpret_cast<const char *>(raw), len);
	}
}

static int
record_finish(struct rspamd_http_connection *conn, struct rspamd_http_message *)
{
	static_cast<key_state *>(conn->ud)->finishes++;

	return 0;
}

struct key_fixture {
	struct ev_loop *loop = nullptr;
	struct rspamd_http_context *ctx = nullptr;
	struct rspamd_http_connection *conn = nullptr;
	int local_fd = -1;
	int remote_fd = -1;
	key_state state;

	explicit key_fixture(bool client)
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

	~key_fixture()
	{
		rspamd_http_connection_unref(conn);
		rspamd_http_context_free(ctx);
		close(remote_fd);
		close(local_fd);
		ev_loop_destroy(loop);
	}

	key_fixture(const key_fixture &) = delete;
	key_fixture &operator=(const key_fixture &) = delete;

	/* What the connection has sent so far, after letting the loop run */
	std::string drain()
	{
		std::string out;
		char buf[4096];

		for (int i = 0; i < 16 && out.empty(); i++) {
			ev_run(loop, EVRUN_NOWAIT);

			ssize_t r;

			while ((r = read(remote_fd, buf, sizeof(buf))) > 0) {
				out.append(buf, r);
			}
		}

		return out;
	}

	void push(const std::string &data)
	{
		REQUIRE(write(remote_fd, data.data(), data.size()) == (ssize_t) data.size());

		for (int i = 0; i < 16 && state.errors == 0 && state.finishes == 0; i++) {
			ev_run(loop, EVRUN_NOWAIT);
		}
	}
};

}// namespace http_key_test

TEST_SUITE("http_key")
{
	TEST_CASE("server keeps the first matching key of a request")
	{
		using namespace http_key_test;
		auto server = new_keypair();
		auto first = new_keypair();
		auto second = new_keypair();
		auto other = new_keypair();
		key_fixture t(false);

		rspamd_http_connection_set_key(t.conn, server.get());
		rspamd_http_connection_read_message(t.conn, &t.state, 1000.0);
		/* A key for another receiver does not count as the first one */
		t.push("POST /check HTTP/1.1\r\n" +
			   key_header(other.get(), second.get()) +
			   key_header(server.get(), first.get()) +
			   key_header(server.get(), second.get()) +
			   "Content-Length: 0\r\n\r\n");

		CHECK(t.state.finishes == 0);
		REQUIRE(t.state.errors == 1);
		CHECK(t.state.peer_pk == raw_pk(first.get()));
	}

	TEST_CASE("client ignores a key in the reply")
	{
		using namespace http_key_test;
		auto client = new_keypair();
		auto server = new_keypair();
		auto forged = new_keypair();
		key_fixture t(true);

		rspamd_http_connection_set_key(t.conn, client.get());

		auto *msg = rspamd_http_message_from_url("http://localhost/check");
		REQUIRE(msg != nullptr);
		auto pk = raw_pk(server.get());
		auto *server_pk = rspamd_pubkey_from_bin(reinterpret_cast<const unsigned char *>(pk.data()),
												 pk.size(), RSPAMD_KEYPAIR_KEX);
		REQUIRE(server_pk != nullptr);
		rspamd_http_message_set_peer_key(msg, server_pk);
		rspamd_pubkey_unref(server_pk);
		REQUIRE(rspamd_http_connection_write_message(t.conn, msg, "localhost", nullptr,
													 &t.state, 1000.0));

		/* The request is out, so the client now reads the reply */
		auto request = t.drain();
		REQUIRE(request.find("Key: ") != std::string::npos);
		REQUIRE(t.state.errors == 0);

		/* Whoever sits on the wire can name the client key id and its own key */
		t.push("HTTP/1.1 200 OK\r\n" +
			   key_header(client.get(), forged.get()) +
			   "Content-Length: 0\r\n\r\n");

		CHECK(t.state.finishes == 0);
		REQUIRE(t.state.errors == 1);
		CHECK(t.state.peer_pk == raw_pk(server.get()));
	}

	/*
	 * A client parses a reply that arrives while it is still writing the
	 * request (e.g. an early 413). That reply used to be taken as plaintext
	 * on a fresh connection, so anyone on the wire could answer an encrypted
	 * request in clear text.
	 */
	TEST_CASE("client refuses a plaintext reply to an encrypted request in progress")
	{
		using namespace http_key_test;
		auto client = new_keypair();
		auto server = new_keypair();
		key_fixture t(true);

		rspamd_http_connection_set_key(t.conn, client.get());

		auto *msg = rspamd_http_message_from_url("http://localhost/check");
		REQUIRE(msg != nullptr);
		auto pk = raw_pk(server.get());
		auto *server_pk = rspamd_pubkey_from_bin(reinterpret_cast<const unsigned char *>(pk.data()),
												 pk.size(), RSPAMD_KEYPAIR_KEX);
		REQUIRE(server_pk != nullptr);
		rspamd_http_message_set_peer_key(msg, server_pk);
		rspamd_pubkey_unref(server_pk);
		/* Larger than the socket buffers, so the request cannot be sent at once */
		std::string body(4 * 1024 * 1024, 'x');
		REQUIRE(rspamd_http_message_set_body(msg, body.data(), body.size()));
		REQUIRE(rspamd_http_connection_write_message(t.conn, msg, "localhost", nullptr,
													 &t.state, 1000.0));
		ev_run(t.loop, EVRUN_NOWAIT);
		REQUIRE(t.state.errors == 0);

		t.push("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nforged");

		CAPTURE(t.state.error);
		CHECK(t.state.finishes == 0);
		CHECK(t.state.errors == 1);
	}
}

#endif
