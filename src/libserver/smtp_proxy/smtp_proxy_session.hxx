/*
 * Copyright 2025 Vsevolod Stakhov
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

#ifndef RSPAMD_SMTP_PROXY_SESSION_HXX
#define RSPAMD_SMTP_PROXY_SESSION_HXX

#pragma once

#include "config.h"
#include "smtp_proxy.hxx"
#include "eod_scanner.hxx"
#include "contrib/libev/ev.h"
#include "libutil/mem_pool.h"
#include "libutil/addr.h"
#include "libutil/libev_helper.h"

#include <memory>
#include <string>
#include <optional>
#include <functional>

struct rspamd_worker;
struct rspamd_config;
struct rspamd_dns_resolver;
struct rspamd_ssl_connection;
struct lua_State;

namespace rspamd::smtp {

/**
 * Forward declarations
 */
class smtp_proxy_session;
struct smtp_proxy_ctx;

/**
 * Precheck hook point configuration
 */
enum class precheck_point {
	disabled,       // No precheck
	on_connect,     // After connection established
	after_mail,     // After MAIL FROM accepted
	after_first_rcpt// After first RCPT TO accepted
};

/**
 * EHLO capability filtering configuration
 */
struct ehlo_filter_config {
	bool keep_dsn = true;
	bool keep_8bitmime = true;
	bool keep_pipelining = true;
	bool keep_smtputf8 = true;
	bool remove_auth = true;
	bool remove_chunking = true;
	bool advertise_starttls = false;
	std::optional<std::size_t> max_size;// Optional SIZE limit clamp
};

/**
 * SMTP proxy worker context
 *
 * This is the shared context for all sessions within a worker process.
 */
struct smtp_proxy_ctx {
	static constexpr uint64_t magic = 0x534d545050524f58ULL;// "SMTPPROX"

	uint64_t ctx_magic = magic;

	// Common worker fields (must be at start for rspamd_worker_check_context)
	struct ev_loop *event_loop = nullptr;
	struct rspamd_dns_resolver *resolver = nullptr;
	struct rspamd_config *cfg = nullptr;

	// SMTP proxy specific configuration
	ev_tstamp client_timeout = 300.0;// Client I/O timeout
	ev_tstamp backend_timeout = 60.0;// Backend connection timeout
	ev_tstamp greeting_delay = 0.0;  // Delay before sending greeting

	std::size_t max_line_length = 4096;// Maximum line length
	std::size_t max_outstanding = 10;  // Maximum pipelined commands
	std::size_t max_connections = 0;   // Maximum connections (0 = unlimited)

	precheck_point precheck_hook = precheck_point::disabled;
	ehlo_filter_config ehlo_filter;

	// TLS configuration
	bool starttls_enabled = false;
	void *ssl_ctx = nullptr;// SSL_CTX for server-side TLS

	// Backend configuration
	std::string backend_host;
	uint16_t backend_port = 25;
	bool backend_ssl = false;

	// Lua state for policy hooks
	lua_State *lua_state = nullptr;
	int on_connect_ref = -1;  // Lua callback ref for on_connect
	int on_violation_ref = -1;// Lua callback ref for on_violation
	int on_precheck_ref = -1; // Lua callback ref for precheck

	// Session cache
	void *sessions_cache = nullptr;

	// Worker reference
	struct rspamd_worker *worker = nullptr;
};

/**
 * Backend connection state
 */
enum class backend_state {
	disconnected,
	connecting,
	connected,
	tls_handshaking,
	ready
};

/**
 * Client connection leg
 */
struct client_connection {
	int fd = -1;
	smtp_buffer read_buffer;
	smtp_buffer write_buffer;
	ev_io read_ev;
	ev_io write_ev;
	ev_timer timeout_ev;

	struct rspamd_ssl_connection *ssl = nullptr;
	struct rspamd_io_ev ssl_ev;// Used for SSL handshake and I/O
	bool ssl_active = false;

	// Read state
	line_reader reader;
	bool read_paused = false;

	// Session reference
	smtp_proxy_session *session = nullptr;
};

/**
 * Backend connection leg
 */
struct backend_connection {
	int fd = -1;
	smtp_buffer read_buffer;
	smtp_buffer write_buffer;
	ev_io read_ev;
	ev_io write_ev;
	ev_timer timeout_ev;
	ev_timer connect_timeout_ev;

	struct rspamd_ssl_connection *ssl = nullptr;
	struct rspamd_io_ev ssl_ev;// Used for SSL handshake and I/O
	bool ssl_active = false;

	backend_state state = backend_state::disconnected;

	// Response parsing state
	reply_parser parser;
	smtp_reply current_reply;

	// Session reference
	smtp_proxy_session *session = nullptr;
};

/**
 * SMTP proxy session
 *
 * Manages a single client connection and its backend connection.
 * Handles command parsing, pipelining tracking, and DATA streaming.
 */
class smtp_proxy_session : public std::enable_shared_from_this<smtp_proxy_session> {
public:
	using ptr = std::shared_ptr<smtp_proxy_session>;

	/**
	 * Create a new session
	 */
	static auto create(smtp_proxy_ctx *ctx, int client_fd,
					   const rspamd_inet_addr_t *client_addr) -> ptr;

	~smtp_proxy_session();

	// Prevent copying
	smtp_proxy_session(const smtp_proxy_session &) = delete;
	smtp_proxy_session &operator=(const smtp_proxy_session &) = delete;

	/**
	 * Start the session (connect to backend, etc.)
	 */
	auto start() -> void;

	/**
	 * Close the session
	 */
	auto close(const char *reason = nullptr) -> void;

	/**
	 * Get session state
	 */
	[[nodiscard]] auto get_state() const noexcept -> session_state
	{
		return state_;
	}

	/**
	 * Get client address
	 */
	[[nodiscard]] auto get_client_addr() const noexcept -> const rspamd_inet_addr_t *
	{
		return client_addr_;
	}

	/**
	 * Get current transaction state
	 */
	[[nodiscard]] auto get_transaction() const noexcept -> const transaction_state &
	{
		return transaction_;
	}

	/**
	 * Get memory pool
	 */
	[[nodiscard]] auto get_pool() const noexcept -> rspamd_mempool_t *
	{
		return pool_;
	}

private:
	explicit smtp_proxy_session(smtp_proxy_ctx *ctx, int client_fd,
								const rspamd_inet_addr_t *client_addr);

	// Event handlers
	static void client_read_cb(struct ev_loop *loop, ev_io *w, int revents);
	static void client_write_cb(struct ev_loop *loop, ev_io *w, int revents);
	static void client_timeout_cb(struct ev_loop *loop, ev_timer *w, int revents);

	static void backend_read_cb(struct ev_loop *loop, ev_io *w, int revents);
	static void backend_write_cb(struct ev_loop *loop, ev_io *w, int revents);
	static void backend_connect_cb(struct ev_loop *loop, ev_io *w, int revents);
	static void backend_timeout_cb(struct ev_loop *loop, ev_timer *w, int revents);

	// Internal handlers
	auto handle_client_read() -> void;
	auto handle_client_write() -> void;
	auto handle_backend_read() -> void;
	auto handle_backend_write() -> void;

	auto process_client_line(const line_result &line) -> void;
	auto process_backend_reply(const smtp_reply &reply) -> void;

	auto connect_backend() -> bool;
	auto forward_to_backend(std::string_view data) -> void;
	auto forward_to_client(std::string_view data) -> void;

	auto handle_ehlo_response(const smtp_reply &reply) -> void;
	auto handle_data_response(const smtp_reply &reply) -> void;
	auto handle_starttls_response(const smtp_reply &reply) -> void;

	auto start_client_tls() -> void;
	auto start_backend_tls() -> void;

	// SSL callbacks
	static void client_ssl_handler(int fd, short what, gpointer d);
	static void client_ssl_error_handler(gpointer d, GError *err);
	static void backend_ssl_handler(int fd, short what, gpointer d);
	static void backend_ssl_error_handler(gpointer d, GError *err);

	auto handle_client_ssl_ready() -> void;
	auto handle_backend_ssl_ready() -> void;

	auto report_violation(violation_type v) -> void;
	auto run_precheck() -> bool;
	[[nodiscard]] auto should_run_precheck(command_type cmd) const -> bool;

	auto enable_client_read() -> void;
	auto disable_client_read() -> void;
	auto enable_client_write() -> void;
	auto disable_client_write() -> void;

	auto enable_backend_read() -> void;
	auto disable_backend_read() -> void;
	auto enable_backend_write() -> void;
	auto disable_backend_write() -> void;

	auto reset_client_timeout() -> void;
	auto reset_backend_timeout() -> void;

	// SSL-aware I/O helpers
	auto read_client_data() -> std::pair<io::ring_buffer<>::io_result, std::size_t>;
	auto write_client_data() -> std::pair<io::ring_buffer<>::io_result, std::size_t>;
	auto read_backend_data() -> std::pair<io::ring_buffer<>::io_result, std::size_t>;
	auto write_backend_data() -> std::pair<io::ring_buffer<>::io_result, std::size_t>;

	// Context and configuration
	smtp_proxy_ctx *ctx_;
	rspamd_mempool_t *pool_;
	const rspamd_inet_addr_t *client_addr_;

	// Connection state
	client_connection client_;
	backend_connection backend_;

	// SMTP state
	session_state state_ = session_state::initial;
	transaction_state transaction_;
	pipelining_tracker pipeline_;
	command_parser cmd_parser_;

	// EHLO state
	std::optional<ehlo_response> client_ehlo_;
	std::optional<ehlo_response> backend_ehlo_;
	std::string client_helo_domain_;

	// DATA streaming state
	bool in_data_stream_ = false;
	std::size_t data_bytes_transferred_ = 0;
	eod_scanner eod_scanner_;// Scanner for end-of-data sequence

	// Session bookkeeping
	bool closed_ = false;
	std::string close_reason_;

	// Precheck state
	bool precheck_done_ = false;
	std::string precheck_reject_reply_;

	// Logging tag
	char log_tag_[9] = {0};
};

}// namespace rspamd::smtp

#endif// RSPAMD_SMTP_PROXY_SESSION_HXX
