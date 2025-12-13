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

#include "smtp_proxy_session.hxx"
#include "libutil/util.h"
#include "libutil/addr.h"
#include "libserver/dns.h"
#include "libserver/ssl_util.h"
#include "unix-std.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <fcntl.h>

namespace rspamd::smtp {

namespace {

// Set socket to non-blocking mode
auto set_nonblocking(int fd) -> bool
{
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) {
		return false;
	}
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK) >= 0;
}

// Enable TCP_NODELAY
auto set_nodelay(int fd) -> bool
{
	int flag = 1;
	return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) >= 0;
}

// Generate random log tag
auto generate_log_tag(char *buf, size_t len) -> void
{
	static const char alphanum[] = "0123456789abcdef";
	for (size_t i = 0; i < len - 1; ++i) {
		buf[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
	}
	buf[len - 1] = '\0';
}

}// anonymous namespace

auto smtp_proxy_session::create(smtp_proxy_ctx *ctx, int client_fd,
								const rspamd_inet_addr_t *client_addr) -> ptr
{
	// Use shared_ptr with custom destructor pattern
	auto session = ptr(new smtp_proxy_session(ctx, client_fd, client_addr));
	return session;
}

smtp_proxy_session::smtp_proxy_session(smtp_proxy_ctx *ctx, int client_fd,
									   const rspamd_inet_addr_t *client_addr)
	: ctx_(ctx),
	  client_addr_(client_addr),
	  pipeline_(ctx->max_outstanding)
{
	// Create memory pool for session
	pool_ = rspamd_mempool_new(rspamd_mempool_suggest_size(), "smtp_proxy", 0);

	// Generate log tag
	generate_log_tag(log_tag_, sizeof(log_tag_));
	rspamd_strlcpy(pool_->tag.tagname, "smtp_proxy", sizeof(pool_->tag.tagname));
	rspamd_strlcpy(pool_->tag.uid, log_tag_, sizeof(pool_->tag.uid));

	// Initialize client connection
	client_.fd = client_fd;
	client_.session = this;
	client_.reader.set_max_line_length(ctx->max_line_length);

	// Set socket options
	set_nonblocking(client_fd);
	set_nodelay(client_fd);

	// Initialize libev watchers
	ev_io_init(&client_.read_ev, client_read_cb, client_fd, EV_READ);
	ev_io_init(&client_.write_ev, client_write_cb, client_fd, EV_WRITE);
	ev_timer_init(&client_.timeout_ev, client_timeout_cb, ctx->client_timeout, 0.0);

	client_.read_ev.data = this;
	client_.write_ev.data = this;
	client_.timeout_ev.data = this;

	// Initialize backend connection (not connected yet)
	backend_.fd = -1;
	backend_.session = this;

	ev_io_init(&backend_.read_ev, backend_read_cb, -1, EV_READ);
	ev_io_init(&backend_.write_ev, backend_write_cb, -1, EV_WRITE);
	ev_timer_init(&backend_.timeout_ev, backend_timeout_cb, ctx->backend_timeout, 0.0);
	ev_timer_init(&backend_.connect_timeout_ev, backend_timeout_cb, ctx->backend_timeout, 0.0);

	backend_.read_ev.data = this;
	backend_.write_ev.data = this;
	backend_.timeout_ev.data = this;
	backend_.connect_timeout_ev.data = this;
}

smtp_proxy_session::~smtp_proxy_session()
{
	close("session destroyed");

	if (pool_) {
		rspamd_mempool_delete(pool_);
		pool_ = nullptr;
	}
}

auto smtp_proxy_session::start() -> void
{
	// Connect to backend first
	if (!connect_backend()) {
		// Send temporary failure and close
		forward_to_client(reply_parser::get_standard_reply(421));
		close("backend connection failed");
		return;
	}

	// Start timeout timer
	reset_client_timeout();

	// We'll wait for backend greeting before enabling client reads
}

auto smtp_proxy_session::close(const char *reason) -> void
{
	if (closed_) {
		return;
	}

	closed_ = true;
	if (reason) {
		close_reason_ = reason;
	}

	// Stop all watchers
	if (ctx_ && ctx_->event_loop) {
		ev_io_stop(ctx_->event_loop, &client_.read_ev);
		ev_io_stop(ctx_->event_loop, &client_.write_ev);
		ev_timer_stop(ctx_->event_loop, &client_.timeout_ev);

		ev_io_stop(ctx_->event_loop, &backend_.read_ev);
		ev_io_stop(ctx_->event_loop, &backend_.write_ev);
		ev_timer_stop(ctx_->event_loop, &backend_.timeout_ev);
		ev_timer_stop(ctx_->event_loop, &backend_.connect_timeout_ev);
	}

	// Close SSL connections if active
	if (client_.ssl) {
		rspamd_ssl_connection_free(client_.ssl);
		client_.ssl = nullptr;
	}
	if (backend_.ssl) {
		rspamd_ssl_connection_free(backend_.ssl);
		backend_.ssl = nullptr;
	}

	// Close file descriptors
	if (client_.fd >= 0) {
		::close(client_.fd);
		client_.fd = -1;
	}
	if (backend_.fd >= 0) {
		::close(backend_.fd);
		backend_.fd = -1;
	}

	state_ = session_state::closing;
}

auto smtp_proxy_session::connect_backend() -> bool
{
	// Create socket
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		return false;
	}

	set_nonblocking(fd);
	set_nodelay(fd);

	// Connect to backend (simplified - real implementation would use DNS resolution)
	struct sockaddr_in addr{};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(ctx_->backend_port);

	// For now, assume backend_host is an IP address or use localhost
	if (ctx_->backend_host.empty()) {
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	}
	else {
		// This is simplified - real implementation would use proper address resolution
		if (inet_pton(AF_INET, ctx_->backend_host.c_str(), &addr.sin_addr) != 1) {
			::close(fd);
			return false;
		}
	}

	int ret = connect(fd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr));
	if (ret < 0 && errno != EINPROGRESS) {
		::close(fd);
		return false;
	}

	backend_.fd = fd;
	backend_.state = backend_state::connecting;

	// Initialize watchers with actual fd
	ev_io_init(&backend_.read_ev, backend_read_cb, fd, EV_READ);
	ev_io_init(&backend_.write_ev, backend_write_cb, fd, EV_WRITE);
	backend_.read_ev.data = this;
	backend_.write_ev.data = this;

	// Wait for connection to complete (write becomes ready)
	ev_io_init(&backend_.read_ev, backend_connect_cb, fd, EV_WRITE);
	ev_io_start(ctx_->event_loop, &backend_.read_ev);
	ev_timer_start(ctx_->event_loop, &backend_.connect_timeout_ev);

	return true;
}

// Static callback wrappers
void smtp_proxy_session::client_read_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	auto *session = static_cast<smtp_proxy_session *>(w->data);
	if (revents & EV_READ) {
		session->handle_client_read();
	}
}

void smtp_proxy_session::client_write_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	auto *session = static_cast<smtp_proxy_session *>(w->data);
	if (revents & EV_WRITE) {
		session->handle_client_write();
	}
}

void smtp_proxy_session::client_timeout_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
	auto *session = static_cast<smtp_proxy_session *>(w->data);
	session->forward_to_client("421 4.4.2 Timeout\r\n");
	session->close("client timeout");
}

void smtp_proxy_session::backend_read_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	auto *session = static_cast<smtp_proxy_session *>(w->data);
	if (revents & EV_READ) {
		session->handle_backend_read();
	}
}

void smtp_proxy_session::backend_write_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	auto *session = static_cast<smtp_proxy_session *>(w->data);
	if (revents & EV_WRITE) {
		session->handle_backend_write();
	}
}

void smtp_proxy_session::backend_connect_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	auto *session = static_cast<smtp_proxy_session *>(w->data);

	ev_io_stop(loop, w);
	ev_timer_stop(loop, &session->backend_.connect_timeout_ev);

	// Check if connection succeeded
	int err = 0;
	socklen_t len = sizeof(err);
	if (getsockopt(session->backend_.fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err != 0) {
		session->forward_to_client(reply_parser::get_standard_reply(421));
		session->close("backend connection failed");
		return;
	}

	session->backend_.state = backend_state::connected;

	// Re-initialize watchers for normal operation
	ev_io_init(&session->backend_.read_ev, backend_read_cb,
			   session->backend_.fd, EV_READ);
	ev_io_init(&session->backend_.write_ev, backend_write_cb,
			   session->backend_.fd, EV_WRITE);
	session->backend_.read_ev.data = session;
	session->backend_.write_ev.data = session;

	// Start reading backend greeting
	session->enable_backend_read();
	session->reset_backend_timeout();
}

void smtp_proxy_session::backend_timeout_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
	auto *session = static_cast<smtp_proxy_session *>(w->data);
	session->forward_to_client("421 4.4.2 Backend timeout\r\n");
	session->close("backend timeout");
}

auto smtp_proxy_session::handle_client_read() -> void
{
	reset_client_timeout();

	// Read data into buffer
	auto [result, bytes] = client_.read_buffer.read_from_fd(client_.fd);

	switch (result) {
	case io::ring_buffer<>::io_result::ok:
		break;
	case io::ring_buffer<>::io_result::would_block:
		return;
	case io::ring_buffer<>::io_result::eof:
		close("client closed connection");
		return;
	case io::ring_buffer<>::io_result::error:
		close("client read error");
		return;
	case io::ring_buffer<>::io_result::buffer_full:
		// Backpressure - disable reads
		disable_client_read();
		return;
	default:
		return;
	}

	// Process data based on state
	if (in_data_stream_) {
		// Stream DATA directly to backend
		auto [ptr1, len1, ptr2, len2] = client_.read_buffer.get_read_regions();

		// Feed data to the eod_scanner to find end-of-data sequence
		std::optional<eod_scanner::result> eod_result;

		if (len1 > 0) {
			eod_result = eod_scanner_.feed(ptr1, len1, data_bytes_transferred_);
		}
		if (!eod_result && len2 > 0) {
			eod_result = eod_scanner_.feed(ptr2, len2, data_bytes_transferred_ + len1);
		}

		if (eod_result && eod_result->found) {
			// Calculate how much of the current buffer contains the EOD
			std::size_t eod_relative_start = eod_result->eod_start - data_bytes_transferred_;
			std::size_t total = eod_relative_start + eod_result->eod_length;

			// Forward up to and including end-of-data
			if (len1 >= total) {
				forward_to_backend({reinterpret_cast<const char *>(ptr1), total});
			}
			else {
				forward_to_backend({reinterpret_cast<const char *>(ptr1), len1});
				if (ptr2 && total > len1) {
					forward_to_backend({reinterpret_cast<const char *>(ptr2), total - len1});
				}
			}
			client_.read_buffer.consume(total);
			data_bytes_transferred_ += total;

			in_data_stream_ = false;
			eod_scanner_.reset();
			pipeline_.data_transfer_complete();
		}
		else {
			// Forward all available data (keeping potential partial terminator)
			// The eod_scanner tells us how many bytes are "pending" as part of
			// a potential EOD sequence that we shouldn't forward yet
			std::size_t pending = eod_scanner_.pending_bytes();
			std::size_t buffer_size = client_.read_buffer.size();
			std::size_t safe_len = buffer_size > pending ? buffer_size - pending : 0;

			if (safe_len > 0) {
				if (len1 >= safe_len) {
					forward_to_backend({reinterpret_cast<const char *>(ptr1), safe_len});
				}
				else {
					forward_to_backend({reinterpret_cast<const char *>(ptr1), len1});
					if (ptr2) {
						forward_to_backend({reinterpret_cast<const char *>(ptr2), safe_len - len1});
					}
				}
				client_.read_buffer.consume(safe_len);
				data_bytes_transferred_ += safe_len;
			}
		}
	}
	else {
		// Process command lines
		while (!closed_) {
			auto line = client_.reader.try_read_line(client_.read_buffer);

			switch (line.state) {
			case line_result::status::ok:
				process_client_line(line);
				break;
			case line_result::status::incomplete:
				return;
			case line_result::status::violation:
				report_violation(to_violation_type(line.violation_type));
				return;
			}
		}
	}
}

auto smtp_proxy_session::handle_client_write() -> void
{
	auto [result, bytes] = client_.write_buffer.write_to_fd(client_.fd);

	switch (result) {
	case io::ring_buffer<>::io_result::ok:
		if (client_.write_buffer.empty()) {
			disable_client_write();
		}
		break;
	case io::ring_buffer<>::io_result::would_block:
		break;
	case io::ring_buffer<>::io_result::error:
		close("client write error");
		break;
	default:
		break;
	}

	// Re-enable backend reads if we have space
	if (client_.write_buffer.is_below_low_watermark()) {
		enable_backend_read();
	}
}

auto smtp_proxy_session::handle_backend_read() -> void
{
	reset_backend_timeout();

	auto [result, bytes] = backend_.read_buffer.read_from_fd(backend_.fd);

	switch (result) {
	case io::ring_buffer<>::io_result::ok:
		break;
	case io::ring_buffer<>::io_result::would_block:
		return;
	case io::ring_buffer<>::io_result::eof:
		close("backend closed connection");
		return;
	case io::ring_buffer<>::io_result::error:
		close("backend read error");
		return;
	case io::ring_buffer<>::io_result::buffer_full:
		disable_backend_read();
		return;
	default:
		return;
	}

	// Parse reply lines
	line_reader reader;
	while (!closed_) {
		auto line = reader.try_read_line(backend_.read_buffer);

		if (line.state != line_result::status::ok) {
			break;
		}

		auto parsed = backend_.parser.parse_line(line.line, line.raw_line);
		if (!parsed) {
			// Invalid reply - forward as-is for robustness
			forward_to_client(line.raw_line);
			continue;
		}

		bool complete = backend_.parser.accumulate(backend_.current_reply, *parsed);

		if (complete) {
			process_backend_reply(backend_.current_reply);
			backend_.current_reply = smtp_reply{};// Reset for next reply
		}
	}
}

auto smtp_proxy_session::handle_backend_write() -> void
{
	auto [result, bytes] = backend_.write_buffer.write_to_fd(backend_.fd);

	switch (result) {
	case io::ring_buffer<>::io_result::ok:
		if (backend_.write_buffer.empty()) {
			disable_backend_write();
		}
		break;
	case io::ring_buffer<>::io_result::would_block:
		break;
	case io::ring_buffer<>::io_result::error:
		close("backend write error");
		break;
	default:
		break;
	}

	// Re-enable client reads if we have space
	if (backend_.write_buffer.is_below_low_watermark() && !client_.read_paused) {
		enable_client_read();
	}
}

auto smtp_proxy_session::process_client_line(const line_result &line) -> void
{
	// Parse the command
	auto cmd = cmd_parser_.parse(line.line, line.raw_line);

	// Check pipelining rules
	auto violation = pipeline_.check_command(cmd);
	if (violation != pipelining_violation::none) {
		report_violation(to_violation_type(violation));
		return;
	}

	// Handle unsupported commands
	if (cmd.type == command_type::bdat) {
		forward_to_client("502 5.5.1 BDAT not implemented\r\n");
		return;
	}

	if (cmd.type == command_type::auth) {
		forward_to_client("502 5.5.1 AUTH not implemented\r\n");
		return;
	}

	// Track command state
	switch (cmd.type) {
	case command_type::ehlo:
	case command_type::helo:
		client_helo_domain_ = cmd.argument;
		break;

	case command_type::mail_from:
		transaction_.reset();
		transaction_.mail_from = cmd.argument;
		if (cmd.has_param("BODY")) {
			auto body = cmd.get_param("BODY");
			if (body && (*body == "8BITMIME" || *body == "8bitmime")) {
				transaction_.has_8bitmime = true;
			}
		}
		if (cmd.has_param("SMTPUTF8")) {
			transaction_.has_smtputf8 = true;
		}
		break;

	case command_type::rcpt_to:
		transaction_.rcpt_to.push_back(cmd.argument);
		break;

	case command_type::data:
		if (pipeline_.check_data_before_354()) {
			report_violation(violation_type::data_before_354);
			return;
		}
		break;

	case command_type::rset:
		transaction_.reset();
		break;

	case command_type::quit:
		// Forward QUIT and prepare to close
		state_ = session_state::closing;
		break;

	default:
		break;
	}

	// Record command sent
	pipeline_.command_sent(cmd);

	// Forward to backend
	forward_to_backend(cmd.raw_line);
}

auto smtp_proxy_session::process_backend_reply(const smtp_reply &reply) -> void
{
	// Get expected command type
	auto expected = pipeline_.next_expected_response();

	// For greeting (no command expected), relay directly
	if (!expected && backend_.state == backend_state::connected) {
		backend_.state = backend_state::ready;
		forward_to_client(reply.get_raw());
		enable_client_read();
		return;
	}

	// Record response received
	bool is_final = reply.is_complete();
	auto responded_to = pipeline_.response_received(reply.code, is_final);

	if (!responded_to) {
		// Unexpected response - forward anyway
		forward_to_client(reply.get_raw());
		return;
	}

	// Handle specific responses
	switch (*responded_to) {
	case command_type::ehlo:
		handle_ehlo_response(reply);
		break;

	case command_type::data:
		handle_data_response(reply);
		break;

	case command_type::starttls:
		handle_starttls_response(reply);
		break;

	default:
		// Forward reply as-is
		forward_to_client(reply.get_raw());
		break;
	}

	// Update session state
	if (responded_to && reply.is_success()) {
		switch (*responded_to) {
		case command_type::ehlo:
		case command_type::helo:
			state_ = session_state::greeted;
			break;
		case command_type::mail_from:
			state_ = session_state::mail_from;
			break;
		case command_type::rcpt_to:
			state_ = session_state::rcpt_to;
			break;
		default:
			break;
		}
	}
}

auto smtp_proxy_session::handle_ehlo_response(const smtp_reply &reply) -> void
{
	if (!reply.is_success()) {
		forward_to_client(reply.get_raw());
		return;
	}

	// Parse EHLO capabilities
	backend_ehlo_ = backend_.parser.parse_ehlo_response(reply);

	// Check for PIPELINING capability
	if (backend_ehlo_->has_capability("PIPELINING")) {
		pipeline_.enable_pipelining(true);
	}

	// Rewrite capabilities based on configuration
	std::vector<std::string> caps_to_remove;
	std::vector<ehlo_capability> caps_to_add;

	// Always remove AUTH (v1)
	if (ctx_->ehlo_filter.remove_auth) {
		caps_to_remove.push_back("AUTH");
	}

	// Remove CHUNKING/BDAT (v1)
	if (ctx_->ehlo_filter.remove_chunking) {
		caps_to_remove.push_back("CHUNKING");
		caps_to_remove.push_back("BINARYMIME");
	}

	// Handle STARTTLS
	if (!ctx_->starttls_enabled) {
		caps_to_remove.push_back("STARTTLS");
	}
	else if (!backend_ehlo_->has_capability("STARTTLS")) {
		// Add STARTTLS if we support it but backend doesn't advertise
		caps_to_add.push_back({"STARTTLS", {}});
	}

	// Generate rewritten response
	std::string rewritten = backend_.parser.rewrite_ehlo_response(
		*backend_ehlo_,
		{},// Keep all by default
		caps_to_remove,
		caps_to_add,
		ctx_->ehlo_filter.max_size);

	forward_to_client(rewritten);
}

auto smtp_proxy_session::handle_data_response(const smtp_reply &reply) -> void
{
	forward_to_client(reply.get_raw());

	if (reply.code == 354) {
		// Backend accepted DATA, enter streaming mode
		in_data_stream_ = true;
		state_ = session_state::data;
		data_bytes_transferred_ = 0;
	}
}

auto smtp_proxy_session::handle_starttls_response(const smtp_reply &reply) -> void
{
	if (reply.code != 220) {
		forward_to_client(reply.get_raw());
		pipeline_.tls_handshake_complete(false);
		return;
	}

	// Don't forward 220 yet - initiate TLS on both sides
	state_ = session_state::tls_handshake;

	// Start backend TLS first, then client TLS
	start_backend_tls();
}

auto smtp_proxy_session::start_client_tls() -> void
{
	// Forward the 220 to client to trigger their TLS handshake
	forward_to_client("220 2.0.0 Ready to start TLS\r\n");

	// TODO: Implement SSL accept using rspamd_ssl_accept_fd (to be added)
	// For now, this is a placeholder
}

auto smtp_proxy_session::start_backend_tls() -> void
{
	// TODO: Implement backend TLS upgrade
	// This would use rspamd_ssl_connect_fd
}

auto smtp_proxy_session::forward_to_backend(std::string_view data) -> void
{
	std::size_t written = backend_.write_buffer.write(data);
	if (written > 0) {
		enable_backend_write();
	}

	// Apply backpressure if needed
	if (backend_.write_buffer.is_above_high_watermark()) {
		disable_client_read();
	}
}

auto smtp_proxy_session::forward_to_client(std::string_view data) -> void
{
	std::size_t written = client_.write_buffer.write(data);
	if (written > 0) {
		enable_client_write();
	}

	// Apply backpressure if needed
	if (client_.write_buffer.is_above_high_watermark()) {
		disable_backend_read();
	}
}

auto smtp_proxy_session::report_violation(violation_type v) -> void
{
	// TODO: Call Lua on_violation hook

	// Default action: send error and close
	std::string msg = "500 5.5.1 Protocol violation: ";
	msg += violation_to_string(v);
	msg += "\r\n";

	forward_to_client(msg);
	close(violation_to_string(v));
}

auto smtp_proxy_session::run_precheck() -> bool
{
	// TODO: Implement precheck using rspamd_task
	return true;
}

// Helper methods for event management
auto smtp_proxy_session::enable_client_read() -> void
{
	if (!ev_is_active(&client_.read_ev)) {
		ev_io_start(ctx_->event_loop, &client_.read_ev);
	}
}

auto smtp_proxy_session::disable_client_read() -> void
{
	ev_io_stop(ctx_->event_loop, &client_.read_ev);
}

auto smtp_proxy_session::enable_client_write() -> void
{
	if (!ev_is_active(&client_.write_ev)) {
		ev_io_start(ctx_->event_loop, &client_.write_ev);
	}
}

auto smtp_proxy_session::disable_client_write() -> void
{
	ev_io_stop(ctx_->event_loop, &client_.write_ev);
}

auto smtp_proxy_session::enable_backend_read() -> void
{
	if (!ev_is_active(&backend_.read_ev)) {
		ev_io_start(ctx_->event_loop, &backend_.read_ev);
	}
}

auto smtp_proxy_session::disable_backend_read() -> void
{
	ev_io_stop(ctx_->event_loop, &backend_.read_ev);
}

auto smtp_proxy_session::enable_backend_write() -> void
{
	if (!ev_is_active(&backend_.write_ev)) {
		ev_io_start(ctx_->event_loop, &backend_.write_ev);
	}
}

auto smtp_proxy_session::disable_backend_write() -> void
{
	ev_io_stop(ctx_->event_loop, &backend_.write_ev);
}

auto smtp_proxy_session::reset_client_timeout() -> void
{
	ev_timer_stop(ctx_->event_loop, &client_.timeout_ev);
	ev_timer_set(&client_.timeout_ev, ctx_->client_timeout, 0.0);
	ev_timer_start(ctx_->event_loop, &client_.timeout_ev);
}

auto smtp_proxy_session::reset_backend_timeout() -> void
{
	ev_timer_stop(ctx_->event_loop, &backend_.timeout_ev);
	ev_timer_set(&backend_.timeout_ev, ctx_->backend_timeout, 0.0);
	ev_timer_start(ctx_->event_loop, &backend_.timeout_ev);
}

}// namespace rspamd::smtp
