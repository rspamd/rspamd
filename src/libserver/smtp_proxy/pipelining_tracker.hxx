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

#ifndef RSPAMD_PIPELINING_TRACKER_HXX
#define RSPAMD_PIPELINING_TRACKER_HXX

#pragma once

#include "config.h"
#include "command_parser.hxx"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <string>

namespace rspamd::smtp {

/**
 * Pipelining violations that can be detected
 */
enum class pipelining_violation {
	none,
	too_many_outstanding, // Exceeded max_outstanding limit
	data_before_354,      // Client sent data before receiving 354
	command_during_tls,   // Commands sent during TLS handshake
	command_during_data,  // Commands sent during DATA transfer
	sync_command_pipelined// Sync command was pipelined (EHLO, DATA, STARTTLS, QUIT)
};

/**
 * State of the DATA phase
 */
enum class data_state {
	none,     // Not in DATA phase
	wait_354, // Sent DATA, waiting for 354
	receiving,// Receiving message body
	completed // Received end-of-data, waiting for final response
};

/**
 * Queued command awaiting response
 */
struct pending_command {
	command_type type;
	std::string raw_line;  // For forwarding to backend
	bool expects_multiline;// EHLO expects multiline response
};

/**
 * SMTP pipelining tracker
 *
 * Tracks outstanding pipelined commands and detects violations:
 * - Too many outstanding commands (configurable limit)
 * - DATA bytes sent before 354 response
 * - Commands during TLS handshake
 * - Invalid state transitions
 *
 * Also handles multiline EHLO responses properly.
 */
class pipelining_tracker {
public:
	static constexpr std::size_t default_max_outstanding = 10;

	explicit pipelining_tracker(std::size_t max_outstanding = default_max_outstanding)
		: max_outstanding_(max_outstanding)
	{
	}

	/**
	 * Set maximum outstanding pipelined commands
	 */
	auto set_max_outstanding(std::size_t max) noexcept -> void
	{
		max_outstanding_ = max;
	}

	/**
	 * Get maximum outstanding pipelined commands
	 */
	[[nodiscard]] auto max_outstanding() const noexcept -> std::size_t
	{
		return max_outstanding_;
	}

	/**
	 * Reset tracker to initial state
	 */
	auto reset() noexcept -> void
	{
		pending_.clear();
		data_state_ = data_state::none;
		in_tls_handshake_ = false;
		ehlo_received_ = false;
		pipelining_enabled_ = false;
	}

	/**
	 * Check if a command can be accepted given current state
	 * @param cmd The command to check
	 * @return pipelining_violation if violation detected, none otherwise
	 */
	[[nodiscard]] auto check_command(const parsed_command &cmd) const noexcept -> pipelining_violation
	{
		// Check TLS handshake state
		if (in_tls_handshake_) {
			return pipelining_violation::command_during_tls;
		}

		// Check DATA state
		if (data_state_ == data_state::receiving) {
			return pipelining_violation::command_during_data;
		}

		// Check outstanding limit (only if pipelining is enabled)
		if (pipelining_enabled_ && pending_.size() >= max_outstanding_) {
			return pipelining_violation::too_many_outstanding;
		}

		// Check if sync command is being pipelined
		if (pipelining_enabled_ && !pending_.empty() && command_parser::is_sync_command(cmd.type)) {
			return pipelining_violation::sync_command_pipelined;
		}

		return pipelining_violation::none;
	}

	/**
	 * Record that a command has been sent/forwarded
	 * @param cmd The command that was sent
	 */
	auto command_sent(const parsed_command &cmd) -> void
	{
		pending_command pending;
		pending.type = cmd.type;
		pending.raw_line = cmd.raw_line;
		pending.expects_multiline = (cmd.type == command_type::ehlo);

		pending_.push_back(std::move(pending));

		// Update state for DATA command
		if (cmd.type == command_type::data) {
			data_state_ = data_state::wait_354;
		}

		// Update state for STARTTLS
		if (cmd.type == command_type::starttls) {
			// We'll enter TLS handshake when we receive 220 response
		}

		// Track EHLO/HELO
		if (cmd.type == command_type::ehlo || cmd.type == command_type::helo) {
			ehlo_received_ = true;
		}
	}

	/**
	 * Check if we're waiting for DATA 354 response and client is trying to send body
	 */
	[[nodiscard]] auto check_data_before_354() const noexcept -> bool
	{
		return data_state_ == data_state::wait_354;
	}

	/**
	 * Record that a response has been received
	 * @param code SMTP response code (e.g., 250, 354, 220)
	 * @param is_final True if this is the final line of a multiline response
	 * @return The command type this response was for, or nullopt if unexpected
	 */
	auto response_received(int code, bool is_final) -> std::optional<command_type>
	{
		if (pending_.empty()) {
			return std::nullopt;
		}

		auto &front = pending_.front();

		// For EHLO, wait for final line of multiline response
		if (front.expects_multiline && !is_final) {
			return front.type;
		}

		auto type = front.type;
		pending_.pop_front();

		// Handle state transitions based on response
		switch (type) {
		case command_type::ehlo:
			// EHLO 250 response enables pipelining (usually)
			// Note: We should check for PIPELINING in capability list
			if (code >= 200 && code < 300) {
				pipelining_enabled_ = true;
			}
			break;

		case command_type::data:
			if (code == 354) {
				data_state_ = data_state::receiving;
			}
			else {
				data_state_ = data_state::none;
			}
			break;

		case command_type::starttls:
			if (code == 220) {
				in_tls_handshake_ = true;
			}
			break;

		case command_type::rset:
			// RSET resets transaction state but not session state
			data_state_ = data_state::none;
			break;

		default:
			break;
		}

		return type;
	}

	/**
	 * Record that DATA transfer has completed (end-of-data received)
	 */
	auto data_transfer_complete() -> void
	{
		if (data_state_ == data_state::receiving) {
			data_state_ = data_state::completed;
		}
	}

	/**
	 * Record that final DATA response has been received
	 */
	auto data_response_received() -> void
	{
		data_state_ = data_state::none;
	}

	/**
	 * Record that TLS handshake has completed
	 * @param success True if handshake succeeded
	 */
	auto tls_handshake_complete(bool success) -> void
	{
		in_tls_handshake_ = false;
		if (success) {
			// After STARTTLS, client must send EHLO again
			ehlo_received_ = false;
			pipelining_enabled_ = false;
			// Clear any pending commands (shouldn't be any)
			pending_.clear();
		}
	}

	/**
	 * Check if we need to enable pipelining based on EHLO capabilities
	 */
	auto enable_pipelining(bool enable) noexcept -> void
	{
		pipelining_enabled_ = enable;
	}

	/**
	 * Current number of outstanding commands
	 */
	[[nodiscard]] auto outstanding_count() const noexcept -> std::size_t
	{
		return pending_.size();
	}

	/**
	 * Check if any commands are pending
	 */
	[[nodiscard]] auto has_pending() const noexcept -> bool
	{
		return !pending_.empty();
	}

	/**
	 * Get the next expected response command type
	 */
	[[nodiscard]] auto next_expected_response() const noexcept -> std::optional<command_type>
	{
		if (pending_.empty()) {
			return std::nullopt;
		}
		return pending_.front().type;
	}

	/**
	 * Current DATA phase state
	 */
	[[nodiscard]] auto get_data_state() const noexcept -> data_state
	{
		return data_state_;
	}

	/**
	 * Check if in DATA receiving phase
	 */
	[[nodiscard]] auto is_in_data() const noexcept -> bool
	{
		return data_state_ == data_state::receiving;
	}

	/**
	 * Check if in TLS handshake
	 */
	[[nodiscard]] auto is_in_tls_handshake() const noexcept -> bool
	{
		return in_tls_handshake_;
	}

	/**
	 * Check if EHLO has been received
	 */
	[[nodiscard]] auto has_ehlo() const noexcept -> bool
	{
		return ehlo_received_;
	}

	/**
	 * Check if pipelining is enabled
	 */
	[[nodiscard]] auto is_pipelining_enabled() const noexcept -> bool
	{
		return pipelining_enabled_;
	}

	/**
	 * Get string representation of a pipelining violation
	 */
	[[nodiscard]] static auto violation_to_string(pipelining_violation v) noexcept -> const char *
	{
		switch (v) {
		case pipelining_violation::none:
			return "none";
		case pipelining_violation::too_many_outstanding:
			return "too many outstanding pipelined commands";
		case pipelining_violation::data_before_354:
			return "data sent before 354 response";
		case pipelining_violation::command_during_tls:
			return "command sent during TLS handshake";
		case pipelining_violation::command_during_data:
			return "command sent during DATA transfer";
		case pipelining_violation::sync_command_pipelined:
			return "synchronization command was pipelined";
		}
		return "unknown violation";
	}

private:
	std::deque<pending_command> pending_;
	std::size_t max_outstanding_;
	data_state data_state_ = data_state::none;
	bool in_tls_handshake_ = false;
	bool ehlo_received_ = false;
	bool pipelining_enabled_ = false;
};

}// namespace rspamd::smtp

#endif// RSPAMD_PIPELINING_TRACKER_HXX
