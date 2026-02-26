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

#ifndef RSPAMD_SMTP_PROXY_HXX
#define RSPAMD_SMTP_PROXY_HXX

#pragma once

/**
 * SMTP Proxy Library
 *
 * This library provides the underlying components for implementing an SMTP proxy:
 *
 * - ring_buffer: Fixed-capacity I/O buffer with watermarks and CRLF scanning
 * - line_reader: CRLF-terminated line extraction with violation detection
 * - command_parser: SMTP command parsing (EHLO, MAIL, RCPT, etc.)
 * - reply_parser: SMTP response parsing and EHLO capability handling
 * - pipelining_tracker: Pipelining state tracking and violation detection
 *
 * These components are designed to be used together in an async I/O context
 * with libev and the Rspamd worker infrastructure.
 */

#include "ring_buffer.hxx"
#include "line_reader.hxx"
#include "command_parser.hxx"
#include "reply_parser.hxx"
#include "pipelining_tracker.hxx"

namespace rspamd::smtp {

/**
 * Unified violation type that combines all protocol violations
 */
enum class violation_type {
	// Line violations
	bare_lf,
	line_too_long,
	nul_in_line,
	missing_crlf,

	// Pipelining violations
	too_many_outstanding,
	data_before_354,
	command_during_tls,
	command_during_data,
	sync_command_pipelined,

	// Command violations
	unknown_command,
	invalid_syntax,
	unsupported_command
};

/**
 * Convert violation type to human-readable string
 */
[[nodiscard]] inline auto violation_to_string(violation_type v) noexcept -> const char *
{
	switch (v) {
	case violation_type::bare_lf:
		return "bare LF without CR";
	case violation_type::line_too_long:
		return "line too long";
	case violation_type::nul_in_line:
		return "NUL character in line";
	case violation_type::missing_crlf:
		return "missing CRLF terminator";
	case violation_type::too_many_outstanding:
		return "too many outstanding pipelined commands";
	case violation_type::data_before_354:
		return "data sent before 354 response";
	case violation_type::command_during_tls:
		return "command sent during TLS handshake";
	case violation_type::command_during_data:
		return "command sent during DATA transfer";
	case violation_type::sync_command_pipelined:
		return "synchronization command was pipelined";
	case violation_type::unknown_command:
		return "unknown command";
	case violation_type::invalid_syntax:
		return "invalid command syntax";
	case violation_type::unsupported_command:
		return "unsupported command";
	}
	return "unknown violation";
}

/**
 * Convert line_violation to unified violation_type
 */
[[nodiscard]] inline auto to_violation_type(line_violation v) noexcept -> violation_type
{
	switch (v) {
	case line_violation::bare_lf:
		return violation_type::bare_lf;
	case line_violation::line_too_long:
		return violation_type::line_too_long;
	case line_violation::nul_in_line:
		return violation_type::nul_in_line;
	case line_violation::missing_crlf:
		return violation_type::missing_crlf;
	case line_violation::none:
		break;
	}
	return violation_type::invalid_syntax;// Fallback
}

/**
 * Convert pipelining_violation to unified violation_type
 */
[[nodiscard]] inline auto to_violation_type(pipelining_violation v) noexcept -> violation_type
{
	switch (v) {
	case pipelining_violation::too_many_outstanding:
		return violation_type::too_many_outstanding;
	case pipelining_violation::data_before_354:
		return violation_type::data_before_354;
	case pipelining_violation::command_during_tls:
		return violation_type::command_during_tls;
	case pipelining_violation::command_during_data:
		return violation_type::command_during_data;
	case pipelining_violation::sync_command_pipelined:
		return violation_type::sync_command_pipelined;
	case pipelining_violation::none:
		break;
	}
	return violation_type::invalid_syntax;// Fallback
}

/**
 * SMTP session state
 */
enum class session_state {
	initial,      // Before client sends EHLO/HELO
	greeted,      // After successful EHLO/HELO
	mail_from,    // After successful MAIL FROM
	rcpt_to,      // After at least one successful RCPT TO
	data,         // In DATA transfer
	tls_handshake,// During STARTTLS handshake
	closing       // Connection is closing
};

/**
 * Transaction state (within a session)
 */
struct transaction_state {
	std::string mail_from;
	std::vector<std::string> rcpt_to;
	std::size_t message_size = 0;
	bool has_8bitmime = false;
	bool has_smtputf8 = false;

	auto reset() -> void
	{
		mail_from.clear();
		rcpt_to.clear();
		message_size = 0;
		has_8bitmime = false;
		has_smtputf8 = false;
	}

	[[nodiscard]] auto has_envelope() const noexcept -> bool
	{
		return !mail_from.empty() && !rcpt_to.empty();
	}
};

/**
 * Default buffer size for SMTP proxy
 */
constexpr std::size_t default_buffer_size = 16384;

/**
 * Type alias for the default ring buffer
 */
using smtp_buffer = io::ring_buffer<default_buffer_size>;

}// namespace rspamd::smtp

#endif// RSPAMD_SMTP_PROXY_HXX
