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

#ifndef RSPAMD_EOD_SCANNER_HXX
#define RSPAMD_EOD_SCANNER_HXX

#pragma once

#include "config.h"

#include <cstddef>
#include <cstdint>
#include <optional>

namespace rspamd::smtp {

/**
 * SMTP End-of-Data scanner using a state machine.
 * Scans for <CRLF>.<CRLF>, handles bare LF violations.
 * Maintains state across buffer boundaries.
 */
class eod_scanner {
public:
	/**
	 * Result of scanning
	 */
	struct result {
		bool found = false;
		std::size_t eod_start = 0; // Position where EOD sequence starts (the leading CR or LF)
		std::size_t eod_length = 0;// Length of the EOD sequence
		std::size_t body_end = 0;  // Position of last body byte (before terminator)
		bool had_violation = false;// True if bare LF or other violation detected
	};

	/**
	 * Reset scanner to initial state
	 */
	auto reset() noexcept -> void
	{
		state_ = state::body;
		bytes_scanned_ = 0;
		eod_start_offset_ = 0;
		had_violation_ = false;
	}

	/**
	 * Feed data to the scanner incrementally
	 *
	 * @param data Pointer to data chunk
	 * @param len Length of data chunk
	 * @param base_offset Offset in the overall stream where this chunk starts
	 * @return result if EOD found, nullopt if more data needed
	 */
	[[nodiscard]] auto feed(const std::uint8_t *data, std::size_t len,
							std::size_t base_offset = 0) noexcept -> std::optional<result>
	{
		for (std::size_t i = 0; i < len; ++i) {
			std::uint8_t ch = data[i];
			std::size_t pos = base_offset + i;

			switch (state_) {
			case state::body:
				// Looking for start of line terminator
				if (ch == '\r') {
					state_ = state::got_cr;
					eod_start_offset_ = pos;
				}
				else if (ch == '\n') {
					// Bare LF - violation but continue
					state_ = state::got_lf;
					eod_start_offset_ = pos;
					had_violation_ = true;
				}
				break;

			case state::got_cr:
				if (ch == '\n') {
					state_ = state::got_crlf;
				}
				else if (ch == '\r') {
					// \r\r - stay in got_cr, update start
					eod_start_offset_ = pos;
				}
				else if (ch == '.') {
					// \r. without LF - unusual but handle it
					// This is actually a violation
					had_violation_ = true;
					state_ = state::got_crlf_dot;
				}
				else {
					state_ = state::body;
				}
				break;

			case state::got_lf:
				// After bare LF (violation case)
				if (ch == '.') {
					state_ = state::got_crlf_dot;
				}
				else if (ch == '\r') {
					state_ = state::got_cr;
					eod_start_offset_ = pos;
				}
				else if (ch == '\n') {
					// \n\n - double bare LF
					eod_start_offset_ = pos;
				}
				else {
					state_ = state::body;
				}
				break;

			case state::got_crlf:
				// After CRLF (or bare LF), looking for dot
				if (ch == '.') {
					state_ = state::got_crlf_dot;
				}
				else if (ch == '\r') {
					state_ = state::got_cr;
					eod_start_offset_ = pos;
				}
				else if (ch == '\n') {
					// Bare LF after CRLF
					state_ = state::got_lf;
					eod_start_offset_ = pos;
					had_violation_ = true;
				}
				else {
					state_ = state::body;
				}
				break;

			case state::got_crlf_dot:
				// After CRLF. (or LF.), looking for final line terminator
				if (ch == '\r') {
					state_ = state::got_crlf_dot_cr;
				}
				else if (ch == '\n') {
					// CRLF.LF or LF.LF - bare LF termination (violation)
					had_violation_ = true;
					return make_result(pos + 1);
				}
				else {
					// Not EOD, just a dot-stuffed line
					state_ = state::body;
				}
				break;

			case state::got_crlf_dot_cr:
				// After CRLF.\r, looking for final LF
				if (ch == '\n') {
					// Found complete EOD: CRLF.CRLF
					return make_result(pos + 1);
				}
				else if (ch == '\r') {
					// CRLF.\r\r - weird but handle it
					// Stay in this state
				}
				else {
					// CRLF.\r<other> - not EOD
					state_ = state::body;
				}
				break;
			}

			bytes_scanned_++;
		}

		return std::nullopt;
	}

	/**
	 * Convenience overload for char data
	 */
	[[nodiscard]] auto feed(const char *data, std::size_t len,
							std::size_t base_offset = 0) noexcept -> std::optional<result>
	{
		return feed(reinterpret_cast<const std::uint8_t *>(data), len, base_offset);
	}

	/**
	 * Get number of bytes scanned so far
	 */
	[[nodiscard]] auto bytes_scanned() const noexcept -> std::size_t
	{
		return bytes_scanned_;
	}

	/**
	 * Check if any protocol violations were detected
	 */
	[[nodiscard]] auto had_violation() const noexcept -> bool
	{
		return had_violation_;
	}

	/**
	 * Get minimum bytes that must be preserved in buffer for state continuity
	 * This is useful for determining how much data can be safely forwarded
	 * while keeping enough context for the state machine.
	 */
	[[nodiscard]] auto pending_bytes() const noexcept -> std::size_t
	{
		switch (state_) {
		case state::body:
			return 0;
		case state::got_cr:
		case state::got_lf:
			return 1;
		case state::got_crlf:
			return 2;
		case state::got_crlf_dot:
			return 3;
		case state::got_crlf_dot_cr:
			return 4;
		}
		return 0;
	}

	/**
	 * Check if scanner is in the middle of a potential EOD sequence
	 */
	[[nodiscard]] auto in_potential_eod() const noexcept -> bool
	{
		return state_ != state::body;
	}

private:
	enum class state {
		body,          // Normal body content
		got_cr,        // Saw \r
		got_lf,        // Saw \n (bare LF - violation)
		got_crlf,      // Saw \r\n or \n
		got_crlf_dot,  // Saw \r\n. or \n.
		got_crlf_dot_cr// Saw \r\n.\r
	};

	[[nodiscard]] auto make_result(std::size_t end_pos) const noexcept -> result
	{
		result r;
		r.found = true;
		r.eod_start = eod_start_offset_;
		r.eod_length = end_pos - eod_start_offset_;
		r.body_end = eod_start_offset_;
		r.had_violation = had_violation_;
		return r;
	}

	state state_ = state::body;
	std::size_t bytes_scanned_ = 0;
	std::size_t eod_start_offset_ = 0;
	bool had_violation_ = false;
};

/**
 * Simple CRLF scanner for line-by-line reading
 * Tracks state across buffer boundaries
 */
class crlf_scanner {
public:
	struct result {
		bool found = false;
		std::size_t line_end = 0; // Position of \r (or \n for bare LF)
		std::size_t next_line = 0;// Position after \n
		bool bare_lf = false;     // True if bare LF detected
	};

	auto reset() noexcept -> void
	{
		saw_cr_ = false;
		cr_position_ = 0;
	}

	/**
	 * Scan for next CRLF in data
	 * @param data Data to scan
	 * @param len Length of data
	 * @param base_offset Offset in stream
	 * @return result if CRLF found
	 */
	[[nodiscard]] auto scan(const std::uint8_t *data, std::size_t len,
							std::size_t base_offset = 0) noexcept -> std::optional<result>
	{
		for (std::size_t i = 0; i < len; ++i) {
			std::uint8_t ch = data[i];
			std::size_t pos = base_offset + i;

			if (saw_cr_) {
				if (ch == '\n') {
					result r;
					r.found = true;
					r.line_end = cr_position_;
					r.next_line = pos + 1;
					r.bare_lf = false;
					saw_cr_ = false;
					return r;
				}
				else if (ch == '\r') {
					// \r\r - update position
					cr_position_ = pos;
				}
				else {
					// \r without \n - could be old Mac style, treat as line end
					result r;
					r.found = true;
					r.line_end = cr_position_;
					r.next_line = pos;
					r.bare_lf = false;
					saw_cr_ = false;
					return r;
				}
			}
			else {
				if (ch == '\r') {
					saw_cr_ = true;
					cr_position_ = pos;
				}
				else if (ch == '\n') {
					// Bare LF
					result r;
					r.found = true;
					r.line_end = pos;
					r.next_line = pos + 1;
					r.bare_lf = true;
					return r;
				}
			}
		}

		return std::nullopt;
	}

	[[nodiscard]] auto scan(const char *data, std::size_t len,
							std::size_t base_offset = 0) noexcept -> std::optional<result>
	{
		return scan(reinterpret_cast<const std::uint8_t *>(data), len, base_offset);
	}

	/**
	 * Check if we have a pending CR that needs context from next buffer
	 */
	[[nodiscard]] auto has_pending_cr() const noexcept -> bool
	{
		return saw_cr_;
	}

private:
	bool saw_cr_ = false;
	std::size_t cr_position_ = 0;
};

/**
 * NUL byte scanner - detects NUL characters which are protocol violations
 */
class nul_scanner {
public:
	struct result {
		bool found = false;
		std::size_t position = 0;
	};

	[[nodiscard]] static auto scan(const std::uint8_t *data, std::size_t len,
								   std::size_t base_offset = 0) noexcept -> std::optional<result>
	{
		for (std::size_t i = 0; i < len; ++i) {
			if (data[i] == '\0') {
				return result{true, base_offset + i};
			}
		}
		return std::nullopt;
	}

	[[nodiscard]] static auto scan(const char *data, std::size_t len,
								   std::size_t base_offset = 0) noexcept -> std::optional<result>
	{
		return scan(reinterpret_cast<const std::uint8_t *>(data), len, base_offset);
	}
};

}// namespace rspamd::smtp

#endif// RSPAMD_EOD_SCANNER_HXX
