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

#ifndef RSPAMD_LINE_READER_HXX
#define RSPAMD_LINE_READER_HXX

#pragma once

#include "config.h"
#include "ring_buffer.hxx"
#include "eod_scanner.hxx"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <optional>
#include <variant>

namespace rspamd::smtp {

/**
 * SMTP protocol violations that can be detected during line reading
 */
enum class line_violation {
	none,
	bare_lf,      // LF without preceding CR
	line_too_long,// Line exceeds max_line_length
	nul_in_line,  // NUL character in command line
	missing_crlf  // Line doesn't end with CRLF (truncated)
};

/**
 * Result of trying to read a line from the buffer
 */
struct line_result {
	enum class status {
		ok,        // Complete line available
		incomplete,// Need more data
		violation  // Protocol violation detected
	};

	status state = status::incomplete;
	line_violation violation_type = line_violation::none;
	std::string line;              // Line content without CRLF
	std::string raw_line;          // Original line including terminator (for forwarding)
	std::size_t bytes_consumed = 0;// Bytes consumed from buffer
};

/**
 * Extracts CRLF-terminated lines from a ring buffer.
 */
class line_reader {
public:
	static constexpr std::size_t default_max_line_length = 4096;

	explicit line_reader(std::size_t max_line_length = default_max_line_length)
		: max_line_length_(max_line_length)
	{
	}

	/**
	 * Set maximum line length
	 */
	auto set_max_line_length(std::size_t len) noexcept -> void
	{
		max_line_length_ = len;
	}

	/**
	 * Get maximum line length
	 */
	[[nodiscard]] auto max_line_length() const noexcept -> std::size_t
	{
		return max_line_length_;
	}

	/**
	 * Try to extract a complete line from the ring buffer
	 *
	 * @tparam Capacity Ring buffer capacity
	 * @param buffer Reference to ring buffer
	 * @return line_result with status and data
	 */
	template<std::size_t Capacity>
	[[nodiscard]] auto try_read_line(io::ring_buffer<Capacity> &buffer) -> line_result
	{
		line_result result;

		if (buffer.empty()) {
			result.state = line_result::status::incomplete;
			return result;
		}

		// Get buffer data for scanning - we need to handle wrap-around
		auto [ptr1, len1, ptr2, len2] = buffer.get_read_regions();

		// Scan both regions of the ring buffer
		std::optional<crlf_scanner::result> crlf_result;
		std::optional<std::size_t> nul_pos;
		std::optional<std::size_t> bare_lf_pos;

		// Reset scanner for fresh scan
		crlf_scanner_.reset();

		// Scan first region
		if (len1 > 0) {
			// Check for NUL
			auto nul_scan = nul_scanner::scan(ptr1, len1, 0);
			if (nul_scan) {
				nul_pos = nul_scan->position;
			}

			// Scan for CRLF
			crlf_result = crlf_scanner_.scan(ptr1, len1, 0);
			if (crlf_result && crlf_result->bare_lf) {
				bare_lf_pos = crlf_result->line_end;
			}
		}

		// Continue scanning second region if needed and no CRLF found yet
		if (!crlf_result && len2 > 0) {
			// Check for NUL in second region
			if (!nul_pos) {
				auto nul_scan = nul_scanner::scan(ptr2, len2, len1);
				if (nul_scan) {
					nul_pos = nul_scan->position;
				}
			}

			// Continue CRLF scan
			crlf_result = crlf_scanner_.scan(ptr2, len2, len1);
			if (crlf_result && crlf_result->bare_lf && !bare_lf_pos) {
				bare_lf_pos = crlf_result->line_end;
			}
		}

		// Check for NUL violation before CRLF
		if (nul_pos) {
			if (!crlf_result || *nul_pos < crlf_result->line_end) {
				result.state = line_result::status::violation;
				result.violation_type = line_violation::nul_in_line;
				return result;
			}
		}

		// Check for bare LF violation
		if (bare_lf_pos) {
			result.state = line_result::status::violation;
			result.violation_type = line_violation::bare_lf;
			return result;
		}

		if (!crlf_result) {
			// No complete line yet - check length
			if (buffer.size() > max_line_length_) {
				result.state = line_result::status::violation;
				result.violation_type = line_violation::line_too_long;
				return result;
			}
			result.state = line_result::status::incomplete;
			return result;
		}

		// Check if line is too long
		if (crlf_result->line_end > max_line_length_) {
			result.state = line_result::status::violation;
			result.violation_type = line_violation::line_too_long;
			return result;
		}

		// Extract the line
		std::size_t line_len = crlf_result->line_end;
		std::size_t total_len = crlf_result->next_line;

		// Read line content (without CRLF)
		result.line.resize(line_len);
		(void) buffer.peek(result.line.data(), line_len);

		// Read raw line (with CRLF) for forwarding
		result.raw_line.resize(total_len);
		(void) buffer.peek(result.raw_line.data(), total_len);

		// Consume the line from buffer
		buffer.consume(total_len);

		result.state = line_result::status::ok;
		result.bytes_consumed = total_len;
		return result;
	}

	/**
	 * Read line with timeout tracking (for use with async I/O)
	 * This version accumulates partial data across calls
	 */
	template<std::size_t Capacity>
	[[nodiscard]] auto read_line_incremental(io::ring_buffer<Capacity> &buffer) -> line_result
	{
		// For incremental reading, we just delegate to try_read_line
		// State management is handled by the caller
		return try_read_line(buffer);
	}

	/**
	 * Check if a partial line in the buffer would exceed max length
	 */
	template<std::size_t Capacity>
	[[nodiscard]] auto check_line_length(const io::ring_buffer<Capacity> &buffer) const noexcept -> bool
	{
		return buffer.size() <= max_line_length_;
	}

	/**
	 * Get a descriptive string for a violation type
	 */
	[[nodiscard]] static auto violation_to_string(line_violation v) noexcept -> const char *
	{
		switch (v) {
		case line_violation::none:
			return "none";
		case line_violation::bare_lf:
			return "bare LF without CR";
		case line_violation::line_too_long:
			return "line too long";
		case line_violation::nul_in_line:
			return "NUL character in line";
		case line_violation::missing_crlf:
			return "missing CRLF terminator";
		}
		return "unknown violation";
	}

private:
	std::size_t max_line_length_;
	crlf_scanner crlf_scanner_;
};

}// namespace rspamd::smtp

#endif// RSPAMD_LINE_READER_HXX
