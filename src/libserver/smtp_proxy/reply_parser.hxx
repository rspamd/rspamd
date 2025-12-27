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

#ifndef RSPAMD_REPLY_PARSER_HXX
#define RSPAMD_REPLY_PARSER_HXX

#pragma once

#include "config.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <algorithm>
#include <cctype>

namespace rspamd::smtp {

/**
 * Parsed SMTP reply line
 */
struct reply_line {
	int code = 0;         // 3-digit reply code
	bool is_final = false;// True if this is the last line (code followed by space)
	std::string text;     // Text after code (without leading space/dash)
	std::string raw_line; // Original line including CRLF (for forwarding)

	/**
	 * Check if this is a successful response (2xx)
	 */
	[[nodiscard]] auto is_success() const noexcept -> bool
	{
		return code >= 200 && code < 300;
	}

	/**
	 * Check if this is a temporary failure (4xx)
	 */
	[[nodiscard]] auto is_temp_failure() const noexcept -> bool
	{
		return code >= 400 && code < 500;
	}

	/**
	 * Check if this is a permanent failure (5xx)
	 */
	[[nodiscard]] auto is_perm_failure() const noexcept -> bool
	{
		return code >= 500 && code < 600;
	}

	/**
	 * Check if this is a positive preliminary (1xx)
	 */
	[[nodiscard]] auto is_preliminary() const noexcept -> bool
	{
		return code >= 100 && code < 200;
	}

	/**
	 * Check if this is a positive intermediate (3xx)
	 */
	[[nodiscard]] auto is_intermediate() const noexcept -> bool
	{
		return code >= 300 && code < 400;
	}
};

/**
 * Complete multiline SMTP reply
 */
struct smtp_reply {
	int code = 0;                 // Reply code (from first/final line)
	std::vector<reply_line> lines;// All lines of the reply
	std::string enhanced_status;  // Enhanced status code if present (e.g., "2.1.0")

	/**
	 * Get all raw lines concatenated (for forwarding)
	 */
	[[nodiscard]] auto get_raw() const -> std::string
	{
		std::string raw;
		for (const auto &line: lines) {
			raw += line.raw_line;
		}
		return raw;
	}

	/**
	 * Check if reply is complete (has final line)
	 */
	[[nodiscard]] auto is_complete() const noexcept -> bool
	{
		return !lines.empty() && lines.back().is_final;
	}

	/**
	 * Get all text lines combined
	 */
	[[nodiscard]] auto get_text() const -> std::string
	{
		std::string text;
		for (const auto &line: lines) {
			if (!text.empty()) {
				text += "\n";
			}
			text += line.text;
		}
		return text;
	}

	// Delegate to reply_line methods using the final code
	[[nodiscard]] auto is_success() const noexcept -> bool
	{
		return code >= 200 && code < 300;
	}

	[[nodiscard]] auto is_temp_failure() const noexcept -> bool
	{
		return code >= 400 && code < 500;
	}

	[[nodiscard]] auto is_perm_failure() const noexcept -> bool
	{
		return code >= 500 && code < 600;
	}
};

/**
 * SMTP EHLO capability
 */
struct ehlo_capability {
	std::string name;               // Capability name (uppercase)
	std::vector<std::string> params;// Parameters (e.g., SIZE limit, AUTH mechanisms)
};

/**
 * Parsed EHLO response
 */
struct ehlo_response {
	std::string greeting;// First line greeting
	std::vector<ehlo_capability> capabilities;
	smtp_reply raw_reply;// Original reply for forwarding

	/**
	 * Check if a capability is present
	 */
	[[nodiscard]] auto has_capability(std::string_view name) const noexcept -> bool
	{
		std::string upper;
		upper.reserve(name.size());
		for (char c: name) {
			upper.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
		}

		return std::any_of(capabilities.begin(), capabilities.end(),
						   [&upper](const ehlo_capability &cap) {
							   return cap.name == upper;
						   });
	}

	/**
	 * Get capability parameters
	 */
	[[nodiscard]] auto get_capability(std::string_view name) const noexcept
		-> std::optional<std::reference_wrapper<const ehlo_capability>>
	{
		std::string upper;
		upper.reserve(name.size());
		for (char c: name) {
			upper.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
		}

		auto it = std::find_if(capabilities.begin(), capabilities.end(),
							   [&upper](const ehlo_capability &cap) {
								   return cap.name == upper;
							   });
		if (it != capabilities.end()) {
			return std::cref(*it);
		}
		return std::nullopt;
	}

	/**
	 * Get SIZE limit if advertised
	 */
	[[nodiscard]] auto get_size_limit() const noexcept -> std::optional<std::size_t>
	{
		auto cap = get_capability("SIZE");
		if (cap && !cap->get().params.empty()) {
			try {
				return std::stoull(cap->get().params[0]);
			} catch (...) {
				return std::nullopt;
			}
		}
		return std::nullopt;
	}
};

/**
 * SMTP reply parser
 *
 * Parses SMTP responses including:
 * - Single line responses (code SP text CRLF)
 * - Multiline responses (code - text CRLF ... code SP text CRLF)
 * - EHLO capability parsing
 */
class reply_parser {
public:
	reply_parser() = default;

	/**
	 * Parse a single reply line (without CRLF terminator)
	 *
	 * @param line Reply line to parse
	 * @param raw_line Original line including CRLF (for forwarding)
	 * @return Parsed reply_line or nullopt if invalid
	 */
	[[nodiscard]] auto parse_line(std::string_view line, std::string_view raw_line = {}) const
		-> std::optional<reply_line>
	{
		if (line.size() < 3) {
			return std::nullopt;
		}

		reply_line result;
		result.raw_line = raw_line.empty() ? std::string(line) + "\r\n" : std::string(raw_line);

		// Parse 3-digit code
		if (!std::isdigit(static_cast<unsigned char>(line[0])) ||
			!std::isdigit(static_cast<unsigned char>(line[1])) ||
			!std::isdigit(static_cast<unsigned char>(line[2]))) {
			return std::nullopt;
		}

		result.code = (line[0] - '0') * 100 + (line[1] - '0') * 10 + (line[2] - '0');

		// Check for continuation or final line
		if (line.size() == 3) {
			// Just the code
			result.is_final = true;
			return result;
		}

		char sep = line[3];
		if (sep == ' ') {
			result.is_final = true;
		}
		else if (sep == '-') {
			result.is_final = false;
		}
		else {
			return std::nullopt;
		}

		// Extract text
		if (line.size() > 4) {
			result.text = std::string(line.substr(4));
		}

		return result;
	}

	/**
	 * Accumulate lines into a complete reply
	 *
	 * @param reply Reply being accumulated
	 * @param line Line to add
	 * @return true if reply is now complete
	 */
	auto accumulate(smtp_reply &reply, const reply_line &line) const -> bool
	{
		reply.lines.push_back(line);

		if (line.is_final) {
			reply.code = line.code;

			// Try to extract enhanced status code from first line text
			if (!reply.lines.empty()) {
				const auto &first_text = reply.lines[0].text;
				if (first_text.size() >= 5 && std::isdigit(static_cast<unsigned char>(first_text[0]))) {
					// Look for enhanced status code pattern: x.y.z
					auto dot1 = first_text.find('.');
					if (dot1 != std::string::npos && dot1 < 2) {
						auto dot2 = first_text.find('.', dot1 + 1);
						if (dot2 != std::string::npos) {
							auto end = first_text.find(' ', dot2);
							if (end == std::string::npos) {
								end = first_text.size();
							}
							reply.enhanced_status = first_text.substr(0, end);
						}
					}
				}
			}

			return true;
		}

		// Validate that multiline responses have consistent code
		if (reply.lines.size() > 1) {
			if (reply.lines.front().code != line.code) {
				// Inconsistent code - this is a protocol error
				// We'll accept it but note that it's weird
			}
		}

		return false;
	}

	/**
	 * Parse a complete EHLO response
	 *
	 * @param reply Complete SMTP reply from EHLO command
	 * @return Parsed EHLO response with capabilities
	 */
	[[nodiscard]] auto parse_ehlo_response(const smtp_reply &reply) const -> ehlo_response
	{
		ehlo_response result;
		result.raw_reply = reply;

		if (reply.lines.empty()) {
			return result;
		}

		// First line is the greeting
		result.greeting = reply.lines[0].text;

		// Subsequent lines are capabilities
		for (size_t i = 1; i < reply.lines.size(); ++i) {
			const auto &text = reply.lines[i].text;
			if (text.empty()) {
				continue;
			}

			ehlo_capability cap;

			// Split on first space
			auto space = text.find(' ');
			std::string_view name_sv;
			std::string_view params_sv;

			if (space != std::string::npos) {
				name_sv = std::string_view(text).substr(0, space);
				params_sv = std::string_view(text).substr(space + 1);
			}
			else {
				name_sv = text;
			}

			// Convert name to uppercase
			cap.name.reserve(name_sv.size());
			for (char c: name_sv) {
				cap.name.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
			}

			// Parse parameters (space-separated)
			if (!params_sv.empty()) {
				std::string current_param;
				for (char c: params_sv) {
					if (c == ' ') {
						if (!current_param.empty()) {
							cap.params.push_back(std::move(current_param));
							current_param.clear();
						}
					}
					else {
						current_param.push_back(c);
					}
				}
				if (!current_param.empty()) {
					cap.params.push_back(std::move(current_param));
				}
			}

			result.capabilities.push_back(std::move(cap));
		}

		return result;
	}

	/**
	 * Build a rewritten EHLO response with filtered capabilities
	 *
	 * @param original Original EHLO response
	 * @param caps_to_keep Set of capability names to keep (uppercase)
	 * @param caps_to_remove Set of capability names to remove (uppercase)
	 * @param caps_to_add Additional capabilities to add
	 * @return Rewritten response as raw SMTP reply
	 */
	[[nodiscard]] auto rewrite_ehlo_response(
		const ehlo_response &original,
		const std::vector<std::string> &caps_to_keep,
		const std::vector<std::string> &caps_to_remove,
		const std::vector<ehlo_capability> &caps_to_add,
		std::optional<std::size_t> size_limit = std::nullopt) const -> std::string
	{
		std::string result;
		const int code = original.raw_reply.code;

		// Helper to check if cap should be included
		auto should_include = [&](const std::string &name) -> bool {
			// Check removal list first
			for (const auto &r: caps_to_remove) {
				if (r == name) {
					return false;
				}
			}
			// If keep list is empty, keep all (except removed)
			if (caps_to_keep.empty()) {
				return true;
			}
			// Check keep list
			for (const auto &k: caps_to_keep) {
				if (k == name) {
					return true;
				}
			}
			return false;
		};

		// Build filtered capability list
		std::vector<std::string> output_lines;

		// First line is always the greeting
		output_lines.push_back(original.greeting);

		// Add filtered capabilities
		for (const auto &cap: original.capabilities) {
			if (!should_include(cap.name)) {
				continue;
			}

			std::string line = cap.name;

			// Special handling for SIZE
			if (cap.name == "SIZE" && size_limit) {
				line += " " + std::to_string(*size_limit);
			}
			else if (!cap.params.empty()) {
				for (const auto &p: cap.params) {
					line += " " + p;
				}
			}

			output_lines.push_back(std::move(line));
		}

		// Add new capabilities
		for (const auto &cap: caps_to_add) {
			std::string line = cap.name;
			for (const auto &p: cap.params) {
				line += " " + p;
			}
			output_lines.push_back(std::move(line));
		}

		// Build output
		for (size_t i = 0; i < output_lines.size(); ++i) {
			char sep = (i == output_lines.size() - 1) ? ' ' : '-';
			result += std::to_string(code) + sep + output_lines[i] + "\r\n";
		}

		return result;
	}

	/**
	 * Create a simple single-line reply
	 */
	[[nodiscard]] static auto make_reply(int code, std::string_view text) -> std::string
	{
		return std::to_string(code) + " " + std::string(text) + "\r\n";
	}

	/**
	 * Create a reply with enhanced status code
	 */
	[[nodiscard]] static auto make_reply(int code, std::string_view enhanced,
										 std::string_view text) -> std::string
	{
		return std::to_string(code) + " " + std::string(enhanced) + " " +
			   std::string(text) + "\r\n";
	}

	/**
	 * Get standard reply for common scenarios
	 */
	[[nodiscard]] static auto get_standard_reply(int code) -> const char *
	{
		switch (code) {
		case 220:
			return "220 Service ready\r\n";
		case 221:
			return "221 2.0.0 Bye\r\n";
		case 250:
			return "250 2.0.0 OK\r\n";
		case 354:
			return "354 Start mail input; end with <CRLF>.<CRLF>\r\n";
		case 421:
			return "421 4.7.0 Service not available, closing transmission channel\r\n";
		case 450:
			return "450 4.7.1 Requested mail action not taken: mailbox unavailable\r\n";
		case 451:
			return "451 4.3.0 Requested action aborted: local error in processing\r\n";
		case 500:
			return "500 5.5.1 Syntax error, command unrecognized\r\n";
		case 501:
			return "501 5.5.4 Syntax error in parameters or arguments\r\n";
		case 502:
			return "502 5.5.1 Command not implemented\r\n";
		case 503:
			return "503 5.5.1 Bad sequence of commands\r\n";
		case 550:
			return "550 5.7.1 Requested action not taken: mailbox unavailable\r\n";
		case 554:
			return "554 5.7.1 Transaction failed\r\n";
		default:
			return nullptr;
		}
	}
};

}// namespace rspamd::smtp

#endif// RSPAMD_REPLY_PARSER_HXX
