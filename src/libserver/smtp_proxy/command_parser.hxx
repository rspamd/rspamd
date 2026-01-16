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

#ifndef RSPAMD_COMMAND_PARSER_HXX
#define RSPAMD_COMMAND_PARSER_HXX

#pragma once

#include "config.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <optional>
#include <vector>
#include <algorithm>
#include <cctype>

#include "contrib/ankerl/unordered_dense.h"

namespace rspamd::smtp {

/**
 * SMTP command types
 */
enum class command_type {
	unknown,
	ehlo,
	helo,
	mail_from,
	rcpt_to,
	data,
	rset,
	noop,
	quit,
	starttls,
	vrfy,
	expn,
	help,
	bdat,// CHUNKING extension - not supported in v1
	auth // AUTH extension - not supported in v1
};

/**
 * ESMTP parameter parsed from MAIL FROM or RCPT TO
 */
struct esmtp_param {
	std::string name;
	std::optional<std::string> value;
};

/**
 * Parsed SMTP command
 */
struct parsed_command {
	command_type type = command_type::unknown;
	std::string verb;               // Original command verb (e.g., "EHLO", "MAIL")
	std::string argument;           // Primary argument (domain for EHLO, path for MAIL/RCPT)
	std::vector<esmtp_param> params;// ESMTP parameters
	std::string raw_line;           // Original line for transparent forwarding

	/**
	 * Check if command has a specific ESMTP parameter
	 */
	[[nodiscard]] auto has_param(std::string_view name) const noexcept -> bool
	{
		return std::any_of(params.begin(), params.end(),
						   [name](const esmtp_param &p) {
							   return case_insensitive_equal(p.name, name);
						   });
	}

	/**
	 * Get value of an ESMTP parameter
	 */
	[[nodiscard]] auto get_param(std::string_view name) const noexcept -> std::optional<std::string_view>
	{
		auto it = std::find_if(params.begin(), params.end(),
							   [name](const esmtp_param &p) {
								   return case_insensitive_equal(p.name, name);
							   });
		if (it != params.end() && it->value) {
			return *it->value;
		}
		return std::nullopt;
	}

private:
	[[nodiscard]] static auto case_insensitive_equal(std::string_view a, std::string_view b) noexcept -> bool
	{
		if (a.size() != b.size()) {
			return false;
		}
		return std::equal(a.begin(), a.end(), b.begin(),
						  [](char c1, char c2) {
							  return std::toupper(static_cast<unsigned char>(c1)) ==
									 std::toupper(static_cast<unsigned char>(c2));
						  });
	}
};

/**
 * SMTP command parser
 *
 * Parses SMTP commands including:
 * - EHLO/HELO with domain argument
 * - MAIL FROM with path and ESMTP parameters
 * - RCPT TO with path and ESMTP parameters
 * - DATA, RSET, NOOP, QUIT, STARTTLS
 *
 * Retains raw line for transparent forwarding to backend.
 */
class command_parser {
public:
	command_parser() = default;

	/**
	 * Parse a command line (without CRLF terminator)
	 *
	 * @param line Command line to parse
	 * @param raw_line Original line including CRLF (for forwarding)
	 * @return parsed_command structure
	 */
	[[nodiscard]] auto parse(std::string_view line, std::string_view raw_line = {}) const -> parsed_command
	{
		parsed_command cmd;
		cmd.raw_line = raw_line.empty() ? std::string(line) + "\r\n" : std::string(raw_line);

		if (line.empty()) {
			return cmd;
		}

		// Extract verb (first word)
		auto space_pos = line.find(' ');
		std::string_view verb_sv;
		std::string_view rest;

		if (space_pos == std::string_view::npos) {
			verb_sv = line;
		}
		else {
			verb_sv = line.substr(0, space_pos);
			rest = line.substr(space_pos + 1);
			// Trim leading whitespace from rest
			while (!rest.empty() && std::isspace(static_cast<unsigned char>(rest.front()))) {
				rest.remove_prefix(1);
			}
		}

		// Store original verb
		cmd.verb.assign(verb_sv.begin(), verb_sv.end());

		// Identify command type
		cmd.type = identify_command(verb_sv);

		// Parse arguments based on command type
		switch (cmd.type) {
		case command_type::ehlo:
		case command_type::helo:
			cmd.argument = std::string(rest);
			break;

		case command_type::mail_from:
			parse_mail_from(rest, cmd);
			break;

		case command_type::rcpt_to:
			parse_rcpt_to(rest, cmd);
			break;

		case command_type::bdat:
			parse_bdat(rest, cmd);
			break;

		case command_type::auth:
			cmd.argument = std::string(rest);
			break;

		case command_type::vrfy:
		case command_type::expn:
		case command_type::help:
			cmd.argument = std::string(rest);
			break;

		case command_type::data:
		case command_type::rset:
		case command_type::noop:
		case command_type::quit:
		case command_type::starttls:
		case command_type::unknown:
			// These commands have no arguments or we don't parse them
			if (!rest.empty()) {
				cmd.argument = std::string(rest);
			}
			break;
		}

		return cmd;
	}

	/**
	 * Check if a command type is valid for pipelining
	 * (can be sent before receiving response to previous command)
	 */
	[[nodiscard]] static auto is_pipelineable(command_type type) noexcept -> bool
	{
		switch (type) {
		case command_type::mail_from:
		case command_type::rcpt_to:
		case command_type::rset:
		case command_type::noop:
			return true;
		default:
			return false;
		}
	}

	/**
	 * Check if a command requires waiting for all pending responses
	 * before being sent (synchronization point)
	 */
	[[nodiscard]] static auto is_sync_command(command_type type) noexcept -> bool
	{
		switch (type) {
		case command_type::ehlo:
		case command_type::helo:
		case command_type::data:
		case command_type::starttls:
		case command_type::quit:
		case command_type::bdat:
			return true;
		default:
			return false;
		}
	}

	/**
	 * Get string representation of command type
	 */
	[[nodiscard]] static auto command_type_to_string(command_type type) noexcept -> const char *
	{
		switch (type) {
		case command_type::unknown:
			return "UNKNOWN";
		case command_type::ehlo:
			return "EHLO";
		case command_type::helo:
			return "HELO";
		case command_type::mail_from:
			return "MAIL";
		case command_type::rcpt_to:
			return "RCPT";
		case command_type::data:
			return "DATA";
		case command_type::rset:
			return "RSET";
		case command_type::noop:
			return "NOOP";
		case command_type::quit:
			return "QUIT";
		case command_type::starttls:
			return "STARTTLS";
		case command_type::vrfy:
			return "VRFY";
		case command_type::expn:
			return "EXPN";
		case command_type::help:
			return "HELP";
		case command_type::bdat:
			return "BDAT";
		case command_type::auth:
			return "AUTH";
		}
		return "UNKNOWN";
	}

private:
	/**
	 * Identify command type from verb
	 */
	[[nodiscard]] auto identify_command(std::string_view verb) const noexcept -> command_type
	{
		// Convert to uppercase for comparison
		std::string upper;
		upper.reserve(verb.size());
		for (char c: verb) {
			upper.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
		}

		if (upper == "EHLO") return command_type::ehlo;
		if (upper == "HELO") return command_type::helo;
		if (upper == "MAIL") return command_type::mail_from;
		if (upper == "RCPT") return command_type::rcpt_to;
		if (upper == "DATA") return command_type::data;
		if (upper == "RSET") return command_type::rset;
		if (upper == "NOOP") return command_type::noop;
		if (upper == "QUIT") return command_type::quit;
		if (upper == "STARTTLS") return command_type::starttls;
		if (upper == "VRFY") return command_type::vrfy;
		if (upper == "EXPN") return command_type::expn;
		if (upper == "HELP") return command_type::help;
		if (upper == "BDAT") return command_type::bdat;
		if (upper == "AUTH") return command_type::auth;

		return command_type::unknown;
	}

	/**
	 * Parse MAIL FROM:<path> [params]
	 */
	auto parse_mail_from(std::string_view rest, parsed_command &cmd) const -> void
	{
		// Expect "FROM:" prefix (case-insensitive)
		if (rest.size() < 5) {
			return;
		}

		std::string prefix;
		prefix.reserve(5);
		for (size_t i = 0; i < 5 && i < rest.size(); ++i) {
			prefix.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(rest[i]))));
		}

		if (prefix != "FROM:") {
			return;
		}

		rest.remove_prefix(5);

		// Skip optional whitespace after colon
		while (!rest.empty() && std::isspace(static_cast<unsigned char>(rest.front()))) {
			rest.remove_prefix(1);
		}

		// Parse path and parameters
		parse_path_and_params(rest, cmd);
	}

	/**
	 * Parse RCPT TO:<path> [params]
	 */
	auto parse_rcpt_to(std::string_view rest, parsed_command &cmd) const -> void
	{
		// Expect "TO:" prefix (case-insensitive)
		if (rest.size() < 3) {
			return;
		}

		std::string prefix;
		prefix.reserve(3);
		for (size_t i = 0; i < 3 && i < rest.size(); ++i) {
			prefix.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(rest[i]))));
		}

		if (prefix != "TO:") {
			return;
		}

		rest.remove_prefix(3);

		// Skip optional whitespace after colon
		while (!rest.empty() && std::isspace(static_cast<unsigned char>(rest.front()))) {
			rest.remove_prefix(1);
		}

		// Parse path and parameters
		parse_path_and_params(rest, cmd);
	}

	/**
	 * Parse <path> and ESMTP parameters
	 */
	auto parse_path_and_params(std::string_view rest, parsed_command &cmd) const -> void
	{
		if (rest.empty()) {
			return;
		}

		// Handle angle-bracketed path
		if (rest.front() == '<') {
			auto close = rest.find('>');
			if (close != std::string_view::npos) {
				cmd.argument = std::string(rest.substr(0, close + 1));
				rest.remove_prefix(close + 1);
			}
			else {
				// Malformed - take everything
				cmd.argument = std::string(rest);
				return;
			}
		}
		else {
			// Path without angle brackets - take until whitespace
			auto space = rest.find(' ');
			if (space != std::string_view::npos) {
				cmd.argument = std::string(rest.substr(0, space));
				rest.remove_prefix(space);
			}
			else {
				cmd.argument = std::string(rest);
				return;
			}
		}

		// Parse ESMTP parameters (space-separated KEY=VALUE or KEY)
		while (!rest.empty()) {
			// Skip whitespace
			while (!rest.empty() && std::isspace(static_cast<unsigned char>(rest.front()))) {
				rest.remove_prefix(1);
			}

			if (rest.empty()) {
				break;
			}

			// Find end of parameter
			auto space = rest.find(' ');
			std::string_view param_str;
			if (space != std::string_view::npos) {
				param_str = rest.substr(0, space);
				rest.remove_prefix(space);
			}
			else {
				param_str = rest;
				rest = {};
			}

			// Parse KEY=VALUE or KEY
			esmtp_param param;
			auto eq = param_str.find('=');
			if (eq != std::string_view::npos) {
				param.name = std::string(param_str.substr(0, eq));
				param.value = std::string(param_str.substr(eq + 1));
			}
			else {
				param.name = std::string(param_str);
			}

			if (!param.name.empty()) {
				cmd.params.push_back(std::move(param));
			}
		}
	}

	/**
	 * Parse BDAT <size> [LAST]
	 */
	auto parse_bdat(std::string_view rest, parsed_command &cmd) const -> void
	{
		// Extract size
		auto space = rest.find(' ');
		if (space != std::string_view::npos) {
			cmd.argument = std::string(rest.substr(0, space));
			rest.remove_prefix(space);

			// Skip whitespace and check for LAST
			while (!rest.empty() && std::isspace(static_cast<unsigned char>(rest.front()))) {
				rest.remove_prefix(1);
			}

			if (!rest.empty()) {
				std::string upper;
				upper.reserve(rest.size());
				for (char c: rest) {
					upper.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
				}
				if (upper == "LAST") {
					cmd.params.push_back({"LAST", std::nullopt});
				}
			}
		}
		else {
			cmd.argument = std::string(rest);
		}
	}
};

}// namespace rspamd::smtp

#endif// RSPAMD_COMMAND_PARSER_HXX
