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
 * String, address and message helpers of the DKIM2 module: they know nothing
 * about DKIM2 header fields and have no task/DNS dependencies.
 *
 * Reference: draft-ietf-dkim-dkim2-spec-09
 */

#ifndef RSPAMD_DKIM2_UTIL_HXX
#define RSPAMD_DKIM2_UTIL_HXX
#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <cstdint>

#include "contrib/expected/expected.hpp"

namespace rspamd::dkim2 {

/* WSP as in the specification: SP and HTAB, nothing else */
constexpr auto is_wsp(char c) -> bool
{
	return c == ' ' || c == '\t';
}

/* Remove WSP from both ends */
auto trim(std::string_view in) -> std::string_view;

/* Remove all WSP */
auto strip_wsp(std::string_view in) -> std::string;

/* ASCII lowercase copy */
auto lc_string(std::string_view in) -> std::string;

/* ASCII case-insensitive comparison */
auto eq_icase(std::string_view a, std::string_view b) -> bool;
auto starts_with_icase(std::string_view in, std::string_view prefix) -> bool;

/* 1*DIGIT that fits into 64 bits */
auto parse_uint(std::string_view in) -> std::optional<std::uint64_t>;

/* textstring without the surrounding FWS: 1*(ALPHA / DIGIT / "-" / "_") */
auto is_textstring(std::string_view in) -> bool;

/**
 * Decode a base64string (Section 2.14). The decoder is strict on purpose: a
 * lenient one skips stray characters, so the same octets get many spellings,
 * and what verifies here would not verify elsewhere. The alphabet is the
 * standard one, FWS is ignored if allowed, the padding is mandatory and the
 * unused bits MUST be zero.
 */
auto b64_decode(std::string_view in, bool allow_fws = true) -> std::optional<std::string>;

/* Encode a base64string: the standard alphabet, padded, on one line */
auto b64_encode(std::string_view in) -> std::string;

/* Split on a single character, keeping empty elements */
template<typename Func>
void split_keep_empty(std::string_view in, char delim, Func &&func)
{
	std::size_t first = 0;

	for (;;) {
		auto second = in.find(delim, first);

		func(in.substr(first, second == std::string_view::npos ? second : second - first));

		if (second == std::string_view::npos) {
			break;
		}

		first = second + 1;
	}
}

/**
 * Check if a string is a domain name usable in a DNS request: dot separated
 * non-empty labels of letters, digits, `-` and `_`
 */
auto valid_domain(std::string_view in) -> bool;

/* A header field of a message as it is on the wire */
struct raw_header_t {
	std::string_view name;  /* without the WSP before the colon */
	std::string_view value; /* unfolded; points to `unfolded` if it was folded */
	std::string unfolded;
};

/* More header fields than that are not accepted: the limit of the MIME parser */
constexpr std::size_t DKIM2_MAX_HEADER_FIELDS = 100000;

/**
 * Split a header block into fields exactly as RFC 5322 defines them: nothing
 * is skipped, repaired or guessed, because every octet that is not covered by
 * a hash can be changed in transit. A line ends with LF or CRLF, a line that
 * starts with WSP continues the previous field, and unfolding removes only
 * the line terminator. Scanning stops at the empty line that ends the header.
 * Fails on what is not a header field and on too many fields.
 */
auto scan_headers(std::string_view block)
	-> tl::expected<std::vector<raw_header_t>, std::string>;

/**
 * Check that a From value can hold just one mailbox: one `@` and no list or
 * group separators outside of quoted strings and comments. It guards the
 * tolerant address parser, which makes a single address of several ones.
 */
auto from_is_single_mailbox(std::string_view value) -> bool;

/**
 * The domain of the only mailbox of a From value as it is written there,
 * nullopt if the value does not hold just one mailbox
 */
auto from_mailbox_domain(std::string_view value) -> std::optional<std::string_view>;

/**
 * Header fields that are not signed (Section 4), as well as Message-Instance
 * and DKIM2-Signature, that do not participate in the header hash
 */
auto is_unsigned_header(std::string_view name) -> bool;

/**
 * Split a message body into lines (line terminators, LF or CRLF, are not
 * included); a trailing terminator does not produce an extra empty line
 */
auto split_body_lines(std::string_view body, std::size_t max_lines)
	-> tl::expected<std::vector<std::string_view>, std::string>;

/**
 * Relaxed domain match (Section 7.2): strip the leftmost labels from `param1`
 * until it equals `param2` (case-insensitively) or no labels remain. The
 * match is asymmetric. A domain literal never matches.
 */
auto relaxed_domain_match(std::string_view param1, std::string_view param2) -> bool;

/**
 * Compare two SMTP paths: angle brackets are stripped, the local part is
 * compared case-sensitively and the domain case-insensitively. The null
 * reverse-path `<>` only matches an empty address.
 */
auto smtp_addr_equal(std::string_view a, std::string_view b) -> bool;

/**
 * Comparison key of an SMTP path: no angle brackets, lowercase domain
 */
auto smtp_addr_key(std::string_view addr) -> std::string;

/**
 * Extract the domain part of an SMTP path (`<local@domain>` or `local@domain`),
 * empty view if there is none
 */
auto smtp_addr_domain(std::string_view addr) -> std::string_view;

/**
 * Check if a decoded mf= value is the null reverse-path
 */
auto smtp_addr_is_null(std::string_view addr) -> bool;

/**
 * Body canonicalization (Section 6.1): all trailing empty lines are ignored
 * and a single final CRLF is appended. A line ends with LF or CRLF, both are
 * emitted as CRLF, since a message may reach us with its line endings
 * converted; a CR that is not followed by LF is an octet of the line as any
 * other. Yields chunks via `out(const char *, std::size_t)`.
 */
template<typename Func>
void body_canon_foreach(std::string_view body, Func &&out)
{
	/* Strip all trailing line terminators: this removes trailing empty lines
	 * together with the line terminator of the last non-empty line, which is
	 * then restored as the single final CRLF */
	auto end = body.size();
	while (end > 0 && body[end - 1] == '\n') {
		end--;
		if (end > 0 && body[end - 1] == '\r') {
			end--;
		}
	}

	body = body.substr(0, end);

	while (!body.empty()) {
		auto nl_pos = body.find('\n');
		auto line = body.substr(0, nl_pos);

		if (nl_pos != std::string_view::npos && !line.empty() && line.back() == '\r') {
			line.remove_suffix(1);
		}

		if (!line.empty()) {
			out(line.data(), line.size());
		}

		if (nl_pos == std::string_view::npos) {
			break;
		}

		out("\r\n", 2);
		body.remove_prefix(nl_pos + 1);
	}

	/* Final CRLF: always present, also for an empty body */
	out("\r\n", 2);
}

}// namespace rspamd::dkim2

#endif /* RSPAMD_DKIM2_UTIL_HXX */
