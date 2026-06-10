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
 * Internal C++ interface of the DKIM2 module: header tag parsing and
 * canonicalization primitives, kept free of task/DNS dependencies so that
 * they can be unit tested in isolation.
 *
 * Reference: draft-ietf-dkim-dkim2-spec
 */

#ifndef RSPAMD_DKIM2_HXX
#define RSPAMD_DKIM2_HXX
#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <span>
#include <cstdint>
#include <ctime>

#include "contrib/expected/expected.hpp"

namespace rspamd::dkim2 {

/* f= tag flags */
constexpr unsigned int DKIM2_SIG_FLAG_DONOTMODIFY = (1u << 0u);
constexpr unsigned int DKIM2_SIG_FLAG_DONOTEXPLODE = (1u << 1u);
constexpr unsigned int DKIM2_SIG_FLAG_FEEDBACK = (1u << 2u);
constexpr unsigned int DKIM2_SIG_FLAG_EXPLODED = (1u << 3u);

struct tag_t {
	std::string_view name;
	std::string_view value;
};

/**
 * Split a DKIM2 tag-list (`tag=value;tag=value...`) into tags, trimming FWS.
 * Unknown tags are preserved as is; empty segments (e.g. a trailing `;`)
 * are skipped.
 */
auto parse_tag_list(std::string_view input) -> tl::expected<std::vector<tag_t>, std::string>;

/* A single hash-set from the Message-Instance h= tag: `alg:hdr-hash:body-hash` */
struct hash_set_t {
	std::string alg;         /* e.g. "sha256" */
	std::string header_hash; /* decoded binary */
	std::string body_hash;   /* decoded binary */
};

struct mi_header_t {
	unsigned int m = 0; /* instance number */
	std::vector<hash_set_t> hashes;
	bool has_recipe = false;
	std::string recipe_b64; /* r= tag, not decoded in the draft implementation */
};

/* A single signature set from the DKIM2-Signature s= tag: `selector:alg:sig` */
struct sig_set_t {
	std::string selector;
	std::string alg; /* "rsa-sha256" or "ed25519-sha256" */
	std::string sig; /* decoded binary */
};

struct sig_header_t {
	unsigned int i = 0;          /* hop sequence number */
	unsigned int m = 0;          /* referenced Message-Instance number */
	std::time_t t = 0;           /* timestamp, 0 if missing */
	std::string mf;              /* decoded MAIL FROM reverse-path, with angle brackets */
	std::vector<std::string> rt; /* decoded RCPT TO forward-paths */
	std::string domain;          /* d= tag */
	std::vector<sig_set_t> sigs;
	unsigned int flags = 0;
};

/**
 * Parse an unfolded Message-Instance header value
 */
auto parse_mi(std::string_view value) -> tl::expected<mi_header_t, std::string>;

/**
 * Parse an unfolded DKIM2-Signature header value
 */
auto parse_sig(std::string_view value) -> tl::expected<sig_header_t, std::string>;

/**
 * Canonicalize a header for the *message header hash* (Section 5.2):
 * lowercase name, collapse WSP runs to a single SP, trim trailing WSP and
 * WSP around the colon; result is `name:value\r\n`.
 * The value must be already unfolded.
 */
auto canon_hash_line(std::string_view name, std::string_view unfolded_value) -> std::string;

/**
 * Canonicalize a Message-Instance/DKIM2-Signature header for the *signature
 * input* (Section 8.5): lowercase name, delete ALL WSP; result is
 * `name:value\r\n`. The value must be already unfolded.
 */
auto canon_sig_line(std::string_view name, std::string_view unfolded_value) -> std::string;

/**
 * Given a canonical signature line (output of canon_sig_line for a
 * DKIM2-Signature header), set all signature values within the s= tag to the
 * null string, as required when constructing the signature input for the hop
 * being verified.
 */
auto blank_sig_values(std::string_view canon_line) -> std::string;

/**
 * Build the signature input for one hop: Message-Instance lines in ascending
 * m= order, complete signature lines of the previous hops in ascending i=
 * order, then the canonical line of the hop being verified with blanked
 * signature values.
 */
auto build_sig_input(std::span<const std::string> mi_lines,
					 std::span<const std::string> prev_sig_lines,
					 std::string_view current_sig_line) -> std::string;

/**
 * Relaxed domain match (Section 8.3): strip leftmost labels from `child`
 * until it equals `base` (case-insensitively) or no labels remain.
 */
auto relaxed_domain_match(std::string_view child, std::string_view base) -> bool;

/**
 * Compare two SMTP paths: angle brackets are stripped, the local part is
 * compared case-sensitively and the domain case-insensitively. The null
 * reverse-path `<>` only matches an empty address.
 */
auto smtp_addr_equal(std::string_view a, std::string_view b) -> bool;

/**
 * Extract the domain part of an SMTP path (`<local@domain>` or `local@domain`),
 * empty view if there is none
 */
auto smtp_addr_domain(std::string_view addr) -> std::string_view;

/**
 * Body canonicalization (Section 5.1): all trailing empty lines are ignored
 * and a single final CRLF is appended; bare LF/CR line endings are emitted as
 * CRLF. Yields chunks via `out(const char *, std::size_t)`.
 */
template<typename Func>
void body_canon_foreach(std::string_view body, Func &&out)
{
	/* Strip all trailing CR/LF octets: this removes trailing empty lines
	 * together with the line terminator of the last non-empty line, which is
	 * then restored as the single final CRLF */
	auto end = body.size();
	while (end > 0 && (body[end - 1] == '\n' || body[end - 1] == '\r')) {
		end--;
	}

	std::size_t run_start = 0;
	for (std::size_t pos = 0; pos < end; pos++) {
		auto c = body[pos];
		if (c == '\r' || c == '\n') {
			if (pos > run_start) {
				out(body.data() + run_start, pos - run_start);
			}
			out("\r\n", 2);
			if (c == '\r' && pos + 1 < end && body[pos + 1] == '\n') {
				pos++;
			}
			run_start = pos + 1;
		}
	}

	if (end > run_start) {
		out(body.data() + run_start, end - run_start);
	}

	/* Final CRLF: always present, also for an empty body */
	out("\r\n", 2);
}

}// namespace rspamd::dkim2

#endif /* RSPAMD_DKIM2_HXX */
