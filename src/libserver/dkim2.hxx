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
 * Internal C++ interface of the DKIM2 module: header tag parsing,
 * canonicalization and chain logic primitives, kept free of task/DNS
 * dependencies so that they can be unit tested in isolation. The string and
 * message helpers live in dkim2_util.hxx, recipes in dkim2_recipe.hxx.
 *
 * Reference: draft-ietf-dkim-dkim2-spec-09; section numbers in the comments
 * refer to that revision.
 */

#ifndef RSPAMD_DKIM2_HXX
#define RSPAMD_DKIM2_HXX
#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <span>
#include <cstdint>

#include "contrib/expected/expected.hpp"

#include "dkim2_util.hxx"
#include "dkim2_recipe.hxx"

namespace rspamd::dkim2 {

/* Internal limits; the specification sets none (Section 20) */
constexpr std::size_t DKIM2_MAX_SIG_SETS_PER_HOP = 8;
constexpr std::size_t DKIM2_MAX_SIG_SETS_TOTAL = 64;
constexpr std::size_t DKIM2_MAX_HASH_SETS = 8;
constexpr std::size_t DKIM2_MAX_RT_ENTRIES = 1024;
constexpr std::size_t DKIM2_MAX_NONCE_LEN = 64;

/* Raw public key and signature sizes of ML-DSA-44 (FIPS 204) */
constexpr std::size_t DKIM2_MLDSA44_PK_LEN = 1312;
constexpr std::size_t DKIM2_MLDSA44_SIG_LEN = 2420;

/* f= tag flags (Section 10.10) */
constexpr unsigned int DKIM2_SIG_FLAG_EXPLODED = (1u << 0u);
constexpr unsigned int DKIM2_SIG_FLAG_FEEDBACK = (1u << 1u);
constexpr unsigned int DKIM2_SIG_FLAG_FEEDHERE = (1u << 2u);

/*
 * Intermediate result of a single hash-set or signature and of their
 * combinations (Sections 14.6 and 14.7)
 */
enum class result_t : std::uint8_t {
	pass,
	fail,
	temperror,
	permerror,
};

/**
 * Result of a comma separated list: a pass if everything passes; a temperror
 * if everything that is not a pass is a temperror; a fail if anything fails;
 * a permerror otherwise.
 */
auto combine_all(std::span<const result_t> results) -> result_t;

/**
 * Result of `|` separated groups: a pass if any group passes, then a
 * temperror if any group is a temperror, then a fail if any group fails;
 * a permerror otherwise.
 */
auto combine_any(std::span<const result_t> results) -> result_t;

struct tag_t {
	std::string_view name;
	std::string_view value;
};

/**
 * Split a tag-list (Section 8) into tags, trimming FWS around names and
 * values. A tag name is ALPHA *(ALPHA / DIGIT / "_"); a tag name that occurs
 * twice makes the whole list invalid. In the strict mode (the DKIM2 header
 * fields) empty tag-specs are allowed only as the result of one trailing `;`
 * and values must be printable ASCII; the lenient mode (DNS records) skips
 * empty tag-specs.
 */
auto parse_tag_list(std::string_view input, bool strict = true)
	-> tl::expected<std::vector<tag_t>, std::string>;

/*
 * A parse error of a DKIM2 header field: the m=/i= number of the field if it
 * could be read (0 otherwise) and the text to follow `Message-Instance m=<x>`
 * or `DKIM2-Signature i=<x>` in the human-readable error (Section 14.2)
 */
struct parse_error_t {
	unsigned int num = 0;
	std::string what;
};

/* A single hash-set from the Message-Instance h= tag: `alg:hdr-hash:body-hash` */
struct hash_set_t {
	std::string alg;         /* "sha256", "sha512" or an unknown name */
	std::string header_hash; /* decoded binary */
	std::string body_hash;   /* decoded binary */
};

struct mi_header_t {
	unsigned int m = 0; /* instance number */
	/* `|` separated groups of `,` separated hash-sets (Section 9.3) */
	std::vector<std::vector<hash_set_t>> hash_groups;
	bool has_recipe = false;
	std::string recipe_b64; /* r= tag with whitespace removed */
};

/* A single signature from the DKIM2-Signature s= tag: `selector:alg:sig` */
struct sig_set_t {
	std::string selector;
	std::string alg; /* "rsa-sha256", "ed25519-sha256", "mldsa44" or unknown */
	std::string sig; /* decoded binary */
};

struct sig_header_t {
	unsigned int i = 0;          /* hop sequence number */
	unsigned int m = 0;          /* referenced Message-Instance number */
	std::uint64_t t = 0;         /* timestamp */
	bool has_nd = false;         /* nd= is present, then there is no mf=/rt= */
	std::string nd;              /* nd= tag: the next signing domain */
	std::string mf;              /* decoded MAIL FROM reverse-path, with angle brackets */
	std::vector<std::string> rt; /* decoded RCPT TO forward-paths, with angle brackets */
	std::string domain;          /* d= tag */
	/* `|` separated groups of `,` separated signatures (Section 10.9) */
	std::vector<std::vector<sig_set_t>> sig_groups;
	unsigned int flags = 0;
	std::string nonce; /* n= tag */
};

/**
 * Parse an unfolded Message-Instance header value
 */
auto parse_mi(std::string_view value) -> tl::expected<mi_header_t, parse_error_t>;

/**
 * Parse an unfolded DKIM2-Signature header value
 */
auto parse_sig(std::string_view value) -> tl::expected<sig_header_t, parse_error_t>;

/**
 * Canonicalize a header for the *message header hash* (Section 6.2):
 * lowercase name, collapse WSP runs to a single SP, trim trailing WSP and
 * WSP around the colon; result is `name:value\r\n`.
 * The value must be already unfolded.
 */
auto canon_hash_line(std::string_view name, std::string_view unfolded_value) -> std::string;

/**
 * Canonicalize a Message-Instance/DKIM2-Signature header for the *signature
 * input* (Section 12.8): lowercase name, delete ALL WSP; result is
 * `name:value\r\n`. The value must be already unfolded.
 */
auto canon_sig_line(std::string_view name, std::string_view unfolded_value) -> std::string;

/**
 * Given a canonical signature line (output of canon_sig_line for a
 * DKIM2-Signature header), set all signature values within the s= tag to the
 * null string, as required when constructing the signature input for the hop
 * being verified. Selectors, algorithm names and the `:` `,` `|` punctuation
 * remain.
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
 * Check the Chain of Custody recorded in the signatures (Section 7.1 items 1
 * and 2, Section 14.4), all but the comparison with the SMTP envelope.
 * `sigs` must be in ascending i= order without gaps.
 * @return the human-readable failure, or nullopt if the chain is valid
 */
auto check_custody(std::span<const sig_header_t> sigs) -> std::optional<std::string>;

/*
 * DNS records (Sections 3.7 and 3.8)
 */

enum class record_status {
	ok,
	ignored,      /* not a DKIM1 record, to be skipped */
	syntax_error, /* a DKIM1 record that cannot be used */
};

struct key_record_t {
	std::string k = "rsa"; /* key type */
	bool revoked = false;  /* empty p= */
	std::string p;         /* base64 key data with whitespace removed */
};

/**
 * Parse a public key TXT record; the retired h=, n=, s= and t= tags and
 * unknown tags are ignored
 */
auto parse_key_record(std::string_view txt, key_record_t &out) -> record_status;

struct policy_record_t {
	bool strict = false; /* subdomains cannot make a From Authentic */
};

/**
 * Parse a Domain Policy Record; records that do not begin with v=DKIM1 are
 * ignored
 */
auto parse_policy_record(std::string_view txt, policy_record_t &out) -> record_status;

/**
 * Key type (the k= value of a key record) required by a signature algorithm,
 * empty for an unknown algorithm
 */
auto sig_alg_key_type(std::string_view sig_alg) -> std::string_view;

}// namespace rspamd::dkim2

#endif /* RSPAMD_DKIM2_HXX */
