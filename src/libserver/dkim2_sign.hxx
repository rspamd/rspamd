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
 * DKIM2 signing of an original message: the first Message-Instance and the
 * first DKIM2-Signature header fields (draft-ietf-dkim-dkim2-spec-09,
 * Section 12). The part that is free of task dependencies.
 */

#ifndef RSPAMD_DKIM2_SIGN_HXX
#define RSPAMD_DKIM2_SIGN_HXX
#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "contrib/expected/expected.hpp"

#include "dkim2_util.hxx"

namespace rspamd::dkim2 {

/* What the Originator records about the transmission of the message */
struct sign_fields_t {
	std::string domain;          /* d= */
	std::string selector;        /* the selector of the s= tag */
	std::string alg;             /* "rsa-sha256" or "ed25519-sha256" */
	std::string mf;              /* MAIL FROM path with angle brackets */
	std::vector<std::string> rt; /* RCPT TO paths with angle brackets */
	std::uint64_t t = 0;         /* timestamp */
};

/*
 * A tag-list under construction. A value is made of plain text, that can be
 * neither split nor padded, and of base64 strings, that can be folded at any
 * point (Section 2.14).
 */
class tag_list_builder {
public:
	/* Start a tag: `name=` */
	auto tag(std::string_view name) -> tag_list_builder &;
	auto text(std::string_view value) -> tag_list_builder &;
	auto base64(std::string_view encoded) -> tag_list_builder &;

	/* On one line: what is signed and what is parsed */
	auto unfolded() const -> std::string;
	/* A tag per line, long base64 strings are wrapped; for the wire */
	auto folded(std::string_view newline, std::size_t width = 76) const -> std::string;

private:
	struct token_t {
		std::string text;
		bool is_base64;
		bool starts_tag;
	};
	std::vector<token_t> tokens;
};

/* The fields of a signed message and their values without the folding */
struct signed_fields_t {
	std::string mi;        /* Message-Instance, folded */
	std::string sig;       /* DKIM2-Signature, folded */
	std::string mi_value;  /* Message-Instance on one line */
	std::string sig_value; /* DKIM2-Signature on one line */
};

/* Signs a SHA-256 digest of the signature input, returns the raw signature */
using sign_digest_fn = std::function<std::optional<std::string>(std::string_view digest)>;

/**
 * Check that the Originator may sign: there are no DKIM2 fields yet, the
 * signing domain matches the MAIL FROM domain (Section 10.8) and the only
 * From header field is Authentic for it (Section 11).
 * @return what is wrong, or nullopt
 */
auto check_originator(std::span<const raw_header_t> headers, const sign_fields_t &fields)
	-> std::optional<std::string>;

/**
 * Make the m=1 Message-Instance and the i=1 DKIM2-Signature header fields
 * for a message (Sections 12.1 and 12.8)
 */
auto sign_message(std::span<const raw_header_t> headers, std::string_view body,
				  const sign_fields_t &fields, std::string_view newline,
				  const sign_digest_fn &sign_digest)
	-> tl::expected<signed_fields_t, std::string>;

}// namespace rspamd::dkim2

#endif /* RSPAMD_DKIM2_SIGN_HXX */
