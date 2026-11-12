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
 * String, address and message helpers of the DKIM2 module, see
 * dkim2_util.hxx
 */

#include "config.h"
#include "dkim2_util.hxx"
#include "libutil/str_util.h"

#include "contrib/fmt/include/fmt/core.h"

#include <algorithm>
#include <array>

namespace rspamd::dkim2 {

auto trim(std::string_view in) -> std::string_view
{
	while (!in.empty() && is_wsp(in.front())) {
		in.remove_prefix(1);
	}
	while (!in.empty() && is_wsp(in.back())) {
		in.remove_suffix(1);
	}

	return in;
}

auto strip_wsp(std::string_view in) -> std::string
{
	std::string out;
	out.reserve(in.size());

	for (auto c: in) {
		if (!is_wsp(c)) {
			out.push_back(c);
		}
	}

	return out;
}

auto lc_string(std::string_view in) -> std::string
{
	std::string out{in};
	rspamd_str_lc(out.data(), out.size());

	return out;
}

auto eq_icase(std::string_view a, std::string_view b) -> bool
{
	return a.size() == b.size() &&
		   rspamd_lc_cmp(a.data(), b.data(), a.size()) == 0;
}

auto starts_with_icase(std::string_view in, std::string_view prefix) -> bool
{
	return in.size() >= prefix.size() &&
		   rspamd_lc_cmp(in.data(), prefix.data(), prefix.size()) == 0;
}

/* 1*DIGIT that fits into 64 bits */
auto parse_uint(std::string_view in) -> std::optional<std::uint64_t>
{
	if (in.empty() || in.size() > 20) {
		return std::nullopt;
	}

	std::uint64_t res = 0;

	for (auto c: in) {
		if (c < '0' || c > '9') {
			return std::nullopt;
		}

		auto digit = static_cast<std::uint64_t>(c - '0');

		if (res > (UINT64_MAX - digit) / 10) {
			return std::nullopt;
		}

		res = res * 10 + digit;
	}

	return res;
}

/* textstring without the surrounding FWS: 1*(ALPHA / DIGIT / "-" / "_") */
auto is_textstring(std::string_view in) -> bool
{
	if (in.empty()) {
		return false;
	}

	return std::all_of(in.begin(), in.end(), [](char c) {
		return g_ascii_isalnum(c) || c == '-' || c == '_';
	});
}

/*
 * Decode a base64string (Section 2.14). The decoder is strict on purpose: a
 * lenient one skips stray characters, so the same octets get many spellings,
 * and what verifies here would not verify elsewhere. The alphabet is the
 * standard one, FWS is ignored if allowed, the padding is mandatory and the
 * unused bits MUST be zero.
 */
auto b64_decode(std::string_view in, bool allow_fws) -> std::optional<std::string>
{
	static constexpr auto table = []() {
		std::array<std::int8_t, 256> t{};

		for (auto &v: t) {
			v = -1;
		}

		const char *alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

		for (int i = 0; i < 64; i++) {
			t[static_cast<unsigned char>(alphabet[i])] = static_cast<std::int8_t>(i);
		}

		return t;
	}();

	std::string out;
	out.reserve(in.size() / 4 * 3);

	std::uint32_t acc = 0;
	unsigned int nchars = 0, npad = 0;

	for (auto c: in) {
		if (is_wsp(c)) {
			if (!allow_fws) {
				return std::nullopt;
			}

			continue;
		}

		if (c == '=') {
			if (++npad > 2) {
				return std::nullopt;
			}

			continue;
		}

		auto v = table[static_cast<unsigned char>(c)];

		if (v < 0 || npad > 0) {
			/* Not in the alphabet, or data after the padding */
			return std::nullopt;
		}

		acc = (acc << 6) | static_cast<std::uint32_t>(v);

		if (++nchars == 4) {
			out.push_back(static_cast<char>(acc >> 16));
			out.push_back(static_cast<char>(acc >> 8));
			out.push_back(static_cast<char>(acc));
			acc = 0;
			nchars = 0;
		}
	}

	switch (nchars) {
	case 0:
		if (npad != 0) {
			return std::nullopt;
		}
		break;
	case 2:
		if (npad != 2 || (acc & 0xF) != 0) {
			return std::nullopt;
		}
		out.push_back(static_cast<char>(acc >> 4));
		break;
	case 3:
		if (npad != 1 || (acc & 0x3) != 0) {
			return std::nullopt;
		}
		out.push_back(static_cast<char>(acc >> 10));
		out.push_back(static_cast<char>(acc >> 2));
		break;
	default:
		return std::nullopt;
	}

	return out;
}

auto b64_encode(std::string_view in) -> std::string
{
	static constexpr char alphabet[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	std::string out;

	out.reserve((in.size() + 2) / 3 * 4);

	for (std::size_t pos = 0; pos < in.size(); pos += 3) {
		auto left = in.size() - pos;
		std::uint32_t acc = static_cast<unsigned char>(in[pos]) << 16;

		if (left > 1) {
			acc |= static_cast<unsigned char>(in[pos + 1]) << 8;
		}
		if (left > 2) {
			acc |= static_cast<unsigned char>(in[pos + 2]);
		}

		out.push_back(alphabet[(acc >> 18) & 0x3F]);
		out.push_back(alphabet[(acc >> 12) & 0x3F]);
		out.push_back(left > 1 ? alphabet[(acc >> 6) & 0x3F] : '=');
		out.push_back(left > 2 ? alphabet[acc & 0x3F] : '=');
	}

	return out;
}

auto valid_domain(std::string_view in) -> bool
{
	if (in.empty() || in.size() > 253) {
		return false;
	}

	std::size_t label_len = 0;

	for (auto c: in) {
		if (c == '.') {
			if (label_len == 0) {
				return false;
			}
			label_len = 0;
		}
		else if (g_ascii_isalnum(c) || c == '-' || c == '_') {
			if (++label_len > 63) {
				return false;
			}
		}
		else {
			return false;
		}
	}

	return label_len > 0;
}

auto is_unsigned_header(std::string_view name) -> bool
{
	static constexpr std::string_view exact[] = {
		"apparently-to",
		"arc-authentication-results",
		"arc-message-signature",
		"arc-seal",
		"authentication-results",
		"delivered-to",
		"dkim-signature",
		"dl-expansion-history",
		"original-recipient",
		"received",
		"return-path",
		"sio-label-history",
		"x400-received",
		"x400-trace",
		/* Signed by the DKIM2-Signature fields, not by the header hash */
		"message-instance",
		"dkim2-signature",
	};

	for (auto ex: exact) {
		if (eq_icase(name, ex)) {
			return true;
		}
	}

	return starts_with_icase(name, "x-") || starts_with_icase(name, "received-");
}

auto relaxed_domain_match(std::string_view param1, std::string_view param2) -> bool
{
	if (param1.empty() || param2.empty() ||
		param1.front() == '[' || param2.front() == '[') {
		return false;
	}

	for (;;) {
		if (eq_icase(param1, param2)) {
			return true;
		}

		auto dot_pos = param1.find('.');

		if (dot_pos == std::string_view::npos) {
			return false;
		}

		param1.remove_prefix(dot_pos + 1);

		if (param1.empty()) {
			return false;
		}
	}
}

static auto
strip_angle(std::string_view addr) -> std::string_view
{
	addr = trim(addr);

	if (addr.size() >= 2 && addr.front() == '<' && addr.back() == '>') {
		addr.remove_prefix(1);
		addr.remove_suffix(1);
	}

	/* An obsolete source route: `@a,@b:local@domain` */
	if (!addr.empty() && addr.front() == '@') {
		auto colon_pos = addr.find(':');

		if (colon_pos != std::string_view::npos) {
			addr.remove_prefix(colon_pos + 1);
		}
	}

	return addr;
}

auto smtp_addr_domain(std::string_view addr) -> std::string_view
{
	addr = strip_angle(addr);
	auto at_pos = addr.rfind('@');

	if (at_pos == std::string_view::npos) {
		return {};
	}

	return addr.substr(at_pos + 1);
}

auto smtp_addr_is_null(std::string_view addr) -> bool
{
	return strip_angle(addr).empty();
}

auto smtp_addr_key(std::string_view addr) -> std::string
{
	addr = strip_angle(addr);
	std::string key{addr};
	auto at_pos = key.rfind('@');

	if (at_pos != std::string::npos) {
		rspamd_str_lc(key.data() + at_pos + 1, key.size() - at_pos - 1);
	}

	return key;
}

auto smtp_addr_equal(std::string_view a, std::string_view b) -> bool
{
	return smtp_addr_key(a) == smtp_addr_key(b);
}

auto split_body_lines(std::string_view body, std::size_t max_lines)
	-> tl::expected<std::vector<std::string_view>, std::string>
{
	std::vector<std::string_view> lines;

	/* The same notion of a line as in body_canon_foreach */
	while (!body.empty()) {
		auto nl_pos = body.find('\n');
		auto line = body.substr(0, nl_pos);

		if (nl_pos != std::string_view::npos && !line.empty() && line.back() == '\r') {
			line.remove_suffix(1);
		}

		if (lines.size() >= max_lines) {
			return tl::make_unexpected(fmt::format("too many body lines (max {})",
												   max_lines));
		}

		lines.emplace_back(line);

		if (nl_pos == std::string_view::npos) {
			break;
		}

		body.remove_prefix(nl_pos + 1);
	}

	return lines;
}

auto scan_headers(std::string_view block)
	-> tl::expected<std::vector<raw_header_t>, std::string>
{
	std::vector<raw_header_t> res;
	/* The field being collected: its first line and all of its lines */
	std::string_view name, first_line;
	const char *field_start = nullptr, *field_end = nullptr;
	bool folded = false;

	auto flush = [&]() {
		if (field_start == nullptr) {
			return;
		}

		auto &hdr = res.emplace_back();

		hdr.name = name;

		if (!folded) {
			hdr.value = first_line;
		}
		else {
			/* Unfold: drop the terminators of all lines, keep everything else */
			std::string_view raw{field_start, static_cast<std::size_t>(field_end - field_start)};

			raw.remove_prefix(first_line.data() - field_start);
			hdr.unfolded.reserve(raw.size());

			while (!raw.empty()) {
				auto nl_pos = raw.find('\n');
				auto line = raw.substr(0, nl_pos);

				if (nl_pos != std::string_view::npos && !line.empty() && line.back() == '\r') {
					line.remove_suffix(1);
				}

				hdr.unfolded.append(line);

				if (nl_pos == std::string_view::npos) {
					break;
				}

				raw.remove_prefix(nl_pos + 1);
			}
		}

		field_start = nullptr;
	};

	while (!block.empty()) {
		auto nl_pos = block.find('\n');
		auto line = block.substr(0, nl_pos);

		if (nl_pos != std::string_view::npos && !line.empty() && line.back() == '\r') {
			line.remove_suffix(1);
		}

		auto line_end = line.data() + line.size();

		if (line.empty()) {
			/* The end of the header */
			break;
		}

		if (is_wsp(line.front())) {
			if (field_start == nullptr) {
				return tl::make_unexpected(std::string{"a continuation line without a header field"});
			}

			folded = true;
			field_end = line_end;
		}
		else {
			flush();

			auto colon_pos = line.find(':');

			if (colon_pos == std::string_view::npos) {
				return tl::make_unexpected(std::string{"a line that is not a header field"});
			}

			name = line.substr(0, colon_pos);

			while (!name.empty() && is_wsp(name.back())) {
				name.remove_suffix(1);
			}

			if (name.empty() || !std::all_of(name.begin(), name.end(), [](char c) {
					return c > 0x20 && c < 0x7f;
				})) {
				return tl::make_unexpected(std::string{"an invalid header field name"});
			}

			if (res.size() >= DKIM2_MAX_HEADER_FIELDS) {
				return tl::make_unexpected(std::string{"too many header fields"});
			}

			first_line = line.substr(colon_pos + 1);
			field_start = line.data();
			field_end = line_end;
			folded = false;
		}

		if (nl_pos == std::string_view::npos) {
			break;
		}

		block.remove_prefix(nl_pos + 1);
	}

	flush();

	/* Vector growth moves the strings, so the views are set at the end */
	for (auto &hdr: res) {
		if (!hdr.unfolded.empty()) {
			hdr.value = hdr.unfolded;
		}
	}

	return res;
}

auto from_is_single_mailbox(std::string_view value) -> bool
{
	return from_mailbox_domain(value).has_value();
}

auto from_mailbox_domain(std::string_view value) -> std::optional<std::string_view>
{
	unsigned int nat = 0, comment_depth = 0;
	std::size_t at_pos = 0;
	bool in_quotes = false;

	for (std::size_t pos = 0; pos < value.size(); pos++) {
		auto c = value[pos];

		if (c == '\\' && (in_quotes || comment_depth > 0)) {
			/* A quoted pair */
			pos++;
		}
		else if (in_quotes) {
			in_quotes = c != '"';
		}
		else if (comment_depth > 0) {
			if (c == '(') {
				comment_depth++;
			}
			else if (c == ')') {
				comment_depth--;
			}
		}
		else if (c == '"') {
			in_quotes = true;
		}
		else if (c == '(') {
			comment_depth++;
		}
		else if (c == '@') {
			nat++;
			at_pos = pos;
		}
		else if (c == ',' || c == ';') {
			return std::nullopt;
		}
	}

	if (nat != 1 || in_quotes || comment_depth != 0) {
		return std::nullopt;
	}

	/* The domain ends where a comment, the angle bracket or whitespace starts */
	auto domain = value.substr(at_pos + 1);
	auto end = domain.find_first_of(" \t>(");

	return domain.substr(0, end);
}

}// namespace rspamd::dkim2
