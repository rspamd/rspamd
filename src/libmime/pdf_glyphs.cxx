/*-
 * Copyright 2026 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include "config.h"

#include "pdf_glyphs.hxx"
#include "pdf_glyphs_defs.hxx"

#include "libutil/str_util.h"
#include "libutil/rspamd_simdutf.h"

#include "unicode/uchar.h"
#include "unicode/utf8.h"

#include <algorithm>

namespace rspamd::mime::pdf {

namespace {

auto base_table_for(base_encoding base) noexcept -> const glyph_utf8 *
{
	switch (base) {
	case base_encoding::win_ansi:
		return win_ansi_encoding_utf8;
	case base_encoding::mac_roman:
		return mac_roman_encoding_utf8;
	case base_encoding::standard:
	default:
		return standard_encoding_utf8;
	}
}

auto iequals(std::string_view a, std::string_view b) noexcept -> bool
{
	return a.size() == b.size() && rspamd_lc_cmp(a.data(), b.data(), a.size()) == 0;
}

/* Parses exactly nhex hex digits, nothing more and nothing less */
auto parse_hex_run(std::string_view s, std::size_t nhex) noexcept -> std::optional<char32_t>
{
	gulong v;

	if (s.size() != nhex || !rspamd_xstrtoul(s.data(), s.size(), &v)) {
		return std::nullopt;
	}

	return static_cast<char32_t>(v);
}

}// namespace

auto base_encoding_from_name(std::string_view name) -> std::optional<base_encoding>
{
	if (!name.empty() && name.front() == '/') {
		name.remove_prefix(1);
	}

	if (iequals(name, "WinAnsiEncoding")) {
		return base_encoding::win_ansi;
	}
	if (iequals(name, "MacRomanEncoding")) {
		return base_encoding::mac_roman;
	}
	if (iequals(name, "StandardEncoding")) {
		return base_encoding::standard;
	}

	/*
	 * MacExpertEncoding is a different repertoire altogether (old style figures,
	 * small caps and the like) and is vanishingly rare; treat it as unknown
	 * rather than silently decoding it as text.
	 */
	return std::nullopt;
}

auto glyph_name_to_unicode(std::string_view name) noexcept -> std::optional<char32_t>
{
	if (name.empty()) {
		return std::nullopt;
	}

	if (name.front() == '/') {
		name.remove_prefix(1);
	}

	/*
	 * A glyph name may carry a suffix that does not change the character, e.g.
	 * "a.sc" or "one.oldstyle"; the base name is what matters.
	 */
	if (auto dot = name.find('.'); dot != std::string_view::npos && dot > 0) {
		name = name.substr(0, dot);
	}

	if (name.empty()) {
		return std::nullopt;
	}

	auto it = std::lower_bound(std::begin(pdf_glyph_names), std::end(pdf_glyph_names),
							   name,
							   [](const pdf_glyph_name_def &def, std::string_view n) {
								   return std::string_view{def.name} < n;
							   });

	if (it != std::end(pdf_glyph_names) && std::string_view{it->name} == name) {
		return it->uc;
	}

	/* uniXXXX: the AGL algorithmic form, four hex digits */
	if (name.size() == 7 && name.compare(0, 3, "uni") == 0) {
		auto uc = parse_hex_run(name.substr(3), 4);

		if (uc && *uc != 0 && U_IS_UNICODE_CHAR(*uc)) {
			return uc;
		}

		return std::nullopt;
	}

	/* uXXXX .. uXXXXXX: four to six hex digits */
	if (name.size() >= 5 && name.size() <= 7 && name.front() == 'u') {
		auto uc = parse_hex_run(name.substr(1), name.size() - 1);

		if (uc && *uc != 0 && U_IS_UNICODE_CHAR(*uc)) {
			return uc;
		}

		return std::nullopt;
	}

	/*
	 * Everything else -- gNN, cidNN, indexNN and whatever else a subsetting tool
	 * invented -- names a glyph slot, not a character.
	 */
	return std::nullopt;
}

font_encoding::font_encoding(base_encoding base) noexcept
	: base_table(base_table_for(base))
{
}

auto font_encoding::set_difference(unsigned char code, std::string_view glyph_name) -> bool
{
	auto uc = glyph_name_to_unicode(glyph_name);

	if (!uc) {
		return false;
	}

	if (!overrides) {
		/* Value initialised, so every slot starts out empty */
		overrides = std::make_unique<std::array<glyph_utf8, 256>>();
	}

	auto &slot = (*overrides)[code];
	int32_t off = 0;
	U8_APPEND_UNSAFE(slot.bytes, off, *uc);
	slot.len = static_cast<std::uint8_t>(off);

	return true;
}

auto font_encoding::lookup(unsigned char code) const noexcept -> std::string_view
{
	if (overrides) {
		const auto &slot = (*overrides)[code];

		if (slot.len > 0) {
			return slot.view();
		}
	}

	return base_table[code].view();
}

text_builder::text_builder(std::size_t reserve, std::size_t max_output)
	: limit(max_output)
{
	if (reserve > 0) {
		reserve_for(reserve);
	}
}

auto text_builder::reserve_for(std::size_t extra) -> void
{
	buf.reserve(std::min(buf.size() + extra, limit));
}

auto text_builder::append_capped(std::string_view utf8) -> bool
{
	if (utf8.size() > limit - buf.size()) {
		hit_ceiling = true;

		return false;
	}

	buf.append(utf8);

	return true;
}

auto text_builder::add_code(unsigned char code) -> void
{
	static const font_encoding default_encoding{base_encoding::standard};

	/*
	 * A font with no /Encoding uses its built-in one, which for the Latin text
	 * fonts this unit can handle is StandardEncoding.
	 */
	const auto *enc = cur_encoding != nullptr ? cur_encoding : &default_encoding;
	auto utf8 = enc->lookup(code);

	/* .notdef produces nothing rather than a placeholder */
	if (!utf8.empty()) {
		append_capped(utf8);
	}
}

auto text_builder::add_cmapped(std::string_view codes) -> void
{
	glyph_utf8 scratch{};

	/*
	 * This is where a hostile PDF pays off best: every code here can resolve to
	 * a mapping far longer than the code itself, so the run is abandoned as
	 * soon as the ceiling is in the way rather than decoded to the end.
	 */
	while (!codes.empty() && !hit_ceiling) {
		auto nbytes = cur_cmap->code_length(codes);

		if (nbytes == 0 || nbytes > codes.size()) {
			break;
		}

		std::uint32_t code = 0;

		for (std::size_t i = 0; i < nbytes; i++) {
			code = (code << 8) | static_cast<unsigned char>(codes[i]);
		}

		auto utf8 = cur_cmap->lookup(code, nbytes, scratch);

		/* An unmapped code is a glyph index with no character: drop it */
		if (!utf8.empty()) {
			append_capped(utf8);
		}

		codes.remove_prefix(nbytes);
	}
}

auto text_builder::decode_codes(std::string_view codes) -> void
{
	/*
	 * A composite font is addressed through its CMap, whose codes may span
	 * several bytes; a simple font is one code per byte.
	 */
	if (cur_cmap != nullptr) {
		add_cmapped(codes);

		return;
	}

	for (auto c: codes) {
		if (hit_ceiling) {
			break;
		}

		add_code(static_cast<unsigned char>(c));
	}
}

auto text_builder::add_encoded(std::string_view codes) -> void
{
	reserve_for(codes.size());
	decode_codes(codes);
}

auto text_builder::add_utf8(std::string_view utf8) -> bool
{
	if (rspamd_fast_utf8_validate((const unsigned char *) utf8.data(), utf8.size()) != 0) {
		return false;
	}

	return append_capped(utf8);
}

auto text_builder::add_char(char c) -> void
{
	append_capped({&c, 1});
}

auto text_builder::add_pdf_string(std::string_view raw) -> void
{
	reserve_for(raw.size());

	/*
	 * Codes accumulate until a structural character interrupts them, because a
	 * CMap code cannot be decoded before all of its bytes are in hand.
	 */
	std::string codes;

	auto flush = [&]() {
		if (!codes.empty()) {
			decode_codes(codes);
			codes.clear();
		}
	};

	auto structural = [&](char c) {
		flush();
		append_capped({&c, 1});
	};

	for (std::size_t i = 0; i < raw.size() && !hit_ceiling;) {
		auto c = raw[i];

		if (c != '\\') {
			/*
			 * An end of line inside a literal string is a line feed, whichever
			 * of the three spellings was used.
			 */
			if (c == '\r') {
				structural('\n');
				i++;

				if (i < raw.size() && raw[i] == '\n') {
					i++;
				}
			}
			else if (c == '\n') {
				structural('\n');
				i++;
			}
			else {
				codes.push_back(c);
				i++;
			}

			continue;
		}

		/* A backslash at the very end is a stray one: drop it */
		if (++i >= raw.size()) {
			break;
		}

		auto esc = raw[i];

		switch (esc) {
		case 'n':
			structural('\n');
			i++;
			break;
		case 'r':
			structural('\r');
			i++;
			break;
		case 't':
			structural('\t');
			i++;
			break;
		case 'b':
		case 'f':
			/* Backspace and form feed carry no text; drop them */
			i++;
			break;
		case '\r':
			/* Line continuation: the newline is not part of the string */
			i++;

			if (i < raw.size() && raw[i] == '\n') {
				i++;
			}
			break;
		case '\n':
			i++;
			break;
		default:
			if (esc >= '0' && esc <= '7') {
				/* Octal escape, one to three digits */
				unsigned int code = 0;
				std::size_t ndigits = 0;

				while (i < raw.size() && ndigits < 3 && raw[i] >= '0' && raw[i] <= '7') {
					code = code * 8 + static_cast<unsigned int>(raw[i] - '0');
					i++;
					ndigits++;
				}

				codes.push_back(static_cast<char>(code & 0xFF));
			}
			else {
				/* \( \) \\ and any other escape stand for the character itself */
				codes.push_back(esc);
				i++;
			}
			break;
		}
	}

	flush();
}

auto text_builder::add_pdf_hexstring(std::string_view raw) -> void
{
	std::string codes;
	codes.reserve(raw.size() / 2);

	int hi = -1;

	for (auto c: raw) {
		auto v = g_ascii_xdigit_value(c);

		if (v < 0) {
			/* Whitespace is allowed inside a hex string; anything else is junk */
			continue;
		}

		if (hi < 0) {
			hi = v;
		}
		else {
			codes.push_back(static_cast<char>((hi << 4) | v));
			hi = -1;
		}
	}

	/* An odd number of digits: the last one is padded with a zero */
	if (hi >= 0) {
		codes.push_back(static_cast<char>(hi << 4));
	}

	reserve_for(codes.size());
	decode_codes(codes);
}

}// namespace rspamd::mime::pdf

TEST_SUITE("pdf glyphs")
{
	using namespace rspamd::mime::pdf;

	TEST_CASE("the same code is a different character per encoding")
	{
		/*
		 * This is the whole reason the unit exists: 0xe9 cannot be decoded, or
		 * charset detected, without knowing which font drew it.
		 */
		font_encoding std_enc{base_encoding::standard};
		font_encoding win_enc{base_encoding::win_ansi};
		font_encoding mac_enc{base_encoding::mac_roman};

		CHECK(std_enc.lookup(0xE9) == "\xc3\x98");// Oslash
		CHECK(win_enc.lookup(0xE9) == "\xc3\xa9");// eacute
		CHECK(mac_enc.lookup(0xE9) == "\xc3\x88");// Egrave
	}

	TEST_CASE("ligature slots belong to their own encoding only")
	{
		font_encoding std_enc{base_encoding::standard};
		font_encoding win_enc{base_encoding::win_ansi};
		font_encoding mac_enc{base_encoding::mac_roman};

		/* fi and fl sit at 0xae/0xaf in StandardEncoding, 0xde/0xdf in MacRoman */
		CHECK(std_enc.lookup(0xAE) == "\xef\xac\x81");
		CHECK(std_enc.lookup(0xAF) == "\xef\xac\x82");
		CHECK(mac_enc.lookup(0xDE) == "\xef\xac\x81");
		CHECK(mac_enc.lookup(0xDF) == "\xef\xac\x82");

		/* ... and in WinAnsi those very codes are ordinary letters */
		CHECK(win_enc.lookup(0xAE) == "\xc2\xae");// registered
		CHECK(win_enc.lookup(0xDF) == "\xc3\x9f");// germandbls
	}

	TEST_CASE("ascii is common ground and notdef yields nothing")
	{
		font_encoding win_enc{base_encoding::win_ansi};

		CHECK(win_enc.lookup('A') == "A");
		CHECK(win_enc.lookup(' ') == " ");
		/* Control codes are not glyphs in any of the three encodings */
		CHECK(win_enc.lookup(0x00).empty());
		CHECK(win_enc.lookup(0x1F).empty());
		CHECK(win_enc.lookup(0x7F).empty());
	}

	TEST_CASE("winansi keeps the annex D deviations")
	{
		font_encoding win_enc{base_encoding::win_ansi};

		CHECK(win_enc.lookup(0x80) == "\xe2\x82\xac");// Euro
		/* nbsp and soft hyphen are extracted as their plain forms */
		CHECK(win_enc.lookup(0xA0) == " ");
		CHECK(win_enc.lookup(0xAD) == "-");
		/* codes cp1252 leaves undefined become bullets */
		CHECK(win_enc.lookup(0x81) == "\xe2\x80\xa2");
	}

	TEST_CASE("encoding name parsing")
	{
		CHECK(base_encoding_from_name("WinAnsiEncoding") == base_encoding::win_ansi);
		CHECK(base_encoding_from_name("/WinAnsiEncoding") == base_encoding::win_ansi);
		CHECK(base_encoding_from_name("/macromanencoding") == base_encoding::mac_roman);
		CHECK(base_encoding_from_name("StandardEncoding") == base_encoding::standard);
		CHECK(!base_encoding_from_name("MacExpertEncoding").has_value());
		CHECK(!base_encoding_from_name("").has_value());
	}

	TEST_CASE("glyph names")
	{
		CHECK(glyph_name_to_unicode("eacute") == U'é');
		CHECK(glyph_name_to_unicode("/eacute") == U'é');
		CHECK(glyph_name_to_unicode("germandbls") == U'ß');
		CHECK(glyph_name_to_unicode("space") == U' ');

		SUBCASE("algorithmic forms")
		{
			CHECK(glyph_name_to_unicode("uni00E9") == U'é');
			CHECK(glyph_name_to_unicode("uni20AC") == U'€');
			CHECK(glyph_name_to_unicode("u1F600") == U'\U0001f600');
			CHECK(!glyph_name_to_unicode("uni00E").has_value());
			CHECK(!glyph_name_to_unicode("uniZZZZ").has_value());
			/* Surrogates are not characters */
			CHECK(!glyph_name_to_unicode("uniD800").has_value());
		}

		SUBCASE("suffixed names keep their base meaning")
		{
			CHECK(glyph_name_to_unicode("a.sc") == U'a');
			CHECK(glyph_name_to_unicode("one.oldstyle") == U'1');
		}

		SUBCASE("glyph slot names carry no character")
		{
			CHECK(!glyph_name_to_unicode("g42").has_value());
			CHECK(!glyph_name_to_unicode("cid1234").has_value());
			CHECK(!glyph_name_to_unicode("index7").has_value());
			CHECK(!glyph_name_to_unicode(".notdef").has_value());
			CHECK(!glyph_name_to_unicode("").has_value());
		}
	}

	TEST_CASE("differences override the base table")
	{
		font_encoding enc{base_encoding::win_ansi};

		REQUIRE(enc.set_difference(0x41, "eacute"));
		CHECK(enc.has_differences());
		CHECK(enc.lookup(0x41) == "\xc3\xa9");
		/* untouched codes still come from the base table */
		CHECK(enc.lookup(0x42) == "B");

		SUBCASE("an unresolvable name leaves the code alone")
		{
			CHECK(!enc.set_difference(0x42, "g17"));
			CHECK(enc.lookup(0x42) == "B");
		}

		SUBCASE("a difference can map onto a notdef code")
		{
			font_encoding std_enc{base_encoding::standard};

			CHECK(std_enc.lookup(0xDE).empty());
			REQUIRE(std_enc.set_difference(0xDE, "germandbls"));
			CHECK(std_enc.lookup(0xDE) == "\xc3\x9f");
		}
	}

	TEST_CASE("builder maps runs through the current encoding")
	{
		font_encoding win_enc{base_encoding::win_ansi};
		font_encoding mac_enc{base_encoding::mac_roman};
		text_builder b;

		b.set_encoding(&win_enc);
		b.add_encoded("caf\xe9");
		b.add_char(' ');
		b.set_encoding(&mac_enc);
		b.add_encoded("caf\x8e");

		CHECK(b.data() == "caf\xc3\xa9 caf\xc3\xa9");
	}

	TEST_CASE("builder defaults to standard encoding")
	{
		text_builder b;

		b.add_encoded("A\xe9");
		CHECK(b.data() == "A\xc3\x98");
	}

	TEST_CASE("literal string unescaping")
	{
		font_encoding win_enc{base_encoding::win_ansi};

		SUBCASE("plain and escaped characters")
		{
			text_builder b;
			b.set_encoding(&win_enc);
			b.add_pdf_string("a\\(b\\)c\\\\d");
			CHECK(b.data() == "a(b)c\\d");
		}

		SUBCASE("octal escapes go through the encoding")
		{
			text_builder b;
			b.set_encoding(&win_enc);
			/* \351 is 0xe9, e-acute in WinAnsi */
			b.add_pdf_string("caf\\351 \\101\\102");
			CHECK(b.data() == "caf\xc3\xa9 AB");
		}

		SUBCASE("short octal escapes stop at a non digit")
		{
			text_builder b;
			b.set_encoding(&win_enc);
			/* \5 is a control code and thus notdef; \62 is '2' */
			b.add_pdf_string("\\5\\62x");
			CHECK(b.data() == "2x");
		}

		SUBCASE("whitespace escapes")
		{
			text_builder b;
			b.set_encoding(&win_enc);
			b.add_pdf_string("a\\nb\\tc\\bd");
			CHECK(b.data() == "a\nb\tcd");
		}

		SUBCASE("a backslash before a newline continues the line")
		{
			text_builder b;
			b.set_encoding(&win_enc);
			b.add_pdf_string("long\\\r\nline");
			CHECK(b.data() == "longline");
		}

		SUBCASE("a bare newline is a line feed")
		{
			text_builder b;
			b.set_encoding(&win_enc);
			b.add_pdf_string("a\r\nb\rc\nd");
			CHECK(b.data() == "a\nb\nc\nd");
		}

		SUBCASE("a trailing backslash is dropped")
		{
			text_builder b;
			b.set_encoding(&win_enc);
			b.add_pdf_string("abc\\");
			CHECK(b.data() == "abc");
		}
	}

	TEST_CASE("hex string decoding")
	{
		font_encoding win_enc{base_encoding::win_ansi};

		SUBCASE("pairs go through the encoding")
		{
			text_builder b;
			b.set_encoding(&win_enc);
			b.add_pdf_hexstring("636166E9");
			CHECK(b.data() == "caf\xc3\xa9");
		}

		SUBCASE("whitespace and junk are skipped")
		{
			text_builder b;
			b.set_encoding(&win_enc);
			b.add_pdf_hexstring("41 42\n43");
			CHECK(b.data() == "ABC");
		}

		SUBCASE("an odd digit count pads with zero")
		{
			text_builder b;
			b.set_encoding(&win_enc);
			b.add_pdf_hexstring("414");
			CHECK(b.data() == "A@");
		}
	}

	TEST_CASE("builder accumulates and releases one buffer")
	{
		text_builder b{64};

		CHECK(b.empty());
		CHECK(b.add_utf8("already utf8: \xc3\xa9"));
		CHECK(b.size() == 16);

		auto out = b.release();
		CHECK(out == "already utf8: \xc3\xa9");
		CHECK(b.empty());
	}

	TEST_CASE("ill formed utf8 never reaches the buffer")
	{
		text_builder b;

		CHECK(b.add_utf8("fine"));
		/* A lone continuation byte and a truncated sequence */
		CHECK(!b.add_utf8("\xa9"));
		CHECK(!b.add_utf8("\xc3"));
		CHECK(b.data() == "fine");
	}

	TEST_CASE("the buffer stops at its ceiling instead of following the input")
	{
		/*
		 * A ceiling small enough to reach in a test; what is being checked is
		 * that the builder stops adding and says so, not the value it stops at.
		 */
		text_builder b{0, 8};

		b.add_encoded("abcdefgh");
		CHECK(b.data() == "abcdefgh");
		CHECK(!b.truncated());

		b.add_encoded("ijkl");
		CHECK(b.data() == "abcdefgh");
		CHECK(b.truncated());

		/* Emptying the builder gives the next page a clean start */
		b.clear();
		CHECK(!b.truncated());
		b.add_encoded("mn");
		CHECK(b.data() == "mn");
	}

	TEST_CASE("no way into the buffer can push past the ceiling")
	{
		SUBCASE("text the caller decoded itself")
		{
			text_builder b{0, 4};

			CHECK(b.add_utf8("abcd"));
			/* Refused whole rather than in part: half a character is not text */
			CHECK(!b.add_utf8("e"));
			CHECK(b.data() == "abcd");
		}

		SUBCASE("a literal string")
		{
			text_builder b{0, 4};

			b.add_pdf_string("abcdefgh");
			CHECK(b.data() == "abcd");
			CHECK(b.truncated());
		}

		SUBCASE("a hex string")
		{
			text_builder b{0, 4};

			b.add_pdf_hexstring("6162636465");
			CHECK(b.data() == "abcd");
		}

		SUBCASE("characters an operator produced")
		{
			text_builder b{0, 2};

			b.add_char('a');
			b.add_char('b');
			b.add_char('c');
			CHECK(b.data() == "ab");
		}
	}

	TEST_CASE("a cmap cannot make the buffer grow without bound")
	{
		/*
		 * This is the shape the ceiling exists for: every code in the run
		 * resolves to a mapping many times longer than the code itself, so how
		 * big the content stream is says nothing about how big the page is.
		 */
		std::string dest;

		for (int i = 0; i < 32; i++) {
			dest += "0061";
		}

		auto cm = cmap::parse("begincmap\n1 begincodespacerange\n<0000> <ffff>\n"
							  "endcodespacerange\n1 beginbfchar\n<0041> <" +
							  dest + ">\nendbfchar\nendcmap\n");

		REQUIRE(cm.has_value());

		text_builder b{0, 100};
		b.set_cmap(&cm.value());

		std::string codes;

		for (int i = 0; i < 1000; i++) {
			codes.append("\x00\x41", 2);
		}

		b.add_encoded(codes);

		CHECK(b.size() <= 100);
		CHECK(b.truncated());
	}
}
