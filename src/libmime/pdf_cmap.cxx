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

#include "unicode/uchar.h"
#include "unicode/utf8.h"
#include "unicode/utf16.h"

#include <algorithm>
#include <utility>

namespace rspamd::mime::pdf {

namespace {

/* A CMap program is PostScript, of which only these tokens matter here */
enum class token_type {
	eof,
	hex_string,  /* <0041> */
	number,      /* 1 */
	keyword,     /* beginbfchar */
	array_start, /* [ */
	array_end,   /* ] */
	other,       /* names, dictionaries, literal strings: skipped */
};

struct token {
	token_type type = token_type::eof;
	std::string_view text; /* keyword or number text */
	std::string bytes;     /* decoded hex string */
};

class lexer {
public:
	explicit lexer(std::string_view in)
		: input(in)
	{
	}

	auto next() -> token;

private:
	auto skip_space() -> void;

	std::string_view input;
	std::size_t pos = 0;
};

auto lexer::skip_space() -> void
{
	while (pos < input.size()) {
		auto c = input[pos];

		if (c == '%') {
			/* A comment runs to the end of the line */
			while (pos < input.size() && input[pos] != '\n' && input[pos] != '\r') {
				pos++;
			}
		}
		else if (g_ascii_isspace(c) || c == '\0') {
			pos++;
		}
		else {
			break;
		}
	}
}

auto lexer::next() -> token
{
	skip_space();

	token tok;

	if (pos >= input.size()) {
		return tok;
	}

	auto c = input[pos];

	if (c == '<') {
		pos++;

		/* A dictionary, not a hex string */
		if (pos < input.size() && input[pos] == '<') {
			pos++;
			tok.type = token_type::other;

			return tok;
		}

		tok.type = token_type::hex_string;
		int hi = -1;

		while (pos < input.size() && input[pos] != '>') {
			auto v = g_ascii_xdigit_value(input[pos]);
			pos++;

			if (v < 0) {
				continue;
			}

			if (hi < 0) {
				hi = v;
			}
			else {
				tok.bytes.push_back(static_cast<char>((hi << 4) | v));
				hi = -1;
			}
		}

		if (hi >= 0) {
			/* Odd digit count: the last one is padded, as in a PDF hex string */
			tok.bytes.push_back(static_cast<char>(hi << 4));
		}

		if (pos < input.size()) {
			pos++; /* '>' */
		}

		return tok;
	}

	if (c == '[') {
		pos++;
		tok.type = token_type::array_start;

		return tok;
	}

	if (c == ']') {
		pos++;
		tok.type = token_type::array_end;

		return tok;
	}

	if (c == '(') {
		/* Literal string: skip it, honouring nesting and escapes */
		pos++;
		int depth = 1;

		while (pos < input.size() && depth > 0) {
			if (input[pos] == '\\') {
				pos++;
			}
			else if (input[pos] == '(') {
				depth++;
			}
			else if (input[pos] == ')') {
				depth--;
			}

			pos++;
		}

		tok.type = token_type::other;

		return tok;
	}

	auto start = pos;

	if (g_ascii_isdigit(c) || c == '-' || c == '+') {
		while (pos < input.size() && (g_ascii_isdigit(input[pos]) || input[pos] == '.' ||
									  input[pos] == '-' || input[pos] == '+')) {
			pos++;
		}

		tok.type = token_type::number;
		tok.text = input.substr(start, pos - start);

		return tok;
	}

	if (g_ascii_isalpha(c)) {
		while (pos < input.size() && (g_ascii_isalnum(input[pos]) || input[pos] == '_')) {
			pos++;
		}

		tok.type = token_type::keyword;
		tok.text = input.substr(start, pos - start);

		return tok;
	}

	/* Names, delimiters and anything else: one character, ignored */
	pos++;
	tok.type = token_type::other;

	return tok;
}

/* Big endian bytes of a code, as CMaps write them */
auto bytes_to_code(std::string_view bytes) noexcept -> std::uint32_t
{
	std::uint32_t code = 0;

	for (auto c: bytes) {
		code = (code << 8) | static_cast<unsigned char>(c);
	}

	return code;
}

/*
 * A destination is UTF-16BE: transcode it, resolving surrogate pairs. Returns
 * the number of characters produced, so a caller can tell a plain single
 * character from something it cannot increment over a range.
 */
auto utf16be_to_utf8(std::string_view bytes, std::string &out, char32_t *single) -> std::size_t
{
	std::size_t nchars = 0;
	char32_t last = 0;

	for (std::size_t i = 0; i + 1 < bytes.size(); i += 2) {
		char32_t uc = (static_cast<unsigned char>(bytes[i]) << 8) |
					  static_cast<unsigned char>(bytes[i + 1]);

		if (U16_IS_LEAD(uc) && i + 3 < bytes.size()) {
			char32_t trail = (static_cast<unsigned char>(bytes[i + 2]) << 8) |
							 static_cast<unsigned char>(bytes[i + 3]);

			if (U16_IS_TRAIL(trail)) {
				uc = U16_GET_SUPPLEMENTARY(uc, trail);
				i += 2;
			}
		}

		if (uc == 0 || !U_IS_UNICODE_CHAR(uc)) {
			continue;
		}

		char buf[4];
		int32_t off = 0;
		U8_APPEND_UNSAFE(buf, off, uc);
		out.append(buf, off);
		last = uc;
		nchars++;
	}

	if (single != nullptr) {
		*single = last;
	}

	return nchars;
}

/*
 * Transcoding UTF-16BE never yields less than half as many bytes as it consumes,
 * so a raw destination past twice the stored cap cannot end up under that cap
 * and is not worth transcoding. Anything that big is a payload the program is
 * trying to get the parser to copy, not a ligature.
 */
auto destination_too_long(std::string_view bytes) noexcept -> bool
{
	return bytes.size() > 2 * cmap::max_mapping_bytes;
}

}// namespace

auto cmap::note_code_width(std::size_t nbytes) noexcept -> void
{
	widest_code_bytes = std::max(widest_code_bytes,
								 static_cast<std::uint8_t>(std::min<std::size_t>(nbytes, 4)));
}

auto cmap::add_single(std::uint32_t code, std::size_t nbytes, std::string &&utf8) -> bool
{
	if (utf8.empty() || singles.size() >= max_singles) {
		return false;
	}

	/*
	 * Both budgets have to hold: one destination may not be a document, and a
	 * program may not stay under that limit and still make the table grow
	 * without bound by repeating it. Refusing rather than truncating keeps the
	 * table free of half characters.
	 */
	if (utf8.size() > max_mapping_bytes ||
		utf8.size() > max_total_mapping_bytes - mapping_bytes) {
		return false;
	}

	auto &slot = singles[make_key(code, nbytes)];

	/* A code declared twice replaces what it spent the first time */
	mapping_bytes -= slot.size();
	mapping_bytes += utf8.size();
	slot = std::move(utf8);

	return true;
}

auto cmap::add_range(std::uint32_t low, std::uint32_t high, char32_t first_uc,
					 std::size_t nbytes) -> bool
{
	if (low > high || ranges.size() >= max_ranges) {
		return false;
	}

	ranges.push_back({low, high, first_uc, high,
					  static_cast<std::uint8_t>(std::min<std::size_t>(nbytes, 4))});

	return true;
}

auto cmap::finalise() -> void
{
	std::sort(codespaces.begin(), codespaces.end(),
			  [](const codespace &a, const codespace &b) { return a.nbytes < b.nbytes; });

	/*
	 * Grouping the ranges by code width first means a lookup can binary search
	 * straight into the group of the width it wants, and can stop the moment it
	 * steps out of it: a range of another width is never an answer, however
	 * close its values are.
	 */
	std::sort(ranges.begin(), ranges.end(), [](const range &a, const range &b) {
		return a.nbytes != b.nbytes ? a.nbytes < b.nbytes : a.low < b.low;
	});

	std::uint32_t running_high = 0;
	std::uint8_t group = 0;

	for (auto &r: ranges) {
		if (r.nbytes != group) {
			group = r.nbytes;
			running_high = 0;
		}

		running_high = std::max(running_high, r.high);
		r.max_high = running_high;
	}

	if (codespaces.empty()) {
		/*
		 * No codespace was declared, so fall back to how wide the source codes
		 * were written: <0041> is a two byte code even though its value fits in
		 * one, and that width is what a composite font emits.
		 */
		if (widest_code_bytes > 0) {
			default_nbytes = std::min<std::uint8_t>(widest_code_bytes, 4);
		}
	}
}

auto cmap::code_length(std::string_view input) const noexcept -> std::size_t
{
	if (input.empty()) {
		return 0;
	}

	/*
	 * Codespaces are sorted by width, so the narrowest range that contains the
	 * prefix wins, which is what the CMap spec prescribes.
	 */
	for (const auto &cs: codespaces) {
		if (cs.nbytes > input.size()) {
			continue;
		}

		auto code = bytes_to_code(input.substr(0, cs.nbytes));

		if (code >= cs.low && code <= cs.high) {
			return cs.nbytes;
		}
	}

	if (!codespaces.empty()) {
		/*
		 * Outside every codespace: consume the narrowest declared width so the
		 * walk keeps moving rather than stalling on a bad byte.
		 */
		auto n = static_cast<std::size_t>(codespaces.front().nbytes);

		return std::min(n, input.size());
	}

	return std::min(static_cast<std::size_t>(default_nbytes), input.size());
}

auto cmap::lookup(std::uint32_t code, std::size_t nbytes, glyph_utf8 &scratch) const noexcept
	-> std::string_view
{
	auto it = singles.find(make_key(code, nbytes));

	if (it != singles.end()) {
		return it->second;
	}

	/*
	 * Ranges are ordered by width and then by first code, so this lands just
	 * past the last range of this width that starts at or below the code, which
	 * is the only one that can hold it unless ranges overlap.
	 */
	auto key = std::make_pair(nbytes, code);
	auto rit = std::upper_bound(
		ranges.begin(), ranges.end(), key,
		[](const std::pair<std::size_t, std::uint32_t> &k, const range &r) {
			return k.first != r.nbytes ? k.first < r.nbytes : k.second < r.low;
		});

	const range *hit = nullptr;
	std::size_t steps = 0;

	while (rit != ranges.begin()) {
		--rit;

		/* Out of the width group: no range of this width can start earlier */
		if (rit->nbytes != nbytes) {
			break;
		}

		if (code <= rit->high) {
			hit = &*rit;
			break;
		}

		/*
		 * Only an overlap can put the answer further back, and the running
		 * maximum says at once whether one is even possible. The step budget is
		 * what is left for a program built entirely out of overlaps, where the
		 * walk would otherwise cost the whole table for every character.
		 */
		if (rit->max_high < code || ++steps >= max_range_backscan) {
			break;
		}
	}

	if (hit == nullptr) {
		return {};
	}

	auto uc = static_cast<char32_t>(hit->first_uc + (code - hit->low));

	if (!U_IS_UNICODE_CHAR(uc)) {
		return {};
	}

	int32_t off = 0;
	U8_APPEND_UNSAFE(scratch.bytes, off, uc);
	scratch.len = static_cast<std::uint8_t>(off);

	return scratch.view();
}

auto cmap::size() const noexcept -> std::size_t
{
	auto total = singles.size();

	for (const auto &r: ranges) {
		total += static_cast<std::size_t>(r.high - r.low) + 1;
	}

	return total;
}

auto cmap::parse(std::string_view program) -> std::optional<cmap>
{
	lexer lex{program};
	cmap result;
	bool seen_cmap_marker = false;
	bool inherits = false;

	for (;;) {
		auto tok = lex.next();

		if (tok.type == token_type::eof) {
			break;
		}

		if (tok.type != token_type::keyword) {
			continue;
		}

		if (tok.text == "begincmap" || tok.text == "endcmap") {
			seen_cmap_marker = true;
			continue;
		}

		if (tok.text == "usecmap") {
			/*
			 * The mappings of another CMap are inherited here, and that CMap is
			 * a resource this code cannot reach. What is left in the program is
			 * only the local overrides, so honouring it would produce text that
			 * is confidently wrong wherever the base was meant to answer.
			 */
			seen_cmap_marker = true;
			inherits = true;
			continue;
		}

		if (tok.text == "begincodespacerange") {
			for (;;) {
				auto low = lex.next();

				if (low.type != token_type::hex_string) {
					break;
				}

				auto high = lex.next();

				if (high.type != token_type::hex_string || low.bytes.empty()) {
					break;
				}

				if (result.codespaces.size() < max_codespaces) {
					result.codespaces.push_back({
						bytes_to_code(low.bytes),
						bytes_to_code(high.bytes),
						static_cast<std::uint8_t>(std::min<std::size_t>(low.bytes.size(), 4)),
					});
				}
			}

			continue;
		}

		if (tok.text == "beginbfchar") {
			for (;;) {
				auto src = lex.next();

				if (src.type != token_type::hex_string) {
					break;
				}

				auto dst = lex.next();

				if (dst.type != token_type::hex_string) {
					break;
				}

				result.note_code_width(src.bytes.size());

				if (destination_too_long(dst.bytes)) {
					continue;
				}

				std::string utf8;
				utf16be_to_utf8(dst.bytes, utf8, nullptr);
				result.add_single(bytes_to_code(src.bytes), src.bytes.size(),
								  std::move(utf8));
			}

			continue;
		}

		if (tok.text == "beginbfrange") {
			for (;;) {
				auto low = lex.next();

				if (low.type != token_type::hex_string) {
					break;
				}

				auto high = lex.next();

				if (high.type != token_type::hex_string) {
					break;
				}

				result.note_code_width(low.bytes.size());

				auto lo_code = bytes_to_code(low.bytes);
				auto hi_code = bytes_to_code(high.bytes);
				auto dst = lex.next();

				if (dst.type == token_type::hex_string) {
					if (destination_too_long(dst.bytes)) {
						continue;
					}

					std::string utf8;
					char32_t single = 0;
					auto nchars = utf16be_to_utf8(dst.bytes, utf8, &single);

					if (nchars == 1) {
						/* Consecutive destinations: keep the range as a range */
						result.add_range(lo_code, hi_code, single, low.bytes.size());
					}
					else if (nchars > 1) {
						/*
						 * A multi character destination cannot simply be
						 * incremented, so expand, and only up to the cap. Such
						 * ranges are short in practice: they name ligatures.
						 */
						auto count = std::min<std::size_t>(
							static_cast<std::size_t>(hi_code - lo_code) + 1,
							max_range_expansion);

						/* The spec increments the last character of the destination */
						auto prefix = utf8.substr(0, utf8.size() - U8_LENGTH(single));

						for (std::size_t i = 0; i < count; i++) {
							auto uc = static_cast<char32_t>(single + i);

							if (!U_IS_UNICODE_CHAR(uc)) {
								break;
							}

							auto dst_utf8 = prefix;
							char buf[4];
							int32_t off = 0;
							U8_APPEND_UNSAFE(buf, off, uc);
							dst_utf8.append(buf, off);

							/*
							 * Every copy is the same size, so once one does not
							 * fit a budget none of the rest will either, and
							 * this is the loop that turns a short program into
							 * a big table.
							 */
							if (!result.add_single(lo_code + static_cast<std::uint32_t>(i),
												   low.bytes.size(), std::move(dst_utf8))) {
								break;
							}
						}
					}
				}
				else if (dst.type == token_type::array_start) {
					/* [ <0041> <0042> ... ]: one destination per code */
					std::uint32_t code = lo_code;

					for (;;) {
						auto elt = lex.next();

						if (elt.type != token_type::hex_string) {
							break;
						}

						if (code <= hi_code) {
							if (!destination_too_long(elt.bytes)) {
								std::string utf8;
								utf16be_to_utf8(elt.bytes, utf8, nullptr);
								result.add_single(code, low.bytes.size(), std::move(utf8));
							}

							code++;
						}
					}
				}
				else {
					break;
				}
			}

			continue;
		}
	}

	if (result.empty() || !seen_cmap_marker) {
		return std::nullopt;
	}

	if (inherits) {
		/* Partial text is worse than none: the caller should fall back */
		return std::nullopt;
	}

	result.finalise();

	return result;
}

}// namespace rspamd::mime::pdf

TEST_SUITE("pdf cmap")
{
	using namespace rspamd::mime::pdf;

	/* Decodes a code string the way a builder would */
	static auto decode(const cmap &cm, std::string_view codes) -> std::string
	{
		std::string out;
		glyph_utf8 scratch{};

		while (!codes.empty()) {
			auto n = cm.code_length(codes);

			if (n == 0 || n > codes.size()) {
				break;
			}

			std::uint32_t code = 0;

			for (std::size_t i = 0; i < n; i++) {
				code = (code << 8) | static_cast<unsigned char>(codes[i]);
			}

			out.append(cm.lookup(code, n, scratch));
			codes.remove_prefix(n);
		}

		return out;
	}

	TEST_CASE("a typical identity ToUnicode cmap")
	{
		auto cm = cmap::parse(R"cmap(/CIDInit /ProcSet findresource begin
12 dict begin
begincmap
/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def
/CMapName /Adobe-Identity-UCS def
/CMapType 2 def
1 begincodespacerange
<0000> <FFFF>
endcodespacerange
3 beginbfchar
<0003> <0020>
<0024> <0041>
<0025> <00E9>
endbfchar
1 beginbfrange
<0030> <0032> <0061>
endbfrange
endcmap
CMapName currentdict /CMap defineresource pop
end
end)cmap");

		REQUIRE(cm.has_value());
		CHECK(!cm->empty());

		SUBCASE("single codes")
		{
			CHECK(decode(*cm, std::string_view{"\x00\x24", 2}) == "A");
			CHECK(decode(*cm, std::string_view{"\x00\x25", 2}) == "\xc3\xa9");
			CHECK(decode(*cm, std::string_view{"\x00\x03", 2}) == " ");
		}

		SUBCASE("a range increments the destination")
		{
			CHECK(decode(*cm, std::string_view{"\x00\x30\x00\x31\x00\x32", 6}) == "abc");
		}

		SUBCASE("codes are two bytes wide, as the codespace says")
		{
			CHECK(cm->code_length(std::string_view{"\x00\x24", 2}) == 2);
			CHECK(decode(*cm, std::string_view{"\x00\x24\x00\x03\x00\x24", 6}) == "A A");
		}

		SUBCASE("unmapped codes vanish rather than becoming noise")
		{
			CHECK(decode(*cm, std::string_view{"\xff\xfd", 2}).empty());
		}
	}

	TEST_CASE("a bfrange with an array of destinations")
	{
		auto cm = cmap::parse("begincmap\n1 begincodespacerange\n<00> <ff>\n"
							  "endcodespacerange\n1 beginbfrange\n"
							  "<41> <43> [<0058> <0059> <005A>]\nendbfrange\nendcmap\n");

		REQUIRE(cm.has_value());
		CHECK(decode(*cm, "ABC") == "XYZ");
	}

	TEST_CASE("multi character and non BMP destinations")
	{
		auto cm = cmap::parse("begincmap\n1 begincodespacerange\n<0000> <ffff>\n"
							  "endcodespacerange\n2 beginbfchar\n"
							  /* an ffi ligature spelled out, and a surrogate pair */
							  "<0001> <0066006600690020>\n"
							  "<0002> <D83DDE00>\n"
							  "endbfchar\nendcmap\n");

		REQUIRE(cm.has_value());
		CHECK(decode(*cm, std::string_view{"\x00\x01", 2}) == "ffi ");
		CHECK(decode(*cm, std::string_view{"\x00\x02", 2}) == "\xf0\x9f\x98\x80");
	}

	TEST_CASE("a code is its width as well as its value")
	{
		/*
		 * Both codespaces are declared, and <41> and <0041> are distinct codes
		 * even though their numeric values agree.
		 */
		auto cm = cmap::parse("begincmap\n2 begincodespacerange\n<00> <7f>\n"
							  "<8000> <ffff>\nendcodespacerange\n"
							  "2 beginbfchar\n<41> <0058>\n<8041> <0059>\n"
							  "endbfchar\nendcmap\n");

		REQUIRE(cm.has_value());

		glyph_utf8 scratch{};
		CHECK(cm->lookup(0x41, 1, scratch) == "X");
		CHECK(cm->lookup(0x8041, 2, scratch) == "Y");
		/* The same value at the wrong width is not a mapping */
		CHECK(cm->lookup(0x41, 2, scratch).empty());
		CHECK(cm->lookup(0x8041, 1, scratch).empty());
	}

	TEST_CASE("ranges of different widths do not shadow each other")
	{
		auto cm = cmap::parse("begincmap\n2 begincodespacerange\n<00> <7f>\n"
							  "<8000> <ffff>\nendcodespacerange\n"
							  "2 beginbfrange\n<41> <43> <0061>\n"
							  "<8041> <8043> <0071>\nendbfrange\nendcmap\n");

		REQUIRE(cm.has_value());

		glyph_utf8 scratch{};
		CHECK(cm->lookup(0x42, 1, scratch) == "b");
		CHECK(cm->lookup(0x8042, 2, scratch) == "r");
		CHECK(cm->lookup(0x42, 2, scratch).empty());
	}

	TEST_CASE("one byte codespaces")
	{
		auto cm = cmap::parse("begincmap\n1 begincodespacerange\n<00> <ff>\n"
							  "endcodespacerange\n1 beginbfchar\n<41> <00E9>\n"
							  "endbfchar\nendcmap\n");

		REQUIRE(cm.has_value());
		CHECK(cm->code_length("A") == 1);
		CHECK(decode(*cm, "A") == "\xc3\xa9");
	}

	TEST_CASE("a missing codespace is guessed from the codes")
	{
		auto wide = cmap::parse("begincmap\n1 beginbfchar\n<0041> <0042>\nendbfchar\nendcmap\n");
		REQUIRE(wide.has_value());
		CHECK(wide->code_length(std::string_view{"\x00\x41", 2}) == 2);

		auto narrow = cmap::parse("begincmap\n1 beginbfchar\n<41> <0042>\nendbfchar\nendcmap\n");
		REQUIRE(narrow.has_value());
		CHECK(narrow->code_length("A") == 1);
	}

	TEST_CASE("comments and literal strings do not derail the parse")
	{
		auto cm = cmap::parse("%!PS-Adobe-3.0 Resource-CMap\nbegincmap\n"
							  "/Registry (Adobe) def % a comment with <deadbeef>\n"
							  "1 begincodespacerange\n<0000> <ffff>\nendcodespacerange\n"
							  "1 beginbfchar\n<0041> <0042>\nendbfchar\nendcmap\n");

		REQUIRE(cm.has_value());
		CHECK(decode(*cm, std::string_view{"\x00\x41", 2}) == "B");
	}

	TEST_CASE("a cmap that inherits from another is refused")
	{
		/*
		 * Only the local overrides are in the program, so answering with them
		 * alone would silently drop everything the base CMap mapped.
		 */
		auto cm = cmap::parse("begincmap\n/Adobe-Japan1-UCS2 usecmap\n"
							  "1 begincodespacerange\n<0000> <ffff>\n"
							  "endcodespacerange\n1 beginbfchar\n<0041> <0042>\n"
							  "endbfchar\nendcmap\n");

		CHECK(!cm.has_value());
	}

	TEST_CASE("input that is not a cmap is refused")
	{
		CHECK(!cmap::parse("").has_value());
		CHECK(!cmap::parse("just some text").has_value());
		/* A CMap that maps nothing is of no use either */
		CHECK(!cmap::parse("begincmap\nendcmap\n").has_value());
	}

	TEST_CASE("a truncated program does not run away")
	{
		CHECK(!cmap::parse("begincmap 1 beginbfchar <0041").has_value());
		CHECK(!cmap::parse("begincmap 1 beginbfrange <0041> <0043>").has_value());
		CHECK(!cmap::parse("begincmap 1 begincodespacerange <00").has_value());
	}

	TEST_CASE("a hostile range is capped rather than expanded")
	{
		/* A multi character destination over the whole 2 byte space */
		auto cm = cmap::parse("begincmap\n1 begincodespacerange\n<0000> <ffff>\n"
							  "endcodespacerange\n1 beginbfrange\n"
							  "<0000> <FFFF> <00410042>\nendbfrange\nendcmap\n");

		REQUIRE(cm.has_value());
		CHECK(cm->size() <= cmap::max_range_expansion);
	}

	/* Four hex digits, the way a CMap writes a two byte code */
	static auto hex4(unsigned v) -> std::string
	{
		static const char digits[] = "0123456789ABCDEF";
		std::string out;

		for (int shift = 12; shift >= 0; shift -= 4) {
			out.push_back(digits[(v >> shift) & 0xF]);
		}

		return out;
	}

	/* A destination of n times the letter a, as UTF-16BE hex */
	static auto long_destination(std::size_t nchars) -> std::string
	{
		std::string out;

		for (std::size_t i = 0; i < nchars; i++) {
			out += "0061";
		}

		return out;
	}

	TEST_CASE("a destination that is a payload rather than a character")
	{
		/*
		 * Counting entries says nothing about how big one entry is: a single
		 * bfchar can carry as many characters as the program has room for, and
		 * the parser would keep every one of them.
		 */
		auto program = std::string{"begincmap\n1 begincodespacerange\n<0000> <ffff>\n"
								   "endcodespacerange\n1 beginbfchar\n<0041> <"};
		program += long_destination(20000);
		program += ">\nendbfchar\nendcmap\n";

		/* Refused outright, and it was the only mapping, so nothing is left */
		CHECK(!cmap::parse(program).has_value());
	}

	TEST_CASE("the destination cap leaves room for any real ligature")
	{
		/*
		 * A producer spells a ligature in two or three characters; a mapping
		 * built right at the cap is already absurd, and it still has to work,
		 * because the cost of a limit set too low is text silently gone
		 * missing from mail nobody complains about.
		 */
		auto program = std::string{"begincmap\n1 begincodespacerange\n<0000> <ffff>\n"
								   "endcodespacerange\n1 beginbfchar\n<0041> <"};
		program += long_destination(cmap::max_mapping_bytes);
		program += ">\nendbfchar\nendcmap\n";

		auto cm = cmap::parse(program);

		REQUIRE(cm.has_value());
		CHECK(cm->stored_bytes() == cmap::max_mapping_bytes);
		CHECK(decode(*cm, std::string_view{"\x00\x41", 2}).size() == cmap::max_mapping_bytes);
	}

	TEST_CASE("mappings that each fit are not allowed to add up")
	{
		/*
		 * Every destination here is legal on its own, and the entry count stays
		 * under the cap; what a few dozen kilobytes of program buys is the
		 * expansion of each range into hundreds of copies of one.
		 */
		constexpr unsigned nranges = 96;
		constexpr std::size_t dest_chars = 64;

		std::string program = "begincmap\n1 begincodespacerange\n<0000> <ffff>\n"
							  "endcodespacerange\n";

		program += std::to_string(nranges) + " beginbfrange\n";

		for (unsigned i = 0; i < nranges; i++) {
			program += "<" + hex4(i * 256) + "> <" + hex4(i * 256 + 255) + "> <" +
					   long_destination(dest_chars) + ">\n";
		}

		program += "endbfrange\nendcmap\n";

		auto cm = cmap::parse(program);

		REQUIRE(cm.has_value());
		CHECK(cm->stored_bytes() <= cmap::max_total_mapping_bytes);
		/* Whatever fitted is kept; what the program asked for is not */
		CHECK(!cm->empty());
		CHECK(cm->size() < nranges * cmap::max_range_expansion);
	}

	TEST_CASE("an unmapped code does not cost a walk over the ranges")
	{
		/*
		 * A lookup happens once per character of the content stream, so a
		 * search that fell back to the front of the table on every miss would
		 * multiply a table this size by a stream of misses.
		 */
		constexpr unsigned nranges = 2048;

		std::string program = "begincmap\n1 begincodespacerange\n<0000> <ffff>\n"
							  "endcodespacerange\n";

		program += std::to_string(nranges) + " beginbfrange\n";

		for (unsigned i = 0; i < nranges; i++) {
			/* Only even codes are mapped, so the odd ones are all misses */
			program += "<" + hex4(i * 2) + "> <" + hex4(i * 2) + "> <0061>\n";
		}

		program += "endbfrange\nendcmap\n";

		auto cm = cmap::parse(program);

		REQUIRE(cm.has_value());

		glyph_utf8 scratch{};
		CHECK(cm->lookup(0x0F00, 2, scratch) == "a");
		CHECK(cm->lookup(0x0F01, 2, scratch).empty());
		/* Past everything the table covers */
		CHECK(cm->lookup(0xF000, 2, scratch).empty());
	}

	TEST_CASE("an overlapped range is still the answer")
	{
		/*
		 * Where ranges overlap, the one that answers is not the last one to
		 * start at or below the code, so the search does have to look back.
		 */
		auto cm = cmap::parse("begincmap\n1 begincodespacerange\n<0000> <ffff>\n"
							  "endcodespacerange\n3 beginbfrange\n"
							  "<0000> <001F> <0061>\n"
							  "<0002> <0003> <0041>\n"
							  "<0004> <0005> <0058>\n"
							  "endbfrange\nendcmap\n");

		REQUIRE(cm.has_value());

		glyph_utf8 scratch{};
		/* The narrow ranges win where they reach */
		CHECK(cm->lookup(0x0002, 2, scratch) == "A");
		CHECK(cm->lookup(0x0004, 2, scratch) == "X");
		/* And the wide one answers past them, two steps back */
		CHECK(cm->lookup(0x0010, 2, scratch) == "q");
		/* Past the wide range there is nothing to look back for */
		CHECK(cm->lookup(0x0030, 2, scratch).empty());
	}

	TEST_CASE("a table built entirely out of overlaps gives up rather than walks")
	{
		/*
		 * Overlapping every range with every other is the one shape where
		 * looking back is unbounded work, and it is a shape no producer emits.
		 * Answering the first few and then declining is the trade: a code this
		 * deep under the pile loses its character, which beats spending the
		 * whole table on every character of the stream.
		 */
		constexpr unsigned nnested = cmap::max_range_backscan * 2;

		std::string program = "begincmap\n1 begincodespacerange\n<0000> <ffff>\n"
							  "endcodespacerange\n";

		program += std::to_string(nnested + 1) + " beginbfrange\n";
		/* One range under everything, which only a full walk back would reach */
		program += "<0000> <0FFF> <0061>\n";

		for (unsigned i = 1; i <= nnested; i++) {
			program += "<" + hex4(i) + "> <" + hex4(i) + "> <0041>\n";
		}

		program += "endbfrange\nendcmap\n";

		auto cm = cmap::parse(program);

		REQUIRE(cm.has_value());

		glyph_utf8 scratch{};
		/* What the nested ranges cover is found at once */
		CHECK(cm->lookup(0x0001, 2, scratch) == "A");
		/* What only the buried range covers is beyond the step budget */
		CHECK(cm->lookup(0x0800, 2, scratch).empty());
	}
}
