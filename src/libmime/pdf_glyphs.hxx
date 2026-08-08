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

/*
 * Decoding of PDF simple-font text into UTF-8.
 *
 * A string inside a PDF content stream is a sequence of character *codes*, not
 * characters: what each code means depends on the /Encoding of the font that
 * was current when the string was drawn. The same byte 0xe9 is Oslash in
 * StandardEncoding, e-acute in WinAnsiEncoding and Egrave in MacRomanEncoding,
 * so codes cannot be interpreted -- or charset-detected -- without knowing the
 * font.
 *
 * This unit owns the three base encodings from ISO 32000-1 Annex D plus the
 * per-font /Differences overrides, and a builder that turns a page's worth of
 * text runs into one UTF-8 buffer without an allocation per run.
 *
 * Composite (Type0/CID) fonts are out of scope: their codes are glyph indices
 * that only a /ToUnicode CMap can resolve, and that is a separate layer.
 */

#ifndef RSPAMD_PDF_GLYPHS_HXX
#define RSPAMD_PDF_GLYPHS_HXX
#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace rspamd::mime::pdf {

enum class base_encoding : std::uint8_t {
	standard,
	win_ansi,
	mac_roman,
};

/**
 * One decoded glyph, stored as UTF-8 with an explicit length so that a lookup
 * never has to measure a string. A zero length means .notdef.
 */
struct glyph_utf8 {
	char bytes[4];
	std::uint8_t len;

	[[nodiscard]] auto view() const noexcept -> std::string_view
	{
		return {bytes, len};
	}
};

/**
 * Maps a PDF encoding name (with or without the leading slash) to a base
 * encoding, e.g. "WinAnsiEncoding" or "/MacRomanEncoding".
 */
auto base_encoding_from_name(std::string_view name) -> std::optional<base_encoding>;

/**
 * Resolves a glyph name to a codepoint, as used by /Differences arrays.
 * Handles the names of the three base encodings plus the algorithmic uniXXXX
 * and uXXXX..XXXXXX forms. Returns nothing for anything else, notably the
 * gNN / cidNN / indexNN names of subset fonts, which carry no Unicode meaning.
 */
auto glyph_name_to_unicode(std::string_view name) noexcept -> std::optional<char32_t>;

/**
 * The encoding of one font: a base table plus optional per-code overrides.
 * Cheap to copy-construct from a base encoding; the override table is only
 * allocated once /Differences is actually applied.
 */
class font_encoding {
public:
	explicit font_encoding(base_encoding base = base_encoding::standard) noexcept;

	/**
	 * Applies one /Differences entry. Returns false if the glyph name has no
	 * Unicode meaning, in which case the code is left mapped to .notdef rather
	 * than to a wrong character.
	 */
	auto set_difference(unsigned char code, std::string_view glyph_name) -> bool;

	/** UTF-8 for a character code, empty if the code is .notdef. */
	[[nodiscard]] auto lookup(unsigned char code) const noexcept -> std::string_view;

	[[nodiscard]] auto has_differences() const noexcept -> bool
	{
		return static_cast<bool>(overrides);
	}

private:
	const glyph_utf8 *base_table;
	std::unique_ptr<std::array<glyph_utf8, 256>> overrides;
};

/**
 * Accumulates decoded text into a single buffer. The intended use is one
 * builder per page: set_encoding() on every Tf, add_*() on every text operator,
 * then hand the whole buffer over at the end.
 */
class text_builder {
public:
	explicit text_builder(std::size_t reserve = 0);

	/** The encoding used by subsequent add_encoded()/add_pdf_*() calls. */
	auto set_encoding(const font_encoding *enc) noexcept -> void
	{
		cur_encoding = enc;
	}

	/** Raw character codes, mapped through the current encoding. */
	auto add_encoded(std::string_view codes) -> void;

	/**
	 * A literal string as it appears between parentheses, still escaped.
	 * Unescaping and mapping happen in one pass.
	 */
	auto add_pdf_string(std::string_view raw) -> void;

	/** A hex string as it appears between angle brackets, without them. */
	auto add_pdf_hexstring(std::string_view raw) -> void;

	/**
	 * Text that is already UTF-8, e.g. a UTF-16 string decoded by the caller.
	 * Validated before it is appended, so that one bad run cannot make the
	 * whole page buffer invalid; returns false and appends nothing if it is not
	 * well formed.
	 */
	auto add_utf8(std::string_view utf8) -> bool;

	/** A structural ASCII character produced by an operator, not by a glyph. */
	auto add_char(char c) -> void;

	[[nodiscard]] auto data() const noexcept -> std::string_view
	{
		return {buf.data(), buf.size()};
	}

	[[nodiscard]] auto size() const noexcept -> std::size_t
	{
		return buf.size();
	}

	[[nodiscard]] auto empty() const noexcept -> bool
	{
		return buf.empty();
	}

	auto clear() -> void
	{
		buf.clear();
	}

	/** Moves the accumulated buffer out, leaving the builder empty. */
	auto release() -> std::string
	{
		return std::move(buf);
	}

private:
	auto add_code(unsigned char code) -> void;

	std::string buf;
	const font_encoding *cur_encoding = nullptr;
};

}// namespace rspamd::mime::pdf

#endif
