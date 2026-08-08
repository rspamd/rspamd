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

#include "contrib/ankerl/unordered_dense.h"

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

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
 * A /ToUnicode CMap.
 *
 * A composite (Type0) font addresses glyphs by index, so its character codes
 * carry no meaning of their own and only the /ToUnicode CMap the producer
 * embedded can turn them back into text. A CMap is a small PostScript program
 * of which three constructs matter:
 *
 *   1 begincodespacerange <0000> <ffff> endcodespacerange   -- code widths
 *   2 beginbfchar <0003> <0020> ... endbfchar               -- single codes
 *   1 beginbfrange <0025> <0027> <0042> endbfrange          -- runs of codes
 *
 * Destinations are UTF-16BE, so one code may expand to several characters (a
 * ligature) or to a surrogate pair. The input is hostile, so the tables are
 * capped; a CMap that exceeds a cap keeps the mappings that fitted.
 */
class cmap {
public:
	static constexpr std::size_t max_codespaces = 64;
	static constexpr std::size_t max_singles = 65536;
	static constexpr std::size_t max_ranges = 8192;
	/* A range whose destination is more than one character is expanded */
	static constexpr std::size_t max_range_expansion = 256;

	/**
	 * Parses an embedded CMap program. Returns nothing if the input is not a
	 * CMap, or maps nothing usable.
	 */
	static auto parse(std::string_view program) -> std::optional<cmap>;

	/**
	 * Length in bytes of the code starting the input, from the codespace
	 * ranges. Never 0 for a non-empty input, so a walk always progresses.
	 */
	[[nodiscard]] auto code_length(std::string_view input) const noexcept -> std::size_t;

	/**
	 * UTF-8 for one code, empty when unmapped. A code covered by a range is
	 * built into the caller's scratch, so the result is valid until that
	 * scratch is reused.
	 */
	[[nodiscard]] auto lookup(std::uint32_t code, glyph_utf8 &scratch) const noexcept
		-> std::string_view;

	[[nodiscard]] auto empty() const noexcept -> bool
	{
		return singles.empty() && ranges.empty();
	}

	/** How many codes are mapped, counting a range as its length. */
	[[nodiscard]] auto size() const noexcept -> std::size_t;

private:
	struct codespace {
		std::uint32_t low;
		std::uint32_t high;
		std::uint8_t nbytes;
	};

	/* A run of codes whose destinations are consecutive single characters */
	struct range {
		std::uint32_t low;
		std::uint32_t high;
		char32_t first_uc;
	};

	auto note_code_width(std::size_t nbytes) noexcept -> void;
	auto add_single(std::uint32_t code, std::string &&utf8) -> bool;
	auto add_range(std::uint32_t low, std::uint32_t high, char32_t first_uc) -> bool;
	auto finalise() -> void;

	std::vector<codespace> codespaces;
	ankerl::unordered_dense::map<std::uint32_t, std::string> singles;
	std::vector<range> ranges;
	/* Used when a CMap declares no codespace at all */
	std::uint8_t default_nbytes = 2;
	/* Widest source code seen, in bytes, which is what sets the code width */
	std::uint8_t widest_code_bytes = 0;
};

/**
 * Accumulates decoded text into a single buffer. The intended use is one
 * builder per page: set_encoding() or set_cmap() on every Tf, add_*() on every
 * text operator, then hand the whole buffer over at the end.
 */
class text_builder {
public:
	explicit text_builder(std::size_t reserve = 0);

	/**
	 * The simple font encoding used by subsequent add_encoded()/add_pdf_*()
	 * calls. Clears any CMap: a font is decoded one way or the other.
	 */
	auto set_encoding(const font_encoding *enc) noexcept -> void
	{
		cur_encoding = enc;
		cur_cmap = nullptr;
	}

	/**
	 * The /ToUnicode CMap used by subsequent add_encoded()/add_pdf_*() calls,
	 * for a composite font whose codes are glyph indices. Clears any simple
	 * encoding.
	 */
	auto set_cmap(const cmap *cm) noexcept -> void
	{
		cur_cmap = cm;
		cur_encoding = nullptr;
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
	/* Decodes a run through the current CMap, whose codes may be multi byte */
	auto add_cmapped(std::string_view codes) -> void;
	/* Dispatches a run of codes to whichever decoder is current */
	auto decode_codes(std::string_view codes) -> void;

	std::string buf;
	const font_encoding *cur_encoding = nullptr;
	const cmap *cur_cmap = nullptr;
};

}// namespace rspamd::mime::pdf

#endif
