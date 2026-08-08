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

#include "lua_common.h"
#include "lua_classnames.h"

/***
 * @module rspamd_pdf_text
 * Decoding of PDF simple-font text into UTF-8.
 *
 * A string in a PDF content stream is a sequence of character codes whose
 * meaning depends on the /Encoding of the font that drew it: the byte 0xe9 is
 * Oslash in StandardEncoding, e-acute in WinAnsiEncoding and Egrave in
 * MacRomanEncoding. This module exposes the encoding tables and a builder that
 * accumulates a page worth of runs into a single buffer, so that unescaping,
 * decoding and concatenation happen in C rather than through a chain of Lua
 * string rewrites.
 *
 * @example
 * local pdf_text = require "rspamd_pdf_text"
 *
 * local enc = pdf_text.encoding('WinAnsiEncoding')
 * enc:apply_differences({65, 'eacute', 'germandbls'})
 *
 * local b = pdf_text.builder()
 * b:set_encoding(enc)            -- on every Tf
 * b:add_string("caf\\351")       -- literal string, still escaped
 * b:add_hexstring("636166E9")    -- hex string
 * local txt = b:finish()         -- rspamd_text, builder is left empty
 */

#include "libmime/pdf_glyphs.hxx"

#include <memory>
#include <new>

#define PDF_ENCODING_CLASS rspamd_pdf_encoding_classname
#define PDF_TEXT_BUILDER_CLASS rspamd_pdf_text_builder_classname
#define PDF_CMAP_CLASS rspamd_pdf_cmap_classname

using namespace rspamd::mime;

LUA_FUNCTION_DEF(pdf_text, encoding);
LUA_FUNCTION_DEF(pdf_text, cmap);
LUA_FUNCTION_DEF(pdf_text, builder);

LUA_FUNCTION_DEF(pdf_cmap, size);
LUA_FUNCTION_DEF(pdf_cmap, dtor);

LUA_FUNCTION_DEF(pdf_encoding, set_difference);
LUA_FUNCTION_DEF(pdf_encoding, apply_differences);
LUA_FUNCTION_DEF(pdf_encoding, dtor);

LUA_FUNCTION_DEF(pdf_text_builder, set_encoding);
LUA_FUNCTION_DEF(pdf_text_builder, set_cmap);
LUA_FUNCTION_DEF(pdf_text_builder, add_string);
LUA_FUNCTION_DEF(pdf_text_builder, add_hexstring);
LUA_FUNCTION_DEF(pdf_text_builder, add_encoded);
LUA_FUNCTION_DEF(pdf_text_builder, add_utf8);
LUA_FUNCTION_DEF(pdf_text_builder, add_char);
LUA_FUNCTION_DEF(pdf_text_builder, len);
LUA_FUNCTION_DEF(pdf_text_builder, finish);
LUA_FUNCTION_DEF(pdf_text_builder, dtor);

static const struct luaL_reg pdf_textlib_f[] = {
	LUA_INTERFACE_DEF(pdf_text, encoding),
	LUA_INTERFACE_DEF(pdf_text, cmap),
	LUA_INTERFACE_DEF(pdf_text, builder),
	{nullptr, nullptr},
};

static const struct luaL_reg pdf_cmaplib_m[] = {
	LUA_INTERFACE_DEF(pdf_cmap, size),
	{"__gc", lua_pdf_cmap_dtor},
	{"__tostring", rspamd_lua_class_tostring},
	{nullptr, nullptr},
};

static const struct luaL_reg pdf_encodinglib_m[] = {
	LUA_INTERFACE_DEF(pdf_encoding, set_difference),
	LUA_INTERFACE_DEF(pdf_encoding, apply_differences),
	{"__gc", lua_pdf_encoding_dtor},
	{"__tostring", rspamd_lua_class_tostring},
	{nullptr, nullptr},
};

static const struct luaL_reg pdf_text_builderlib_m[] = {
	LUA_INTERFACE_DEF(pdf_text_builder, set_encoding),
	LUA_INTERFACE_DEF(pdf_text_builder, set_cmap),
	LUA_INTERFACE_DEF(pdf_text_builder, add_string),
	LUA_INTERFACE_DEF(pdf_text_builder, add_hexstring),
	LUA_INTERFACE_DEF(pdf_text_builder, add_encoded),
	LUA_INTERFACE_DEF(pdf_text_builder, add_utf8),
	LUA_INTERFACE_DEF(pdf_text_builder, add_char),
	LUA_INTERFACE_DEF(pdf_text_builder, len),
	LUA_INTERFACE_DEF(pdf_text_builder, finish),
	{"__gc", lua_pdf_text_builder_dtor},
	{"__tostring", rspamd_lua_class_tostring},
	{nullptr, nullptr},
};

namespace {

/*
 * A builder keeps a reference to the encoding object it was last given, so that
 * Lua cannot collect an encoding that the builder still points at.
 */
struct lua_pdf_builder {
	pdf::text_builder builder;
	/* Whichever decoder object the builder currently points at */
	int decoder_ref = LUA_NOREF;

	explicit lua_pdf_builder(std::size_t reserve)
		: builder(reserve)
	{
	}
};

auto lua_check_pdf_encoding(lua_State *L, int pos) -> pdf::font_encoding *
{
	auto **penc = static_cast<pdf::font_encoding **>(
		rspamd_lua_check_udata(L, pos, PDF_ENCODING_CLASS));
	luaL_argcheck(L, penc != nullptr && *penc != nullptr, pos,
				  "'rspamd{pdf_encoding}' expected");

	return *penc;
}

auto lua_check_pdf_cmap(lua_State *L, int pos) -> pdf::cmap *
{
	auto **pcm = static_cast<pdf::cmap **>(
		rspamd_lua_check_udata(L, pos, PDF_CMAP_CLASS));
	luaL_argcheck(L, pcm != nullptr && *pcm != nullptr, pos,
				  "'rspamd{pdf_cmap}' expected");

	return *pcm;
}

auto lua_check_pdf_builder(lua_State *L, int pos) -> lua_pdf_builder *
{
	auto **pb = static_cast<lua_pdf_builder **>(
		rspamd_lua_check_udata(L, pos, PDF_TEXT_BUILDER_CLASS));
	luaL_argcheck(L, pb != nullptr && *pb != nullptr, pos,
				  "'rspamd{pdf_text_builder}' expected");

	return *pb;
}

/* Accepts a string or an rspamd_text, since the pdf parser produces both */
auto lua_check_bytes(lua_State *L, int pos) -> std::string_view
{
	auto *t = lua_check_text_or_string(L, pos);

	if (t == nullptr) {
		return {};
	}

	return {t->start, t->len};
}

}// namespace

/***
 * @function rspamd_pdf_text.encoding(name)
 * Creates a font encoding from one of the base encoding names of ISO 32000-1
 * Annex D: StandardEncoding, WinAnsiEncoding or MacRomanEncoding. The leading
 * slash of a PDF name is optional.
 * @param {string} name base encoding name
 * @return {rspamd_pdf_encoding|nil} encoding, or nil and an error message
 */
static int
lua_pdf_text_encoding(lua_State *L)
{
	LUA_TRACE_POINT;
	const char *name = luaL_checkstring(L, 1);
	auto base = pdf::base_encoding_from_name(name);

	if (!base) {
		lua_pushnil(L);
		lua_pushstring(L, "unknown base encoding");

		return 2;
	}

	auto **penc = static_cast<pdf::font_encoding **>(
		lua_newuserdata(L, sizeof(pdf::font_encoding *)));
	*penc = new pdf::font_encoding{*base};
	rspamd_lua_setclass(L, PDF_ENCODING_CLASS, -1);

	return 1;
}

/***
 * @method encoding:set_difference(code, glyph_name)
 * Overrides one character code with a named glyph.
 * @param {number} code character code, 0 to 255
 * @param {string} glyph_name glyph name, with or without the leading slash
 * @return {boolean} false if the name carries no character, e.g. g42 or cid7
 */
static int
lua_pdf_encoding_set_difference(lua_State *L)
{
	LUA_TRACE_POINT;
	auto *enc = lua_check_pdf_encoding(L, 1);
	auto code = luaL_checkinteger(L, 2);
	const char *glyph = luaL_checkstring(L, 3);

	if (code < 0 || code > 255) {
		return luaL_error(L, "character code out of range: %d", (int) code);
	}

	lua_pushboolean(L, enc->set_difference(static_cast<unsigned char>(code), glyph));

	return 1;
}

/***
 * @method encoding:apply_differences(array)
 * Applies a /Differences array in its PDF form: a number sets the code of the
 * glyph name that follows it, and each further name takes the next code.
 * @param {table} array mixed array of numbers and glyph names
 * @return {number} how many codes were actually mapped
 */
static int
lua_pdf_encoding_apply_differences(lua_State *L)
{
	LUA_TRACE_POINT;
	auto *enc = lua_check_pdf_encoding(L, 1);

	if (lua_type(L, 2) != LUA_TTABLE) {
		return luaL_error(L, "table expected");
	}

	int applied = 0;
	long code = -1;
	auto nelts = rspamd_lua_table_size(L, 2);

	for (int i = 1; i <= nelts; i++) {
		lua_rawgeti(L, 2, i);

		if (lua_type(L, -1) == LUA_TNUMBER) {
			code = (long) lua_tointeger(L, -1);
		}
		else if (lua_type(L, -1) == LUA_TSTRING) {
			/* Names before the first code, or past the end, have nowhere to go */
			if (code >= 0 && code <= 255) {
				if (enc->set_difference(static_cast<unsigned char>(code),
										lua_tostring(L, -1))) {
					applied++;
				}
			}

			if (code >= 0) {
				code++;
			}
		}

		lua_pop(L, 1);
	}

	lua_pushinteger(L, applied);

	return 1;
}

static int
lua_pdf_encoding_dtor(lua_State *L)
{
	auto **penc = static_cast<pdf::font_encoding **>(
		rspamd_lua_check_udata(L, 1, PDF_ENCODING_CLASS));

	if (penc != nullptr && *penc != nullptr) {
		delete *penc;
		*penc = nullptr;
	}

	return 0;
}

/***
 * @function rspamd_pdf_text.cmap(data)
 * Parses an embedded /ToUnicode CMap, the only thing that can turn the glyph
 * indices of a composite font back into text.
 * @param {string|rspamd_text} data CMap program, as found in the stream
 * @return {rspamd_pdf_cmap|nil} cmap, or nil and an error message
 */
static int
lua_pdf_text_cmap(lua_State *L)
{
	LUA_TRACE_POINT;
	auto data = lua_check_bytes(L, 1);
	auto parsed = pdf::cmap::parse(data);

	if (!parsed) {
		lua_pushnil(L);
		lua_pushstring(L, "not a usable cmap");

		return 2;
	}

	auto **pcm = static_cast<pdf::cmap **>(lua_newuserdata(L, sizeof(pdf::cmap *)));
	*pcm = new pdf::cmap{std::move(*parsed)};
	rspamd_lua_setclass(L, PDF_CMAP_CLASS, -1);

	return 1;
}

/***
 * @method cmap:size()
 * @return {number} how many codes the cmap maps
 */
static int
lua_pdf_cmap_size(lua_State *L)
{
	LUA_TRACE_POINT;
	auto *cm = lua_check_pdf_cmap(L, 1);

	lua_pushinteger(L, (lua_Integer) cm->size());

	return 1;
}

static int
lua_pdf_cmap_dtor(lua_State *L)
{
	auto **pcm = static_cast<pdf::cmap **>(
		rspamd_lua_check_udata(L, 1, PDF_CMAP_CLASS));

	if (pcm != nullptr && *pcm != nullptr) {
		delete *pcm;
		*pcm = nullptr;
	}

	return 0;
}

/***
 * @function rspamd_pdf_text.builder([reserve])
 * Creates a text builder. One builder per page keeps the whole page in a single
 * buffer.
 * @param {number} reserve optional number of bytes to reserve up front
 * @return {rspamd_pdf_text_builder} builder
 */
static int
lua_pdf_text_builder(lua_State *L)
{
	LUA_TRACE_POINT;
	std::size_t reserve = 0;

	if (lua_type(L, 1) == LUA_TNUMBER) {
		auto n = lua_tointeger(L, 1);

		if (n > 0) {
			reserve = (std::size_t) n;
		}
	}

	auto **pb = static_cast<lua_pdf_builder **>(
		lua_newuserdata(L, sizeof(lua_pdf_builder *)));
	*pb = new lua_pdf_builder{reserve};
	rspamd_lua_setclass(L, PDF_TEXT_BUILDER_CLASS, -1);

	return 1;
}

/*
 * Anchors the decoder the builder now points at, releasing the previous one, so
 * that Lua cannot collect an object the C++ side still dereferences.
 */
static void
lua_pdf_builder_anchor(lua_State *L, struct lua_pdf_builder *b, int pos)
{
	if (b->decoder_ref != LUA_NOREF) {
		luaL_unref(L, LUA_REGISTRYINDEX, b->decoder_ref);
		b->decoder_ref = LUA_NOREF;
	}

	if (pos != 0) {
		lua_pushvalue(L, pos);
		b->decoder_ref = luaL_ref(L, LUA_REGISTRYINDEX);
	}
}

/***
 * @method builder:set_encoding(encoding)
 * Selects the simple font encoding used by the following add_* calls, as the Tf
 * operator does in a content stream. Passing nil restores StandardEncoding.
 * @param {rspamd_pdf_encoding|nil} encoding font encoding
 */
static int
lua_pdf_text_builder_set_encoding(lua_State *L)
{
	LUA_TRACE_POINT;
	auto *b = lua_check_pdf_builder(L, 1);

	if (lua_gettop(L) < 2 || lua_type(L, 2) == LUA_TNIL) {
		lua_pdf_builder_anchor(L, b, 0);
		b->builder.set_encoding(nullptr);

		return 0;
	}

	auto *enc = lua_check_pdf_encoding(L, 2);
	b->builder.set_encoding(enc);
	lua_pdf_builder_anchor(L, b, 2);

	return 0;
}

/***
 * @method builder:set_cmap(cmap)
 * Selects a /ToUnicode CMap for the following add_* calls, for a composite font
 * whose codes are glyph indices. Passing nil goes back to the simple font path.
 * @param {rspamd_pdf_cmap|nil} cmap parsed cmap
 */
static int
lua_pdf_text_builder_set_cmap(lua_State *L)
{
	LUA_TRACE_POINT;
	auto *b = lua_check_pdf_builder(L, 1);

	if (lua_gettop(L) < 2 || lua_type(L, 2) == LUA_TNIL) {
		lua_pdf_builder_anchor(L, b, 0);
		b->builder.set_cmap(nullptr);

		return 0;
	}

	auto *cm = lua_check_pdf_cmap(L, 2);
	b->builder.set_cmap(cm);
	lua_pdf_builder_anchor(L, b, 2);

	return 0;
}

/***
 * @method builder:add_string(raw)
 * Appends a literal string as it appears between parentheses, still escaped.
 * Unescaping and decoding happen in one pass.
 * @param {string|rspamd_text} raw string contents without the parentheses
 */
static int
lua_pdf_text_builder_add_string(lua_State *L)
{
	LUA_TRACE_POINT;
	auto *b = lua_check_pdf_builder(L, 1);

	b->builder.add_pdf_string(lua_check_bytes(L, 2));

	return 0;
}

/***
 * @method builder:add_hexstring(raw)
 * Appends a hex string as it appears between angle brackets, without them.
 * @param {string|rspamd_text} raw hex digits, whitespace allowed
 */
static int
lua_pdf_text_builder_add_hexstring(lua_State *L)
{
	LUA_TRACE_POINT;
	auto *b = lua_check_pdf_builder(L, 1);

	b->builder.add_pdf_hexstring(lua_check_bytes(L, 2));

	return 0;
}

/***
 * @method builder:add_encoded(codes)
 * Appends already unescaped character codes, decoding them through the current
 * encoding.
 * @param {string|rspamd_text} codes character codes
 */
static int
lua_pdf_text_builder_add_encoded(lua_State *L)
{
	LUA_TRACE_POINT;
	auto *b = lua_check_pdf_builder(L, 1);

	b->builder.add_encoded(lua_check_bytes(L, 2));

	return 0;
}

/***
 * @method builder:add_utf8(text)
 * Appends text that is already UTF-8, such as a UTF-16 string the caller has
 * converted. The input is validated, so a malformed run cannot make the page
 * buffer invalid.
 * @param {string|rspamd_text} text UTF-8 text
 * @return {boolean} false if the text was not well formed UTF-8, in which case
 * nothing was appended
 */
static int
lua_pdf_text_builder_add_utf8(lua_State *L)
{
	LUA_TRACE_POINT;
	auto *b = lua_check_pdf_builder(L, 1);

	lua_pushboolean(L, b->builder.add_utf8(lua_check_bytes(L, 2)));

	return 1;
}

/***
 * @method builder:add_char(c)
 * Appends one structural character produced by an operator rather than by a
 * glyph, e.g. the space of a TJ offset or the newline of T*.
 * @param {string} c single character
 */
static int
lua_pdf_text_builder_add_char(lua_State *L)
{
	LUA_TRACE_POINT;
	auto *b = lua_check_pdf_builder(L, 1);
	gsize len;
	const char *s = luaL_checklstring(L, 2, &len);

	if (len != 1) {
		return luaL_error(L, "a single character expected");
	}

	b->builder.add_char(*s);

	return 0;
}

/***
 * @method builder:len()
 * @return {number} bytes accumulated so far
 */
static int
lua_pdf_text_builder_len(lua_State *L)
{
	LUA_TRACE_POINT;
	auto *b = lua_check_pdf_builder(L, 1);

	lua_pushinteger(L, (lua_Integer) b->builder.size());

	return 1;
}

/***
 * @method builder:finish()
 * Returns everything accumulated so far as a text object and empties the
 * builder, which can then be reused for the next page.
 * @return {rspamd_text} decoded UTF-8 text
 */
static int
lua_pdf_text_builder_finish(lua_State *L)
{
	LUA_TRACE_POINT;
	auto *b = lua_check_pdf_builder(L, 1);
	auto data = b->builder.data();

	lua_new_text(L, data.data(), data.size(), TRUE);
	b->builder.clear();

	return 1;
}

static int
lua_pdf_text_builder_dtor(lua_State *L)
{
	auto **pb = static_cast<lua_pdf_builder **>(
		rspamd_lua_check_udata(L, 1, PDF_TEXT_BUILDER_CLASS));

	if (pb != nullptr && *pb != nullptr) {
		if ((*pb)->decoder_ref != LUA_NOREF) {
			luaL_unref(L, LUA_REGISTRYINDEX, (*pb)->decoder_ref);
		}

		delete *pb;
		*pb = nullptr;
	}

	return 0;
}

void luaopen_pdf_text(lua_State *L)
{
	rspamd_lua_new_class(L, PDF_ENCODING_CLASS, pdf_encodinglib_m);
	lua_pop(L, 1);
	rspamd_lua_new_class(L, PDF_CMAP_CLASS, pdf_cmaplib_m);
	lua_pop(L, 1);
	rspamd_lua_new_class(L, PDF_TEXT_BUILDER_CLASS, pdf_text_builderlib_m);
	lua_pop(L, 1);

	rspamd_lua_add_preload(L, "rspamd_pdf_text", [](lua_State *LL) -> int {
		luaL_register(LL, "rspamd_pdf_text", pdf_textlib_f);
		return 1;
	});
}
