/*
 * Copyright (c) 2015, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "lua_common.h"
#include "message.h"
#include "diff.h"

/* Textpart methods */
/***
 * @module rspamd_textpart
 * This module provides different methods to manipulate text parts data. Text parts
 * could be obtained from the `rspamd_task` by using of method `task:get_text_parts()`
@example
rspamd_config.R_EMPTY_IMAGE = function (task)
	parts = task:get_text_parts()
	if parts then
		for _,part in ipairs(parts) do
			if part:is_empty() then
				images = task:get_images()
				if images then
					return true
				end
				return false
			end
		end
	end
	return false
end
 */

/***
 * @method text_part:is_utf()
 * Return TRUE if part is a valid utf text
 * @return {boolean} true if part is valid `UTF8` part
 */
LUA_FUNCTION_DEF (textpart, is_utf);
/***
 * @method text_part:get_content()
 * Get the text of the part
 * @return {text} `UTF8` encoded content of the part (zero-copy if not converted to a lua string)
 */
LUA_FUNCTION_DEF (textpart, get_content);
/***
 * @method text_part:get_length()
 * Get length of the text of the part
 * @return {integer} length of part in **bytes**
 */
LUA_FUNCTION_DEF (textpart, get_length);
/***
 * @method mime_part:get_lines_count()
 * Get lines number in the part
 * @return {integer} number of lines in the part
 */
LUA_FUNCTION_DEF (textpart, get_lines_count);
/***
 * @method text_part:is_empty()
 * Returns `true` if the specified part is empty
 * @return {bool} whether a part is empty
 */
LUA_FUNCTION_DEF (textpart, is_empty);
/***
 * @method text_part:is_html()
 * Returns `true` if the specified part has HTML content
 * @return {bool} whether a part is HTML part
 */
LUA_FUNCTION_DEF (textpart, is_html);
/***
 * @method text_part:get_fuzzy()
 * Returns base32 encoded value of fuzzy hash of the specified part
 * @return {string} fuzzy hash value
 */
LUA_FUNCTION_DEF (textpart, get_fuzzy);
/***
 * @method text_part:get_language()
 * Returns the code of the most used unicode script in the text part. Does not work with raw parts
 * @return {string} short abbreviation (such as `ru`) for the script's language
 */
LUA_FUNCTION_DEF (textpart, get_language);
/***
 * @method text_part:get_mimepart()
 * Returns the mime part object corresponding to this text part
 * @return {mimepart} mimepart object
 */
LUA_FUNCTION_DEF (textpart, get_mimepart);
/***
 * @method text_part:compare_distance(other)
 * Calculates the difference to another text part.  This function is intended to work with
 * the parts of `multipart/alternative` container only. If the two parts are not the parts of the
 * same `multipart/alternative` container, then they are considered as unrelated and
 * `-1` is returned.
 * @param {text_part} other text part to compare
 * @return {integer} commodity percentage (e.g. the same strings give `100`, different give `0` and unrelated give `-1`)
 */
LUA_FUNCTION_DEF (textpart, compare_distance);

static const struct luaL_reg textpartlib_m[] = {
	LUA_INTERFACE_DEF (textpart, is_utf),
	LUA_INTERFACE_DEF (textpart, get_content),
	LUA_INTERFACE_DEF (textpart, get_length),
	LUA_INTERFACE_DEF (textpart, get_lines_count),
	LUA_INTERFACE_DEF (textpart, is_empty),
	LUA_INTERFACE_DEF (textpart, is_html),
	LUA_INTERFACE_DEF (textpart, get_fuzzy),
	LUA_INTERFACE_DEF (textpart, get_language),
	LUA_INTERFACE_DEF (textpart, get_mimepart),
	LUA_INTERFACE_DEF (textpart, compare_distance),
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};

/* Mimepart methods */

/***
 * @module rspamd_mimepart
 * This module provides access to mime parts found in a message
@example
rspamd_config.MISSING_CONTENT_TYPE = function(task)
	local parts = task:get_parts()
	if parts and table.maxn(parts) > 1 then
		-- We have more than one part
		for _,p in ipairs(parts) do
			local ct = p:get_header('Content-Type')
			-- And some parts have no Content-Type header
			if not ct then
				return true
			end
		end
	end
	return false
end
 */

/***
 * @method mime_part:get_header(name[, case_sensitive])
 * Get decoded value of a header specified with optional case_sensitive flag.
 * By default headers are searched in caseless matter.
 * @param {string} name name of header to get
 * @param {boolean} case_sensitive case sensitiveness flag to search for a header
 * @return {string} decoded value of a header
 */
LUA_FUNCTION_DEF (mimepart, get_header);
/***
 * @method mime_part:get_header_raw(name[, case_sensitive])
 * Get raw value of a header specified with optional case_sensitive flag.
 * By default headers are searched in caseless matter.
 * @param {string} name name of header to get
 * @param {boolean} case_sensitive case sensitiveness flag to search for a header
 * @return {string} raw value of a header
 */
LUA_FUNCTION_DEF (mimepart, get_header_raw);
/***
 * @method mime_part:get_header_full(name[, case_sensitive])
 * Get raw value of a header specified with optional case_sensitive flag.
 * By default headers are searched in caseless matter. This method returns more
 * information about the header as a list of tables with the following structure:
 *
 * - `name` - name of a header
 * - `value` - raw value of a header
 * - `decoded` - decoded value of a header
 * - `tab_separated` - `true` if a header and a value are separated by `tab` character
 * - `empty_separator` - `true` if there are no separator between a header and a value
 * @param {string} name name of header to get
 * @param {boolean} case_sensitive case sensitiveness flag to search for a header
 * @return {list of tables} all values of a header as specified above
@example
function check_header_delimiter_tab(task, header_name)
	for _,rh in ipairs(task:get_header_full(header_name)) do
		if rh['tab_separated'] then return true end
	end
	return false
end
 */
LUA_FUNCTION_DEF (mimepart, get_header_full);
/***
 * @method mime_part:get_content()
 * Get the raw content of part
 * @return {text} opaque text object (zero-copy if not casted to lua string)
 */
LUA_FUNCTION_DEF (mimepart, get_content);
/***
 * @method mime_part:get_length()
 * Get length of the content of the part
 * @return {integer} length of part in **bytes**
 */
LUA_FUNCTION_DEF (mimepart, get_length);
/***
 * @method mime_part:get_type()
 * Extract content-type string of the mime part
 * @return {string} content type in form 'type/subtype'
 */
LUA_FUNCTION_DEF (mimepart, get_type);
/***
 * @method mime_part:get_filename()
 * Extract filename associated with mime part if it is an attachement
 * @return {string} filename or `nil` if no file is associated with this part
 */
LUA_FUNCTION_DEF (mimepart, get_filename);

static const struct luaL_reg mimepartlib_m[] = {
	LUA_INTERFACE_DEF (mimepart, get_content),
	LUA_INTERFACE_DEF (mimepart, get_length),
	LUA_INTERFACE_DEF (mimepart, get_type),
	LUA_INTERFACE_DEF (mimepart, get_filename),
	LUA_INTERFACE_DEF (mimepart, get_header),
	LUA_INTERFACE_DEF (mimepart, get_header_raw),
	LUA_INTERFACE_DEF (mimepart, get_header_full),
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};


static struct mime_text_part *
lua_check_textpart (lua_State * L)
{
	void *ud = luaL_checkudata (L, 1, "rspamd{textpart}");
	luaL_argcheck (L, ud != NULL, 1, "'textpart' expected");
	return ud ? *((struct mime_text_part **)ud) : NULL;
}

static struct mime_part *
lua_check_mimepart (lua_State * L)
{
	void *ud = luaL_checkudata (L, 1, "rspamd{mimepart}");
	luaL_argcheck (L, ud != NULL, 1, "'mimepart' expected");
	return ud ? *((struct mime_part **)ud) : NULL;
}


static gint
lua_textpart_is_utf (lua_State * L)
{
	struct mime_text_part *part = lua_check_textpart (L);

	if (part == NULL || IS_PART_EMPTY (part)) {
		lua_pushboolean (L, FALSE);
		return 1;
	}

	lua_pushboolean (L, IS_PART_UTF (part));

	return 1;
}


static gint
lua_textpart_get_content (lua_State * L)
{
	struct mime_text_part *part = lua_check_textpart (L);
	struct rspamd_lua_text *t;

	if (part == NULL || IS_PART_EMPTY (part)) {
		lua_pushnil (L);
		return 1;
	}

	t = lua_newuserdata (L, sizeof (*t));
	rspamd_lua_setclass (L, "rspamd{text}", -1);
	t->start = part->content->data;
	t->len = part->content->len;
	t->own = FALSE;

	return 1;
}

static gint
lua_textpart_get_length (lua_State * L)
{
	struct mime_text_part *part = lua_check_textpart (L);

	if (part == NULL) {
		lua_pushnil (L);
		return 1;
	}

	if (IS_PART_EMPTY (part)) {
		lua_pushnumber (L, 0);
	}
	else {
		lua_pushnumber (L, part->content->len);
	}

	return 1;
}

static gint
lua_textpart_get_lines_count (lua_State * L)
{
	struct mime_text_part *part = lua_check_textpart (L);

	if (part == NULL) {
		lua_pushnil (L);
		return 1;
	}

	if (IS_PART_EMPTY (part)) {
		lua_pushnumber (L, 0);
	}
	else {
		lua_pushnumber (L, part->nlines);
	}

	return 1;
}

static gint
lua_textpart_is_empty (lua_State * L)
{
	struct mime_text_part *part = lua_check_textpart (L);

	if (part == NULL) {
		lua_pushnil (L);
		return 1;
	}

	lua_pushboolean (L, IS_PART_EMPTY (part));

	return 1;
}

static gint
lua_textpart_is_html (lua_State * L)
{
	struct mime_text_part *part = lua_check_textpart (L);

	if (part == NULL) {
		lua_pushnil (L);
		return 1;
	}

	lua_pushboolean (L, IS_PART_HTML (part));

	return 1;
}

static gint
lua_textpart_get_fuzzy (lua_State * L)
{
	struct mime_text_part *part = lua_check_textpart (L);
	gchar *out;

	if (part == NULL || IS_PART_EMPTY (part)) {
		lua_pushnil (L);
		return 1;
	}

	out = rspamd_encode_base32 (part->fuzzy->hash_pipe,
			strlen (part->fuzzy->hash_pipe));
	lua_pushstring (L, out);
	g_free (out);

	return 1;
}

static gint
lua_textpart_get_language (lua_State * L)
{
	struct mime_text_part *part = lua_check_textpart (L);

	if (part != NULL) {
		if (part->lang_code != NULL && part->lang_code[0] != '\0') {
			lua_pushstring (L, part->lang_code);
			return 1;
		}
	}

	lua_pushnil (L);
	return 1;
}

static gint
lua_textpart_get_mimepart (lua_State * L)
{
	struct mime_text_part *part = lua_check_textpart (L);
	struct mime_part **pmime;

	if (part != NULL) {
		if (part->mime_part != NULL) {
			pmime = lua_newuserdata (L, sizeof (struct mime_part *));
			rspamd_lua_setclass (L, "rspamd{mimepart}", -1);
			*pmime = part->mime_part;

			return 1;
		}
	}

	lua_pushnil (L);
	return 1;
}

static gint
lua_textpart_compare_distance (lua_State * L)
{
	struct mime_text_part *part = lua_check_textpart (L), *other;
	void *ud = luaL_checkudata (L, 2, "rspamd{textpart}");
	gint diff = -1;
	GMimeObject *parent;
	const GMimeContentType *ct;

	luaL_argcheck (L, ud != NULL, 2, "'textpart' expected");
	other = ud ? *((struct mime_text_part **)ud) : NULL;

	if (other != NULL && part->parent && part->parent == other->parent) {
		parent = part->parent;
		ct = g_mime_object_get_content_type (parent);
#ifndef GMIME24
		if (ct == NULL ||
			!g_mime_content_type_is_type (ct, "multipart", "alternative")) {
#else
		if (ct == NULL ||
			!g_mime_content_type_is_type ((GMimeContentType *)ct, "multipart",
			"alternative")) {
#endif
			diff = -1;

		}
		else {
			if (!IS_PART_EMPTY (part) && !IS_PART_EMPTY (other)) {
				if (part->diff_str != NULL && other->diff_str != NULL) {
					diff = rspamd_diff_distance (part->diff_str,
							other->diff_str);
				}
				else {
					diff = rspamd_fuzzy_compare_parts (part, other);
				}
			}
			else if ((IS_PART_EMPTY (part) &&
				!IS_PART_EMPTY (other)) || (!IS_PART_EMPTY (part) &&
						IS_PART_EMPTY (other))) {
				/* Empty and non empty parts are different */
				diff = 0;
			}
		}
	}
	else {
		diff = -1;
	}


	lua_pushinteger (L, diff);

	return 1;
}

/* Mimepart implementation */

static gint
lua_mimepart_get_content (lua_State * L)
{
	struct mime_part *part = lua_check_mimepart (L);
	struct rspamd_lua_text *t;

	if (part == NULL) {
		lua_pushnil (L);
		return 1;
	}

	t = lua_newuserdata (L, sizeof (*t));
	rspamd_lua_setclass (L, "rspamd{text}", -1);
	t->start = part->content->data;
	t->len = part->content->len;
	t->own = FALSE;

	return 1;
}

static gint
lua_mimepart_get_length (lua_State * L)
{
	struct mime_part *part = lua_check_mimepart (L);

	if (part == NULL) {
		lua_pushnil (L);
		return 1;
	}

	lua_pushinteger (L, part->content->len);

	return 1;
}

static gint
lua_mimepart_get_type (lua_State * L)
{
	struct mime_part *part = lua_check_mimepart (L);

	if (part == NULL) {
		lua_pushnil (L);
		lua_pushnil (L);
		return 2;
	}
#ifndef GMIME24
	lua_pushstring (L, part->type->type);
	lua_pushstring (L, part->type->subtype);
#else
	lua_pushstring (L, g_mime_content_type_get_media_type (part->type));
	lua_pushstring (L, g_mime_content_type_get_media_subtype (part->type));
#endif

	return 2;
}

static gint
lua_mimepart_get_filename (lua_State * L)
{
	struct mime_part *part = lua_check_mimepart (L);

	if (part == NULL || part->filename == NULL) {
		lua_pushnil (L);
		return 1;
	}

	lua_pushstring (L, part->filename);

	return 1;
}

static gint
lua_mimepart_get_header_common (lua_State *L, gboolean full, gboolean raw)
{
	gboolean strong = FALSE;
	struct mime_part *part = lua_check_mimepart (L);
	const gchar *name;

	name = luaL_checkstring (L, 2);

	if (name && part) {
		if (lua_gettop (L) == 3) {
			strong = lua_toboolean (L, 3);
		}
		return rspamd_lua_push_header (L, part->raw_headers, name, strong, full, raw);
	}
	lua_pushnil (L);
	return 1;
}

static gint
lua_mimepart_get_header_full (lua_State * L)
{
	return lua_mimepart_get_header_common (L, TRUE, TRUE);
}

static gint
lua_mimepart_get_header (lua_State * L)
{
	return lua_mimepart_get_header_common (L, FALSE, FALSE);
}

static gint
lua_mimepart_get_header_raw (lua_State * L)
{
	return lua_mimepart_get_header_common (L, FALSE, TRUE);
}

void
luaopen_textpart (lua_State * L)
{
	rspamd_lua_new_class (L, "rspamd{textpart}", textpartlib_m);
	lua_pop (L, 1);                      /* remove metatable from stack */
}

void
luaopen_mimepart (lua_State * L)
{
	rspamd_lua_new_class (L, "rspamd{mimepart}", mimepartlib_m);
	lua_pop (L, 1);                      /* remove metatable from stack */
}

