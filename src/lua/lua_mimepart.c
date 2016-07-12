/*-
 * Copyright 2016 Vsevolod Stakhov
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
#include "lua_common.h"
#include "message.h"

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
				texts = task:get_texts()
				if texts then
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
 * Get the text of the part (html tags stripped)
 * @return {text} `UTF8` encoded content of the part (zero-copy if not converted to a lua string)
 */
LUA_FUNCTION_DEF (textpart, get_content);
/***
 * @method text_part:get_raw_content()
 * Get the original text of the part
 * @return {text} `UTF8` encoded content of the part (zero-copy if not converted to a lua string)
 */
LUA_FUNCTION_DEF (textpart, get_raw_content);
/***
 * @method text_part:get_content_oneline()
 *Get the text of the part (html tags and newlines stripped)
 * @return {text} `UTF8` encoded content of the part (zero-copy if not converted to a lua string)
 */
LUA_FUNCTION_DEF (textpart, get_content_oneline);
/***
 * @method text_part:get_length()
 * Get length of the text of the part
 * @return {integer} length of part in **bytes**
 */
LUA_FUNCTION_DEF (textpart, get_length);
/***
 * @method mime_part:get_raw_length()
 * Get length of the **raw** content of the part (e.g. HTML with tags unstripped)
 * @return {integer} length of part in **bytes**
 */
LUA_FUNCTION_DEF (textpart, get_raw_length);
/***
 * @method mime_part:get_lines_count()
 * Get lines number in the part
 * @return {integer} number of lines in the part
 */
LUA_FUNCTION_DEF (textpart, get_lines_count);
/***
 * @method mime_part:get_words_count()
 * Get words number in the part
 * @return {integer} number of words in the part
 */
LUA_FUNCTION_DEF (textpart, get_words_count);
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
 * @method text_part:get_html()
 * Returns html content of the specified part
 * @return {html} html content
 */
LUA_FUNCTION_DEF (textpart, get_html);
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

static const struct luaL_reg textpartlib_m[] = {
	LUA_INTERFACE_DEF (textpart, is_utf),
	LUA_INTERFACE_DEF (textpart, get_content),
	LUA_INTERFACE_DEF (textpart, get_raw_content),
	LUA_INTERFACE_DEF (textpart, get_content_oneline),
	LUA_INTERFACE_DEF (textpart, get_length),
	LUA_INTERFACE_DEF (textpart, get_raw_length),
	LUA_INTERFACE_DEF (textpart, get_lines_count),
	LUA_INTERFACE_DEF (textpart, get_words_count),
	LUA_INTERFACE_DEF (textpart, is_empty),
	LUA_INTERFACE_DEF (textpart, is_html),
	LUA_INTERFACE_DEF (textpart, get_html),
	LUA_INTERFACE_DEF (textpart, get_language),
	LUA_INTERFACE_DEF (textpart, get_mimepart),
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
/***
 * @method mime_part:is_image()
 * Returns true if mime part is an image
 * @return {bool} true if a part is an image
 */
LUA_FUNCTION_DEF (mimepart, is_image);
/***
 * @method mime_part:get_image()
 * Returns rspamd_image structure associated with this part. This structure has
 * the following methods:
 *
 * * `get_width` - return width of an image in pixels
 * * `get_height` - return height of an image in pixels
 * * `get_type` - return string representation of image's type (e.g. 'jpeg')
 * * `get_filename` - return string with image's file name
 * * `get_size` - return size in bytes
 * @return {rspamd_image} image structure or nil if a part is not an image
 */
LUA_FUNCTION_DEF (mimepart, get_image);
/***
 * @method mime_part:is_archive()
 * Returns true if mime part is an archive
 * @return {bool} true if a part is an archive
 */
LUA_FUNCTION_DEF (mimepart, is_archive);
/***
 * @method mime_part:get_archive()
 * Returns rspamd_archive structure associated with this part. This structure has
 * the following methods:
 *
 * * `get_files` - return list of strings with filenames inside archive
 * * `get_files_full` - return list of tables with all information about files
 * * `is_encrypted` - return true if an archive is encrypted
 * * `get_type` - return string representation of image's type (e.g. 'zip')
 * * `get_filename` - return string with archive's file name
 * * `get_size` - return size in bytes
 * @return {rspamd_archive} archive structure or nil if a part is not an archive
 */
LUA_FUNCTION_DEF (mimepart, get_archive);
/***
 * @method mime_part:is_text()
 * Returns true if mime part is a text part
 * @return {bool} true if a part is a text part
 */
LUA_FUNCTION_DEF (mimepart, is_text);
/***
 * @method mime_part:get_text()
 * Returns rspamd_textpart structure associated with this part.
 * @return {rspamd_textpart} textpart structure or nil if a part is not an text
 */
LUA_FUNCTION_DEF (mimepart, get_text);

static const struct luaL_reg mimepartlib_m[] = {
	LUA_INTERFACE_DEF (mimepart, get_content),
	LUA_INTERFACE_DEF (mimepart, get_length),
	LUA_INTERFACE_DEF (mimepart, get_type),
	LUA_INTERFACE_DEF (mimepart, get_filename),
	LUA_INTERFACE_DEF (mimepart, get_header),
	LUA_INTERFACE_DEF (mimepart, get_header_raw),
	LUA_INTERFACE_DEF (mimepart, get_header_full),
	LUA_INTERFACE_DEF (mimepart, is_image),
	LUA_INTERFACE_DEF (mimepart, get_image),
	LUA_INTERFACE_DEF (mimepart, is_archive),
	LUA_INTERFACE_DEF (mimepart, get_archive),
	LUA_INTERFACE_DEF (mimepart, is_text),
	LUA_INTERFACE_DEF (mimepart, get_text),
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};


static struct rspamd_mime_text_part *
lua_check_textpart (lua_State * L)
{
	void *ud = rspamd_lua_check_udata (L, 1, "rspamd{textpart}");
	luaL_argcheck (L, ud != NULL, 1, "'textpart' expected");
	return ud ? *((struct rspamd_mime_text_part **)ud) : NULL;
}

static struct rspamd_mime_part *
lua_check_mimepart (lua_State * L)
{
	void *ud = rspamd_lua_check_udata (L, 1, "rspamd{mimepart}");
	luaL_argcheck (L, ud != NULL, 1, "'mimepart' expected");
	return ud ? *((struct rspamd_mime_part **)ud) : NULL;
}


static gint
lua_textpart_is_utf (lua_State * L)
{
	struct rspamd_mime_text_part *part = lua_check_textpart (L);

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
	struct rspamd_mime_text_part *part = lua_check_textpart (L);
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
lua_textpart_get_raw_content (lua_State * L)
{
	struct rspamd_mime_text_part *part = lua_check_textpart (L);
	struct rspamd_lua_text *t;

	if (part == NULL || IS_PART_EMPTY (part)) {
		lua_pushnil (L);
		return 1;
	}

	t = lua_newuserdata (L, sizeof (*t));
	rspamd_lua_setclass (L, "rspamd{text}", -1);
	t->start = part->orig->data;
	t->len = part->orig->len;
	t->own = FALSE;

	return 1;
}

static gint
lua_textpart_get_content_oneline (lua_State * L)
{
	struct rspamd_mime_text_part *part = lua_check_textpart (L);
	struct rspamd_lua_text *t;

	if (part == NULL || IS_PART_EMPTY (part)) {
		lua_pushnil (L);
		return 1;
	}

	t = lua_newuserdata (L, sizeof (*t));
	rspamd_lua_setclass (L, "rspamd{text}", -1);
	t->start = part->stripped_content->data;
	t->len = part->stripped_content->len;
	t->own = FALSE;

	return 1;
}

static gint
lua_textpart_get_length (lua_State * L)
{
	struct rspamd_mime_text_part *part = lua_check_textpart (L);

	if (part == NULL) {
		lua_pushnil (L);
		return 1;
	}

	if (IS_PART_EMPTY (part) || part->content == NULL) {
		lua_pushnumber (L, 0);
	}
	else {
		lua_pushnumber (L, part->content->len);
	}

	return 1;
}

static gint
lua_textpart_get_raw_length (lua_State * L)
{
	struct rspamd_mime_text_part *part = lua_check_textpart (L);

	if (part == NULL) {
		lua_pushnil (L);
		return 1;
	}

	if (part->orig == NULL) {
		lua_pushnumber (L, 0);
	}
	else {
		lua_pushnumber (L, part->orig->len);
	}

	return 1;
}

static gint
lua_textpart_get_lines_count (lua_State * L)
{
	struct rspamd_mime_text_part *part = lua_check_textpart (L);

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
lua_textpart_get_words_count (lua_State *L)
{
	struct rspamd_mime_text_part *part = lua_check_textpart (L);

	if (part == NULL) {
		lua_pushnil (L);
		return 1;
	}

	if (IS_PART_EMPTY (part) || part->normalized_words == NULL) {
		lua_pushnumber (L, 0);
	}
	else {
		lua_pushnumber (L, part->normalized_words->len);
	}

	return 1;
}

static gint
lua_textpart_is_empty (lua_State * L)
{
	struct rspamd_mime_text_part *part = lua_check_textpart (L);

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
	struct rspamd_mime_text_part *part = lua_check_textpart (L);

	if (part == NULL) {
		lua_pushnil (L);
		return 1;
	}

	lua_pushboolean (L, IS_PART_HTML (part));

	return 1;
}

static gint
lua_textpart_get_html (lua_State * L)
{
	struct rspamd_mime_text_part *part = lua_check_textpart (L);
	struct html_content **phc;

	if (part == NULL || part->html == NULL) {
		lua_pushnil (L);
	}
	else {
		phc = lua_newuserdata (L, sizeof (*phc));
		rspamd_lua_setclass (L, "rspamd{html}", -1);
		*phc = part->html;
	}

	return 1;
}

static gint
lua_textpart_get_language (lua_State * L)
{
	struct rspamd_mime_text_part *part = lua_check_textpart (L);

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
	struct rspamd_mime_text_part *part = lua_check_textpart (L);
	struct rspamd_mime_part **pmime;

	if (part != NULL) {
		if (part->mime_part != NULL) {
			pmime = lua_newuserdata (L, sizeof (struct rspamd_mime_part *));
			rspamd_lua_setclass (L, "rspamd{mimepart}", -1);
			*pmime = part->mime_part;

			return 1;
		}
	}

	lua_pushnil (L);
	return 1;
}

/* Mimepart implementation */

static gint
lua_mimepart_get_content (lua_State * L)
{
	struct rspamd_mime_part *part = lua_check_mimepart (L);
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
	struct rspamd_mime_part *part = lua_check_mimepart (L);

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
	struct rspamd_mime_part *part = lua_check_mimepart (L);

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
	struct rspamd_mime_part *part = lua_check_mimepart (L);

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
	struct rspamd_mime_part *part = lua_check_mimepart (L);
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

static gint
lua_mimepart_is_image (lua_State * L)
{
	struct rspamd_mime_part *part = lua_check_mimepart (L);

	if (part == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	lua_pushboolean (L, (part->flags & RSPAMD_MIME_PART_IMAGE) ? true : false);

	return 1;
}

static gint
lua_mimepart_is_archive (lua_State * L)
{
	struct rspamd_mime_part *part = lua_check_mimepart (L);

	if (part == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	lua_pushboolean (L, (part->flags & RSPAMD_MIME_PART_ARCHIVE) ? true : false);

	return 1;
}

static gint
lua_mimepart_is_text (lua_State * L)
{
	struct rspamd_mime_part *part = lua_check_mimepart (L);

	if (part == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	lua_pushboolean (L, (part->flags & RSPAMD_MIME_PART_TEXT) ? true : false);

	return 1;
}

static gint
lua_mimepart_get_image (lua_State * L)
{
	struct rspamd_mime_part *part = lua_check_mimepart (L);
	struct rspamd_image **pimg;

	if (part == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	if (!(part->flags & RSPAMD_MIME_PART_IMAGE)) {
		lua_pushnil (L);
	}
	else {
		pimg = lua_newuserdata (L, sizeof (*pimg));
		*pimg = part->specific_data;
		rspamd_lua_setclass (L, "rspamd{image}", -1);
	}

	return 1;
}

static gint
lua_mimepart_get_archive (lua_State * L)
{
	struct rspamd_mime_part *part = lua_check_mimepart (L);
	struct rspamd_archive **parch;

	if (part == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	if (!(part->flags & RSPAMD_MIME_PART_ARCHIVE)) {
		lua_pushnil (L);
	}
	else {
		parch = lua_newuserdata (L, sizeof (*parch));
		*parch = part->specific_data;
		rspamd_lua_setclass (L, "rspamd{archive}", -1);
	}

	return 1;
}

static gint
lua_mimepart_get_text (lua_State * L)
{
	struct rspamd_mime_part *part = lua_check_mimepart (L);
	struct rspamd_mime_text_part **ppart;

	if (part == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	if (!(part->flags & RSPAMD_MIME_PART_TEXT)) {
		lua_pushnil (L);
	}
	else {
		ppart = lua_newuserdata (L, sizeof (*ppart));
		*ppart = part->specific_data;
		rspamd_lua_setclass (L, "rspamd{textpart}", -1);
	}

	return 1;
}

void
luaopen_textpart (lua_State * L)
{
	rspamd_lua_new_class (L, "rspamd{textpart}", textpartlib_m);
	lua_pop (L, 1);
}

void
luaopen_mimepart (lua_State * L)
{
	rspamd_lua_new_class (L, "rspamd{mimepart}", mimepartlib_m);
	lua_pop (L, 1);
}

