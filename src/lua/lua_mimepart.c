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
#include "lua_url.h"
#include "libmime/message.h"
#include "libmime/lang_detection.h"
#include "libstat/stat_api.h"
#include "libcryptobox/cryptobox.h"
#include "libutil/shingles.h"

#include "contrib/uthash/utlist.h"

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
 * @method text_part:has_8bit_raw()
 * Return TRUE if a part has raw 8bit characters
 * @return {boolean} true if a part has raw 8bit characters
 */
LUA_FUNCTION_DEF (textpart, has_8bit_raw);

/***
 * @method text_part:has_8bit()
 * Return TRUE if a part has raw 8bit characters
 * @return {boolean} true if a part has encoded 8bit characters
 */
LUA_FUNCTION_DEF (textpart, has_8bit);

/***
 * @method text_part:get_content([type])
 * Get the text of the part (html tags stripped). Optional `type` defines type of content to get:
 * - `content` (default): utf8 content with HTML tags stripped and newlines preserved
 * - `content_oneline`: utf8 content with HTML tags and newlines stripped
 * - `raw`: raw content, not mime decoded nor utf8 converted
 * - `raw_parsed`: raw content, mime decoded, not utf8 converted
 * - `raw_utf`: raw content, mime decoded, utf8 converted (but with HTML tags and newlines)
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
 * @method mime_part:get_urls_length()
 * Get length of the urls within the part
 * @return {integer} length of urls in **bytes**
 */
LUA_FUNCTION_DEF (textpart, get_urls_length);
/***
 * @method mime_part:get_lines_count()
 * Get lines number in the part
 * @return {integer} number of lines in the part
 */
LUA_FUNCTION_DEF (textpart, get_lines_count);
/***
 * @method mime_part:get_stats()
 * Returns a table with the following data:
 * - `lines`: number of lines
 * - `spaces`: number of spaces
 * - `double_spaces`: double spaces
 * - `empty_lines`: number of empty lines
 * - `non_ascii_characters`: number of non ascii characters
 * - `ascii_characters`: number of ascii characters
 * @return {table} table of stats
 */
LUA_FUNCTION_DEF (textpart, get_stats);
/***
 * @method mime_part:get_words_count()
 * Get words number in the part
 * @return {integer} number of words in the part
 */
LUA_FUNCTION_DEF (textpart, get_words_count);

/***
 * @method mime_part:get_words([how])
 * Get words in the part. Optional `how` argument defines type of words returned:
 * - `stem`: stemmed words (default)
 * - `norm`: normalised words (utf normalised + lowercased)
 * - `raw`: raw words in utf (if possible)
 * - `full`: list of tables, each table has the following fields:
 *   - [1] - stemmed word
 *   - [2] - normalised word
 *   - [3] - raw word
 *   - [4] - flags (table of strings)
 * @return {table/strings} words in the part
 */
LUA_FUNCTION_DEF (textpart, get_words);

/***
 * @method mime_part:filter_words(regexp, [how][, max]])
 * Filter words using some regexp:
 * - `stem`: stemmed words (default)
 * - `norm`: normalised words (utf normalised + lowercased)
 * - `raw`: raw words in utf (if possible)
 * - `full`: list of tables, each table has the following fields:
 *   - [1] - stemmed word
 *   - [2] - normalised word
 *   - [3] - raw word
 *   - [4] - flags (table of strings)
 * @param {rspamd_regexp} regexp regexp to match
 * @param {string} how what words to extract
 * @param {number} max maximum number of hits returned (all hits if <= 0 or nil)
 * @return {table/strings} words matching regexp
 */
LUA_FUNCTION_DEF (textpart, filter_words);

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
 * @method text_part:get_charset()
 * Returns part real charset
 * @return {string} charset of the part
 */
LUA_FUNCTION_DEF (textpart, get_charset);
/***
 * @method text_part:get_languages()
 * Returns array of tables of all languages detected for a part:
 * - 'code': language code (short string)
 * - 'prob': logarithm of probability
 * @return {array|tables} all languages detected for the part
 */
LUA_FUNCTION_DEF (textpart, get_languages);
/***
 * @method text_part:get_fuzzy_hashes(mempool)
 * @param {rspamd_mempool} mempool - memory pool (usually task pool)
 * Returns direct hash of textpart as a string and array [1..32] of shingles each represented as a following table:
 * - [1] - 64 bit fuzzy hash represented as a string
 * - [2..4] - strings used to generate this hash
 * @return {string,array|tables} fuzzy hashes calculated
 */
LUA_FUNCTION_DEF (textpart, get_fuzzy_hashes);
/***
 * @method text_part:get_mimepart()
 * Returns the mime part object corresponding to this text part
 * @return {mimepart} mimepart object
 */
LUA_FUNCTION_DEF (textpart, get_mimepart);

static const struct luaL_reg textpartlib_m[] = {
	LUA_INTERFACE_DEF (textpart, is_utf),
	LUA_INTERFACE_DEF (textpart, has_8bit_raw),
	LUA_INTERFACE_DEF (textpart, has_8bit),
	LUA_INTERFACE_DEF (textpart, get_content),
	LUA_INTERFACE_DEF (textpart, get_raw_content),
	LUA_INTERFACE_DEF (textpart, get_content_oneline),
	LUA_INTERFACE_DEF (textpart, get_length),
	LUA_INTERFACE_DEF (textpart, get_raw_length),
	LUA_INTERFACE_DEF (textpart, get_urls_length),
	LUA_INTERFACE_DEF (textpart, get_lines_count),
	LUA_INTERFACE_DEF (textpart, get_words_count),
	LUA_INTERFACE_DEF (textpart, get_words),
	LUA_INTERFACE_DEF (textpart, filter_words),
	LUA_INTERFACE_DEF (textpart, is_empty),
	LUA_INTERFACE_DEF (textpart, is_html),
	LUA_INTERFACE_DEF (textpart, get_html),
	LUA_INTERFACE_DEF (textpart, get_language),
	LUA_INTERFACE_DEF (textpart, get_charset),
	LUA_INTERFACE_DEF (textpart, get_languages),
	LUA_INTERFACE_DEF (textpart, get_mimepart),
	LUA_INTERFACE_DEF (textpart, get_stats),
	LUA_INTERFACE_DEF (textpart, get_fuzzy_hashes),
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
	if parts and #parts > 1 then
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
 * @method mimepart:get_header_count(name[, case_sensitive])
 * Lightweight version if you need just a header's count
 *  * By default headers are searched in caseless matter.
 * @param {string} name name of header to get
 * @param {boolean} case_sensitive case sensitiveness flag to search for a header
 * @return {number} number of header's occurrencies or 0 if not found
 */
LUA_FUNCTION_DEF (mimepart, get_header_count);

/***
 * @method mimepart:get_raw_headers()
 * Get all undecoded headers of a mime part as a string
 * @return {rspamd_text} all raw headers for a message as opaque text
 */
LUA_FUNCTION_DEF (mimepart, get_raw_headers);

/***
 * @method mimepart:get_headers()
 * Get all undecoded headers of a mime part as a string
 * @return {rspamd_text} all raw headers for a message as opaque text
 */
LUA_FUNCTION_DEF (mimepart, get_headers);

/***
 * @method mime_part:get_content()
 * Get the parsed content of part
 * @return {text} opaque text object (zero-copy if not casted to lua string)
 */
LUA_FUNCTION_DEF (mimepart, get_content);
/***
 * @method mime_part:get_raw_content()
 * Get the raw content of part
 * @return {text} opaque text object (zero-copy if not casted to lua string)
 */
LUA_FUNCTION_DEF (mimepart, get_raw_content);
/***
 * @method mime_part:get_length()
 * Get length of the content of the part
 * @return {integer} length of part in **bytes**
 */
LUA_FUNCTION_DEF (mimepart, get_length);
/***
 * @method mime_part:get_type()
 * Extract content-type string of the mime part
 * @return {string,string} content type in form 'type','subtype'
 */
LUA_FUNCTION_DEF (mimepart, get_type);

/***
 * @method mime_part:get_type_full()
 * Extract content-type string of the mime part with all attributes
 * @return {string,string,table} content type in form 'type','subtype', {attrs}
 */
LUA_FUNCTION_DEF (mimepart, get_type_full);

/***
 * @method mime_part:get_detected_type()
 * Extract content-type string of the mime part. Use lua_magic detection
 * @return {string,string} content type in form 'type','subtype'
 */
LUA_FUNCTION_DEF (mimepart, get_detected_type);

/***
 * @method mime_part:get_detected_type_full()
 * Extract content-type string of the mime part with all attributes. Use lua_magic detection
 * @return {string,string,table} content type in form 'type','subtype', {attrs}
 */
LUA_FUNCTION_DEF (mimepart, get_detected_type_full);

/***
 * @method mime_part:get_detected_ext()
 * Returns a msdos extension name according to lua_magic detection
 * @return {string} detected extension (see lua_magic.types)
 */
LUA_FUNCTION_DEF (mimepart, get_detected_ext);

/***
 * @method mime_part:get_cte()
 * Extract content-transfer-encoding for a part
 * @return {string} content transfer encoding (e.g. `base64` or `7bit`)
 */
LUA_FUNCTION_DEF (mimepart, get_cte);

/***
 * @method mime_part:get_filename()
 * Extract filename associated with mime part if it is an attachment
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
 * @method mime_part:is_attachment()
 * Returns true if mime part looks like an attachment
 * @return {bool} true if a part looks like an attachment
 */
LUA_FUNCTION_DEF (mimepart, is_attachment);

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
 * @method mime_part:is_multipart()
 * Returns true if mime part is a multipart part
 * @return {bool} true if a part is is a multipart part
 */
LUA_FUNCTION_DEF (mimepart, is_multipart);
/***
 * @method mime_part:is_message()
 * Returns true if mime part is a message part (message/rfc822)
 * @return {bool} true if a part is is a message part
 */
LUA_FUNCTION_DEF (mimepart, is_message);
/***
 * @method mime_part:get_boundary()
 * Returns boundary for a part (extracted from parent multipart for normal parts and
 * from the part itself for multipart)
 * @return {string} boundary value or nil
 */
LUA_FUNCTION_DEF (mimepart, get_boundary);

/***
 * @method mime_part:get_enclosing_boundary()
 * Returns an enclosing boundary for a part even for multiparts. For normal parts
 * this method is identical to `get_boundary`
 * @return {string} boundary value or nil
 */
LUA_FUNCTION_DEF (mimepart, get_enclosing_boundary);

/***
 * @method mime_part:get_children()
 * Returns rspamd_mimepart table of part's childer. Returns nil if mime part is not multipart
 * or a message part.
 * @return {rspamd_mimepart} table of children
 */
LUA_FUNCTION_DEF (mimepart, get_children);
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

/***
 * @method mime_part:get_digest()
 * Returns the unique digest for this mime part
 * @return {string} 128 characters hex string with digest of the part
 */
LUA_FUNCTION_DEF (mimepart, get_digest);

/***
 * @method mime_part:get_id()
 * Returns the order of the part in parts list
 * @return {number} index of the part (starting from 1 as it is Lua API)
 */
LUA_FUNCTION_DEF (mimepart, get_id);
/***
 * @method mime_part:is_broken()
 * Returns true if mime part has incorrectly specified content type
 * @return {bool} true if a part has bad content type
 */
LUA_FUNCTION_DEF (mimepart, is_broken);
/***
 * @method mime_part:headers_foreach(callback, [params])
 * This method calls `callback` for each header that satisfies some condition.
 * By default, all headers are iterated unless `callback` returns `true`. Nil or
 * false means continue of iterations.
 * Params could be as following:
 *
 * - `full`: header value is full table of all attributes @see task:get_header_full for details
 * - `regexp`: return headers that satisfies the specified regexp
 * @param {function} callback function from header name and header value
 * @param {table} params optional parameters
 */
LUA_FUNCTION_DEF (mimepart, headers_foreach);
/***
 * @method mime_part:get_parent()
 * Returns parent part for this part
 * @return {rspamd_mimepart} parent part or nil
 */
LUA_FUNCTION_DEF (mimepart, get_parent);

/***
 * @method mime_part:get_specific()
 * Returns specific lua content for this part
 * @return {any} specific lua content
 */
LUA_FUNCTION_DEF (mimepart, get_specific);

/***
 * @method mime_part:set_specific(<any>)
 * Sets a specific content for this part
 * @return {any} previous specific lua content (or nil)
 */
LUA_FUNCTION_DEF (mimepart, set_specific);

/***
 * @method mime_part:is_specific(<any>)
 * Returns true if part has specific lua content
 * @return {boolean} flag
 */
LUA_FUNCTION_DEF (mimepart, is_specific);

/***
 * @method mime_part:get_urls([need_emails|list_protos][, need_images])
 * Get all URLs found in a mime part. Telephone urls and emails are not included unless explicitly asked in `list_protos`
 * @param {boolean} need_emails if `true` then reutrn also email urls, this can be a comma separated string of protocols desired or a table (e.g. `mailto` or `telephone`)
 * @param {boolean} need_images return urls from images (<img src=...>) as well
 * @return {table rspamd_url} list of all urls found
 */
LUA_FUNCTION_DEF (mimepart, get_urls);

static const struct luaL_reg mimepartlib_m[] = {
	LUA_INTERFACE_DEF (mimepart, get_content),
	LUA_INTERFACE_DEF (mimepart, get_raw_content),
	LUA_INTERFACE_DEF (mimepart, get_length),
	LUA_INTERFACE_DEF (mimepart, get_type),
	LUA_INTERFACE_DEF (mimepart, get_type_full),
	LUA_INTERFACE_DEF (mimepart, get_detected_type),
	LUA_INTERFACE_DEF (mimepart, get_detected_ext),
	LUA_INTERFACE_DEF (mimepart, get_detected_type_full),
	LUA_INTERFACE_DEF (mimepart, get_cte),
	LUA_INTERFACE_DEF (mimepart, get_filename),
	LUA_INTERFACE_DEF (mimepart, get_boundary),
	LUA_INTERFACE_DEF (mimepart, get_enclosing_boundary),
	LUA_INTERFACE_DEF (mimepart, get_header),
	LUA_INTERFACE_DEF (mimepart, get_header_raw),
	LUA_INTERFACE_DEF (mimepart, get_header_full),
	LUA_INTERFACE_DEF (mimepart, get_header_count),
	LUA_INTERFACE_DEF (mimepart, get_raw_headers),
	LUA_INTERFACE_DEF (mimepart, get_headers),
	LUA_INTERFACE_DEF (mimepart, is_image),
	LUA_INTERFACE_DEF (mimepart, get_image),
	LUA_INTERFACE_DEF (mimepart, is_archive),
	LUA_INTERFACE_DEF (mimepart, get_archive),
	LUA_INTERFACE_DEF (mimepart, is_multipart),
	LUA_INTERFACE_DEF (mimepart, is_message),
	LUA_INTERFACE_DEF (mimepart, get_children),
	LUA_INTERFACE_DEF (mimepart, get_parent),
	LUA_INTERFACE_DEF (mimepart, get_urls),
	LUA_INTERFACE_DEF (mimepart, is_text),
	LUA_INTERFACE_DEF (mimepart, is_broken),
	LUA_INTERFACE_DEF (mimepart, is_attachment),
	LUA_INTERFACE_DEF (mimepart, get_text),
	LUA_INTERFACE_DEF (mimepart, get_digest),
	LUA_INTERFACE_DEF (mimepart, get_id),
	LUA_INTERFACE_DEF (mimepart, headers_foreach),
	LUA_INTERFACE_DEF (mimepart, get_specific),
	LUA_INTERFACE_DEF (mimepart, set_specific),
	LUA_INTERFACE_DEF (mimepart, is_specific),
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
	LUA_TRACE_POINT;
	struct rspamd_mime_text_part *part = lua_check_textpart (L);

	if (part == NULL || IS_TEXT_PART_EMPTY (part)) {
		lua_pushboolean (L, FALSE);
		return 1;
	}

	lua_pushboolean (L, IS_TEXT_PART_UTF (part));

	return 1;
}


static gint
lua_textpart_has_8bit_raw (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_text_part *part = lua_check_textpart (L);

	if (part) {
		if (part->flags & RSPAMD_MIME_TEXT_PART_FLAG_8BIT_RAW) {
			lua_pushboolean (L, TRUE);
		}
		else {
			lua_pushboolean (L, FALSE);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_textpart_has_8bit (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_text_part *part = lua_check_textpart (L);

	if (part) {
		if (part->flags & RSPAMD_MIME_TEXT_PART_FLAG_8BIT_ENCODED) {
			lua_pushboolean (L, TRUE);
		}
		else {
			lua_pushboolean (L, FALSE);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}


static gint
lua_textpart_get_content (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_text_part *part = lua_check_textpart (L);
	struct rspamd_lua_text *t;
	gsize len;
	const gchar *start, *type = NULL;

	if (part == NULL) {
		lua_pushnil (L);
		return 1;
	}

	if (lua_type (L, 2) == LUA_TSTRING) {
		type = lua_tostring (L, 2);
	}

	if (!type) {
		if (IS_TEXT_PART_EMPTY (part)) {
			lua_pushnil (L);
			return 1;
		}
		start = part->utf_content.begin;
		len = part->utf_content.len;
	}
	else if (strcmp (type, "content") == 0) {
		if (IS_TEXT_PART_EMPTY (part)) {
			lua_pushnil (L);
			return 1;
		}

		start = part->utf_content.begin;
		len = part->utf_content.len;
	}
	else if (strcmp (type, "content_oneline") == 0) {
		if (IS_TEXT_PART_EMPTY (part)) {
			lua_pushnil (L);
			return 1;
		}

		start = part->utf_stripped_content->data;
		len = part->utf_stripped_content->len;
	}
	else if (strcmp (type, "raw_parsed") == 0) {
		if (part->parsed.len == 0) {
			lua_pushnil (L);
			return 1;
		}

		start = part->parsed.begin;
		len = part->parsed.len;
	}
	else if (strcmp (type, "raw_utf") == 0) {
		if (part->utf_raw_content == NULL || part->utf_raw_content->len == 0) {
			lua_pushnil (L);
			return 1;
		}

		start = part->utf_raw_content->data;
		len = part->utf_raw_content->len;
	}
	else if (strcmp (type, "raw") == 0) {
		if (part->raw.len == 0) {
			lua_pushnil (L);
			return 1;
		}

		start = part->raw.begin;
		len = part->raw.len;
	}
	else {
		return luaL_error (L, "invalid content type: %s", type);
	}

	t = lua_newuserdata (L, sizeof (*t));
	rspamd_lua_setclass (L, "rspamd{text}", -1);

	t->start = start;
	t->len = len;
	t->flags = 0;

	return 1;
}

static gint
lua_textpart_get_raw_content (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_text_part *part = lua_check_textpart (L);
	struct rspamd_lua_text *t;

	if (part == NULL || IS_TEXT_PART_EMPTY (part)) {
		lua_pushnil (L);
		return 1;
	}

	t = lua_newuserdata (L, sizeof (*t));
	rspamd_lua_setclass (L, "rspamd{text}", -1);
	t->start = part->raw.begin;
	t->len = part->raw.len;
	t->flags = 0;

	return 1;
}

static gint
lua_textpart_get_content_oneline (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_text_part *part = lua_check_textpart (L);
	struct rspamd_lua_text *t;

	if (part == NULL || IS_TEXT_PART_EMPTY (part)) {
		lua_pushnil (L);
		return 1;
	}

	t = lua_newuserdata (L, sizeof (*t));
	rspamd_lua_setclass (L, "rspamd{text}", -1);
	t->start = part->utf_stripped_content->data;
	t->len = part->utf_stripped_content->len;
	t->flags = 0;

	return 1;
}

static gint
lua_textpart_get_length (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_text_part *part = lua_check_textpart (L);

	if (part == NULL) {
		lua_pushnil (L);
		return 1;
	}

	if (IS_TEXT_PART_EMPTY (part) || part->utf_content.len == 0) {
		lua_pushinteger (L, 0);
	}
	else {
		lua_pushinteger (L, part->utf_content.len);
	}

	return 1;
}

static gint
lua_textpart_get_raw_length (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_text_part *part = lua_check_textpart (L);

	if (part == NULL) {
		lua_pushnil (L);
		return 1;
	}

	lua_pushinteger (L, part->raw.len);

	return 1;
}

static gint
lua_textpart_get_urls_length (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_text_part *part = lua_check_textpart (L);
	GList *cur;
	guint total = 0;
	struct rspamd_process_exception *ex;

	if (part == NULL) {
		lua_pushnil (L);
		return 1;
	}

	for (cur = part->exceptions; cur != NULL; cur = g_list_next (cur)) {
		ex = cur->data;

		if (ex->type == RSPAMD_EXCEPTION_URL) {
			total += ex->len;
		}
	}

	lua_pushinteger (L, total);

	return 1;
}

static gint
lua_textpart_get_lines_count (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_text_part *part = lua_check_textpart (L);

	if (part == NULL) {
		lua_pushnil (L);
		return 1;
	}

	if (IS_TEXT_PART_EMPTY (part)) {
		lua_pushinteger (L, 0);
	}
	else {
		lua_pushinteger (L, part->nlines);
	}

	return 1;
}

static gint
lua_textpart_get_words_count (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_text_part *part = lua_check_textpart (L);

	if (part == NULL) {
		lua_pushnil (L);
		return 1;
	}

	if (IS_TEXT_PART_EMPTY (part) || part->utf_words == NULL) {
		lua_pushinteger (L, 0);
	}
	else {
		lua_pushinteger (L, part->nwords);
	}

	return 1;
}

static inline enum rspamd_lua_words_type
word_extract_type_from_string (const gchar *how_str)
{
	enum rspamd_lua_words_type how = RSPAMD_LUA_WORDS_MAX;

	if (strcmp (how_str, "stem") == 0) {
		how = RSPAMD_LUA_WORDS_STEM;
	}
	else if (strcmp (how_str, "norm") == 0) {
		how = RSPAMD_LUA_WORDS_NORM;
	}
	else if (strcmp (how_str, "raw") == 0) {
		how = RSPAMD_LUA_WORDS_RAW;
	}
	else if (strcmp (how_str, "full") == 0) {
		how = RSPAMD_LUA_WORDS_FULL;
	}

	return how;
}

static gint
lua_textpart_get_words (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_text_part *part = lua_check_textpart (L);
	enum rspamd_lua_words_type how = RSPAMD_LUA_WORDS_STEM;

	if (part == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	if (IS_TEXT_PART_EMPTY (part) || part->utf_words == NULL) {
		lua_createtable (L, 0, 0);
	}
	else {
		if (lua_type (L, 2) == LUA_TSTRING) {
			const gchar *how_str = lua_tostring (L, 2);

			how = word_extract_type_from_string (how_str);

			if (how == RSPAMD_LUA_WORDS_MAX) {
				return luaL_error (L, "invalid extraction type: %s", how_str);
			}
		}

		return rspamd_lua_push_words (L, part->utf_words, how);
	}

	return 1;
}

static gint
lua_textpart_filter_words (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_text_part *part = lua_check_textpart (L);
	struct rspamd_lua_regexp *re = lua_check_regexp (L, 2);
	gint lim = -1;
	enum rspamd_lua_words_type how = RSPAMD_LUA_WORDS_STEM;

	if (part == NULL || re == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	if (IS_TEXT_PART_EMPTY (part) || part->utf_words == NULL) {
		lua_createtable (L, 0, 0);
	}
	else {
		if (lua_type (L, 3) == LUA_TSTRING) {
			const gchar *how_str = lua_tostring (L, 3);

			how = word_extract_type_from_string (how_str);

			if (how == RSPAMD_LUA_WORDS_MAX) {
				return luaL_error (L, "invalid extraction type: %s", how_str);
			}
		}

		if (lua_type (L, 4) == LUA_TNUMBER) {
			lim = lua_tointeger (L, 4);
		}

		guint cnt, i;

		lua_createtable (L, 8, 0);

		for (i = 0, cnt = 1; i < part->utf_words->len; i ++) {
			rspamd_stat_token_t *w = &g_array_index (part->utf_words,
					rspamd_stat_token_t, i);

			switch (how) {
			case RSPAMD_LUA_WORDS_STEM:
				if (w->stemmed.len > 0) {
					if (rspamd_regexp_match (re->re, w->stemmed.begin,
							w->stemmed.len, FALSE)) {
						lua_pushlstring (L, w->stemmed.begin, w->stemmed.len);
						lua_rawseti (L, -2, cnt++);
					}
				}
				break;
			case RSPAMD_LUA_WORDS_NORM:
				if (w->normalized.len > 0) {
					if (rspamd_regexp_match (re->re, w->normalized.begin,
							w->normalized.len, FALSE)) {
						lua_pushlstring (L, w->normalized.begin, w->normalized.len);
						lua_rawseti (L, -2, cnt++);
					}
				}
				break;
			case RSPAMD_LUA_WORDS_RAW:
				if (w->original.len > 0) {
					if (rspamd_regexp_match (re->re, w->original.begin,
							w->original.len, TRUE)) {
						lua_pushlstring (L, w->original.begin, w->original.len);
						lua_rawseti (L, -2, cnt++);
					}
				}
				break;
			case RSPAMD_LUA_WORDS_FULL:
				if (rspamd_regexp_match (re->re, w->normalized.begin,
						w->normalized.len, FALSE)) {
					rspamd_lua_push_full_word (L, w);
					/* Push to the resulting vector */
					lua_rawseti (L, -2, cnt++);
				}
				break;
			default:
				break;
			}

			if (lim > 0 && cnt >= lim) {
				break;
			}
		}
	}

	return 1;
}

static gint
lua_textpart_is_empty (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_text_part *part = lua_check_textpart (L);

	if (part == NULL) {
		lua_pushnil (L);
		return 1;
	}

	lua_pushboolean (L, IS_TEXT_PART_EMPTY (part));

	return 1;
}

static gint
lua_textpart_is_html (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_text_part *part = lua_check_textpart (L);

	if (part == NULL) {
		lua_pushnil (L);
		return 1;
	}

	lua_pushboolean (L, IS_TEXT_PART_HTML (part));

	return 1;
}

static gint
lua_textpart_get_html (lua_State * L)
{
	LUA_TRACE_POINT;
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
	LUA_TRACE_POINT;
	struct rspamd_mime_text_part *part = lua_check_textpart (L);

	if (part != NULL) {
		if (part->language != NULL && part->language[0] != '\0') {
			lua_pushstring (L, part->language);
			return 1;
		}
		else {
			lua_pushnil (L);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_textpart_get_charset (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_text_part *part = lua_check_textpart (L);

	if (part != NULL) {
		if (part->real_charset != NULL) {
			lua_pushstring (L, part->real_charset);
			return 1;
		}
		else {
			lua_pushnil (L);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_textpart_get_languages (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_text_part *part = lua_check_textpart (L);
	guint i;
	struct rspamd_lang_detector_res *cur;

	if (part != NULL) {
		if (part->languages != NULL) {
			lua_createtable (L, part->languages->len, 0);

			PTR_ARRAY_FOREACH (part->languages, i, cur) {
				lua_createtable (L, 0, 2);
				lua_pushstring (L, "code");
				lua_pushstring (L, cur->lang);
				lua_settable (L, -3);
				lua_pushstring (L, "prob");
				lua_pushnumber (L, cur->prob);
				lua_settable (L, -3);

				lua_rawseti (L, -2, i + 1);
			}
		}
		else {
			lua_newtable (L);
		}
	}
	else {
		luaL_error (L, "invalid arguments");
	}

	return 1;
}

struct lua_shingle_data {
	guint64 hash;
	rspamd_ftok_t t1;
	rspamd_ftok_t t2;
	rspamd_ftok_t t3;
};

struct lua_shingle_filter_cbdata {
	struct rspamd_mime_text_part *part;
	rspamd_mempool_t *pool;
};

#define STORE_TOKEN(i, t) do { \
    if ((i) < part->utf_words->len) { \
        word = &g_array_index (part->utf_words, rspamd_stat_token_t, (i)); \
        sd->t.begin = word->stemmed.begin; \
        sd->t.len = word->stemmed.len; \
    } \
    }while (0)

static guint64
lua_shingles_filter (guint64 *input, gsize count,
					 gint shno, const guchar *key, gpointer ud)
{
	guint64 minimal = G_MAXUINT64;
	gsize i, min_idx = 0;
	struct lua_shingle_data *sd;
	rspamd_stat_token_t *word;
	struct lua_shingle_filter_cbdata *cbd = (struct lua_shingle_filter_cbdata *)ud;
	struct rspamd_mime_text_part *part;

	part = cbd->part;

	for (i = 0; i < count; i ++) {
		if (minimal > input[i]) {
			minimal = input[i];
			min_idx = i;
		}
	}

	sd = rspamd_mempool_alloc0 (cbd->pool, sizeof (*sd));
	sd->hash = minimal;


	STORE_TOKEN (min_idx, t1);
	STORE_TOKEN (min_idx + 1, t2);
	STORE_TOKEN (min_idx + 2, t3);

	return GPOINTER_TO_SIZE (sd);
}

#undef STORE_TOKEN

static gint
lua_textpart_get_fuzzy_hashes (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_text_part *part = lua_check_textpart (L);
	rspamd_mempool_t *pool = rspamd_lua_check_mempool (L, 2);
	guchar key[rspamd_cryptobox_HASHBYTES], digest[rspamd_cryptobox_HASHBYTES],
			hexdigest[rspamd_cryptobox_HASHBYTES * 2 + 1], numbuf[64];
	struct rspamd_shingle *sgl;
	guint i;
	struct lua_shingle_data *sd;
	rspamd_cryptobox_hash_state_t st;
	rspamd_stat_token_t *word;
	struct lua_shingle_filter_cbdata cbd;


	if (part == NULL || pool == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	if (IS_TEXT_PART_EMPTY (part) || part->utf_words == NULL) {
		lua_pushnil (L);
		lua_pushnil (L);
	}
	else {
		/* TODO: add keys and algorithms support */
		rspamd_cryptobox_hash (key, "rspamd", strlen ("rspamd"), NULL, 0);

		/* TODO: add short text support */

		/* Calculate direct hash */
		rspamd_cryptobox_hash_init (&st, key, rspamd_cryptobox_HASHKEYBYTES);

		for (i = 0; i < part->utf_words->len; i ++) {
			word = &g_array_index (part->utf_words, rspamd_stat_token_t, i);
			rspamd_cryptobox_hash_update (&st,
					word->stemmed.begin, word->stemmed.len);
		}

		rspamd_cryptobox_hash_final (&st, digest);

		rspamd_encode_hex_buf (digest, sizeof (digest), hexdigest,
				sizeof (hexdigest));
		lua_pushlstring (L, hexdigest, sizeof (hexdigest) - 1);

		cbd.pool = pool;
		cbd.part = part;
		sgl = rspamd_shingles_from_text (part->utf_words, key,
				pool, lua_shingles_filter, &cbd, RSPAMD_SHINGLES_MUMHASH);

		if (sgl == NULL) {
			lua_pushnil (L);
		}
		else {
			lua_createtable (L, G_N_ELEMENTS (sgl->hashes), 0);

			for (i = 0; i < G_N_ELEMENTS (sgl->hashes); i ++) {
				sd = GSIZE_TO_POINTER (sgl->hashes[i]);

				lua_createtable (L, 4, 0);
				rspamd_snprintf (numbuf, sizeof (numbuf), "%uL", sd->hash);
				lua_pushstring (L, numbuf);
				lua_rawseti (L, -2, 1);

				/* Tokens */
				lua_pushlstring (L, sd->t1.begin, sd->t1.len);
				lua_rawseti (L, -2, 2);

				lua_pushlstring (L, sd->t2.begin, sd->t2.len);
				lua_rawseti (L, -2, 3);

				lua_pushlstring (L, sd->t3.begin, sd->t3.len);
				lua_rawseti (L, -2, 4);

				lua_rawseti (L, -2, i + 1); /* Store table */
			}
		}
	}

	return 2;
}

static gint
lua_textpart_get_mimepart (lua_State * L)
{
	LUA_TRACE_POINT;
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

/***
 * @method mime_part:get_stats()
 * Returns a table with the following data:
 * -
 * - `lines`: number of lines
 * - `spaces`: number of spaces
 * - `double_spaces`: double spaces
 * - `empty_lines`: number of empty lines
 * - `non_ascii_characters`: number of non ascii characters
 * - `ascii_characters`: number of ascii characters
 * @return {table} table of stats
 */
static gint
lua_textpart_get_stats (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_text_part *part = lua_check_textpart (L);

	if (part != NULL) {
		lua_createtable (L, 0, 9);

		lua_pushstring (L, "lines");
		lua_pushinteger (L, part->nlines);
		lua_settable (L, -3);
		lua_pushstring (L, "empty_lines");
		lua_pushinteger (L, part->empty_lines);
		lua_settable (L, -3);
		lua_pushstring (L, "spaces");
		lua_pushinteger (L, part->spaces);
		lua_settable (L, -3);
		lua_pushstring (L, "non_spaces");
		lua_pushinteger (L, part->non_spaces);
		lua_settable (L, -3);
		lua_pushstring (L, "double_spaces");
		lua_pushinteger (L, part->double_spaces);
		lua_settable (L, -3);
		lua_pushstring (L, "ascii_characters");
		lua_pushinteger (L, part->ascii_chars);
		lua_settable (L, -3);
		lua_pushstring (L, "non_ascii_characters");
		lua_pushinteger (L, part->non_ascii_chars);
		lua_settable (L, -3);
		lua_pushstring (L, "capital_letters");
		lua_pushinteger (L, part->capital_letters);
		lua_settable (L, -3);
		lua_pushstring (L, "numeric_characters");
		lua_pushinteger (L, part->numeric_characters);
		lua_settable (L, -3);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

/* Mimepart implementation */

static gint
lua_mimepart_get_content (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_part *part = lua_check_mimepart (L);
	struct rspamd_lua_text *t;

	if (part == NULL) {
		lua_pushnil (L);
		return 1;
	}

	t = lua_newuserdata (L, sizeof (*t));
	rspamd_lua_setclass (L, "rspamd{text}", -1);
	t->start = part->parsed_data.begin;
	t->len = part->parsed_data.len;
	t->flags = 0;

	return 1;
}

static gint
lua_mimepart_get_raw_content (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_part *part = lua_check_mimepart (L);
	struct rspamd_lua_text *t;

	if (part == NULL) {
		lua_pushnil (L);
		return 1;
	}

	t = lua_newuserdata (L, sizeof (*t));
	rspamd_lua_setclass (L, "rspamd{text}", -1);
	t->start = part->raw_data.begin;
	t->len = part->raw_data.len;
	t->flags = 0;

	return 1;
}

static gint
lua_mimepart_get_length (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_part *part = lua_check_mimepart (L);

	if (part == NULL) {
		lua_pushnil (L);
		return 1;
	}

	lua_pushinteger (L, part->parsed_data.len);

	return 1;
}

static gint
lua_mimepart_get_type_common (lua_State * L, struct rspamd_content_type *ct,
		gboolean full)
{

	GHashTableIter it;
	gpointer k, v;
	struct rspamd_content_type_param *param;

	if (ct == NULL) {
		lua_pushnil (L);
		lua_pushnil (L);
		return 2;
	}

	lua_pushlstring (L, ct->type.begin, ct->type.len);
	lua_pushlstring (L, ct->subtype.begin, ct->subtype.len);

	if (!full) {
		return 2;
	}

	lua_createtable (L, 0, 2 + (ct->attrs ?
			g_hash_table_size (ct->attrs) : 0));

	if (ct->charset.len > 0) {
		lua_pushstring (L, "charset");
		lua_pushlstring (L, ct->charset.begin, ct->charset.len);
		lua_settable (L, -3);
	}

	if (ct->boundary.len > 0) {
		lua_pushstring (L, "boundary");
		lua_pushlstring (L, ct->boundary.begin, ct->boundary.len);
		lua_settable (L, -3);
	}

	if (ct->attrs) {
		g_hash_table_iter_init (&it, ct->attrs);

		while (g_hash_table_iter_next (&it, &k, &v)) {
			param = v;

			if (param->name.len > 0 && param->value.len > 0) {
				/* TODO: think about multiple values here */
				lua_pushlstring (L, param->name.begin, param->name.len);
				lua_pushlstring (L, param->value.begin, param->value.len);
				lua_settable (L, -3);
			}
		}
	}

	return 3;
}

static gint
lua_mimepart_get_type (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_part *part = lua_check_mimepart (L);

	if (part == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	return lua_mimepart_get_type_common (L, part->ct, FALSE);
}

static gint
lua_mimepart_get_type_full (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_part *part = lua_check_mimepart (L);

	if (part == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	return lua_mimepart_get_type_common (L, part->ct, TRUE);
}

static gint
lua_mimepart_get_detected_type (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_part *part = lua_check_mimepart (L);

	if (part == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	return lua_mimepart_get_type_common (L, part->detected_ct, FALSE);
}

static gint
lua_mimepart_get_detected_type_full (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_part *part = lua_check_mimepart (L);

	if (part == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	return lua_mimepart_get_type_common (L, part->detected_ct, TRUE);
}

static gint
lua_mimepart_get_detected_ext (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_part *part = lua_check_mimepart (L);

	if (part == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	if (part->detected_ext) {
		lua_pushstring (L, part->detected_ext);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_mimepart_get_cte (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_part *part = lua_check_mimepart (L);

	if (part == NULL) {
		lua_pushnil (L);
		return 1;
	}

	lua_pushstring (L, rspamd_cte_to_string (part->cte));

	return 1;
}

static gint
lua_mimepart_get_filename (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_part *part = lua_check_mimepart (L);

	if (part == NULL || part->cd == NULL || part->cd->filename.len == 0) {
		lua_pushnil (L);
		return 1;
	}

	lua_pushlstring (L, part->cd->filename.begin, part->cd->filename.len);

	return 1;
}

static gint
lua_mimepart_get_boundary (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_part *part = lua_check_mimepart (L), *parent;

	if (part == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	if (IS_PART_MULTIPART (part)) {
		lua_pushlstring (L, part->specific.mp->boundary.begin,
				part->specific.mp->boundary.len);
	}
	else {
		parent = part->parent_part;

		if (!parent || !IS_PART_MULTIPART (parent)) {
			lua_pushnil (L);
		}
		else {
			lua_pushlstring (L, parent->specific.mp->boundary.begin,
					parent->specific.mp->boundary.len);
		}
	}

	return 1;
}

static gint
lua_mimepart_get_enclosing_boundary (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_part *part = lua_check_mimepart (L), *parent;

	if (part == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	parent = part->parent_part;

	if (!parent || !IS_PART_MULTIPART (parent)) {
		lua_pushnil (L);
	}
	else {
		lua_pushlstring (L, parent->specific.mp->boundary.begin,
				parent->specific.mp->boundary.len);
	}

	return 1;
}

static gint
lua_mimepart_get_header_common (lua_State *L, enum rspamd_lua_task_header_type how)
{
	struct rspamd_mime_part *part = lua_check_mimepart (L);
	const gchar *name;
	gboolean strong = FALSE;

	name = luaL_checkstring (L, 2);

	if (name && part) {

		if (lua_isboolean (L, 3)) {
			strong = lua_toboolean (L, 3);
		}

		return rspamd_lua_push_header_array (L,
				name,
				rspamd_message_get_header_from_hash(part->raw_headers, name, FALSE),
				how,
				strong);
	}

	lua_pushnil (L);

	return 1;
}

static gint
lua_mimepart_get_header_full (lua_State * L)
{
	LUA_TRACE_POINT;
	return lua_mimepart_get_header_common (L, RSPAMD_TASK_HEADER_PUSH_FULL);
}

static gint
lua_mimepart_get_header (lua_State * L)
{
	LUA_TRACE_POINT;
	return lua_mimepart_get_header_common (L, RSPAMD_TASK_HEADER_PUSH_SIMPLE);
}

static gint
lua_mimepart_get_header_raw (lua_State * L)
{
	LUA_TRACE_POINT;
	return lua_mimepart_get_header_common (L, RSPAMD_TASK_HEADER_PUSH_RAW);
}

static gint
lua_mimepart_get_header_count (lua_State * L)
{
	LUA_TRACE_POINT;
	return lua_mimepart_get_header_common (L, RSPAMD_TASK_HEADER_PUSH_COUNT);
}

static gint
lua_mimepart_get_raw_headers (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_part *part = lua_check_mimepart (L);
	struct rspamd_lua_text *t;

	if (part) {
		t = lua_newuserdata (L, sizeof (*t));
		rspamd_lua_setclass (L, "rspamd{text}", -1);
		t->start = part->raw_headers_str;
		t->len = part->raw_headers_len;
		t->flags = 0;
	}
	else {
		return luaL_error (L, "invalid arguments");
	}


	return 1;
}

static gint
lua_mimepart_get_headers (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_part *part = lua_check_mimepart (L);
	bool need_modified = lua_isnoneornil(L, 2) ? false : lua_toboolean(L, 2);

	if (part) {
		struct rspamd_mime_header *cur;
		int i = 1;

		lua_createtable (L, rspamd_mime_headers_count(part->raw_headers), 0);
		LL_FOREACH2(part->headers_order, cur, ord_next) {
			rspamd_lua_push_header_array(L, cur->name, cur, RSPAMD_TASK_HEADER_PUSH_FULL,
					need_modified);
			lua_rawseti(L, -2, i++);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}


	return 1;
}


static gint
lua_mimepart_is_image (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_part *part = lua_check_mimepart (L);

	if (part == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	lua_pushboolean (L, part->part_type == RSPAMD_MIME_PART_IMAGE);

	return 1;
}

static gint
lua_mimepart_is_archive (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_part *part = lua_check_mimepart (L);

	if (part == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	lua_pushboolean (L, part->part_type == RSPAMD_MIME_PART_ARCHIVE);

	return 1;
}

static gint
lua_mimepart_is_multipart (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_part *part = lua_check_mimepart (L);

	if (part == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	lua_pushboolean (L, IS_PART_MULTIPART (part) ? true : false);

	return 1;
}

static gint
lua_mimepart_is_message (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_part *part = lua_check_mimepart (L);

	if (part == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	lua_pushboolean (L, IS_PART_MESSAGE (part) ? true : false);

	return 1;
}

static gint
lua_mimepart_is_attachment (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_part *part = lua_check_mimepart (L);

	if (part == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	if (part->cd && part->cd->type == RSPAMD_CT_ATTACHMENT) {
		lua_pushboolean (L, true);
	}
	else {
		/* if has_name and not (image and Content-ID_header_present) */
		if (part->cd && part->cd->filename.len > 0) {
			if (part->part_type != RSPAMD_MIME_PART_IMAGE &&
					rspamd_message_get_header_from_hash(part->raw_headers,
							"Content-Id", FALSE) == NULL) {
				/* Filename is presented but no content id and not image */
				lua_pushboolean (L, true);
			}
			else {
				/* Image or an embeded object */
				lua_pushboolean (L, false);
			}
		}
		else {
			/* No filename */
			lua_pushboolean (L, false);
		}
	}

	return 1;
}

static gint
lua_mimepart_is_text (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_part *part = lua_check_mimepart (L);

	if (part == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	lua_pushboolean (L, part->part_type == RSPAMD_MIME_PART_TEXT);

	return 1;
}

static gint
lua_mimepart_is_broken (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_part *part = lua_check_mimepart (L);

	if (part == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	if (part->ct) {
		lua_pushboolean (L, (part->ct->flags & RSPAMD_CONTENT_TYPE_BROKEN) ?
				true : false);
	}
	else {
		lua_pushboolean (L, false);
	}

	return 1;
}

static gint
lua_mimepart_get_image (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_part *part = lua_check_mimepart (L);
	struct rspamd_image **pimg;

	if (part == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	if (part->part_type != RSPAMD_MIME_PART_IMAGE || part->specific.img == NULL) {
		lua_pushnil (L);
	}
	else {
		pimg = lua_newuserdata (L, sizeof (*pimg));
		*pimg = part->specific.img;
		rspamd_lua_setclass (L, "rspamd{image}", -1);
	}

	return 1;
}

static gint
lua_mimepart_get_archive (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_part *part = lua_check_mimepart (L);
	struct rspamd_archive **parch;

	if (part == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	if (part->part_type != RSPAMD_MIME_PART_ARCHIVE || part->specific.arch == NULL) {
		lua_pushnil (L);
	}
	else {
		parch = lua_newuserdata (L, sizeof (*parch));
		*parch = part->specific.arch;
		rspamd_lua_setclass (L, "rspamd{archive}", -1);
	}

	return 1;
}

static gint
lua_mimepart_get_children (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_part *part = lua_check_mimepart (L);
	struct rspamd_mime_part **pcur, *cur;
	guint i;

	if (part == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	if (!IS_PART_MULTIPART (part) || part->specific.mp->children == NULL) {
		lua_pushnil (L);
	}
	else {
		lua_createtable (L, part->specific.mp->children->len, 0);

		PTR_ARRAY_FOREACH (part->specific.mp->children, i, cur) {
			pcur = lua_newuserdata (L, sizeof (*pcur));
			*pcur = cur;
			rspamd_lua_setclass (L, "rspamd{mimepart}", -1);
			lua_rawseti (L, -2, i + 1);
		}
	}

	return 1;
}

static gint
lua_mimepart_get_parent (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_part *part = lua_check_mimepart (L);
	struct rspamd_mime_part **pparent;

	if (part == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	if (part->parent_part) {
		pparent = lua_newuserdata (L, sizeof (*pparent));
		*pparent = part->parent_part;
		rspamd_lua_setclass (L, "rspamd{mimepart}", -1);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}


static gint
lua_mimepart_get_text (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_part *part = lua_check_mimepart (L);
	struct rspamd_mime_text_part **ppart;

	if (part == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	if (part->part_type != RSPAMD_MIME_PART_TEXT || part->specific.txt == NULL) {
		lua_pushnil (L);
	}
	else {
		ppart = lua_newuserdata (L, sizeof (*ppart));
		*ppart = part->specific.txt;
		rspamd_lua_setclass (L, "rspamd{textpart}", -1);
	}

	return 1;
}

static gint
lua_mimepart_get_digest (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_part *part = lua_check_mimepart (L);
	gchar digestbuf[rspamd_cryptobox_HASHBYTES * 2 + 1];

	if (part == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	memset (digestbuf, 0, sizeof (digestbuf));
	rspamd_encode_hex_buf (part->digest, sizeof (part->digest),
			digestbuf, sizeof (digestbuf));
	lua_pushstring (L, digestbuf);

	return 1;
}

static gint
lua_mimepart_get_id (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_part *part = lua_check_mimepart (L);

	if (part == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	lua_pushinteger (L, part->part_number);

	return 1;
}

static gint
lua_mimepart_headers_foreach (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_part *part = lua_check_mimepart (L);
	enum rspamd_lua_task_header_type how = RSPAMD_TASK_HEADER_PUSH_SIMPLE;
	struct rspamd_lua_regexp *re = NULL;
	struct rspamd_mime_header *hdr, *cur;
	gint old_top;

	if (part && lua_isfunction (L, 2)) {
		if (lua_istable (L, 3)) {
			lua_pushstring (L, "full");
			lua_gettable (L, 3);

			if (lua_isboolean (L, -1) && lua_toboolean (L, -1)) {
				how = RSPAMD_TASK_HEADER_PUSH_FULL;
			}

			lua_pop (L, 1);

			lua_pushstring (L, "raw");
			lua_gettable (L, 3);

			if (lua_isboolean (L, -1) && lua_toboolean (L, -1)) {
				how = RSPAMD_TASK_HEADER_PUSH_RAW;
			}

			lua_pop (L, 1);

			lua_pushstring (L, "regexp");
			lua_gettable (L, 3);

			if (lua_isuserdata (L, -1)) {
				RSPAMD_LUA_CHECK_UDATA_PTR_OR_RETURN(L, -1, "rspamd{regexp}",
						struct rspamd_lua_regexp, re);
			}

			lua_pop (L, 1);
		}

		if (part->headers_order) {
			hdr = part->headers_order;

			LL_FOREACH2 (hdr, cur, ord_next) {
				if (re && re->re) {
					if (!rspamd_regexp_match (re->re, cur->name,
							strlen (cur->name),FALSE)) {
						continue;
					}
				}

				old_top = lua_gettop (L);
				lua_pushvalue (L, 2);
				lua_pushstring (L, cur->name);
				rspamd_lua_push_header (L, cur, how);

				if (lua_pcall (L, 2, LUA_MULTRET, 0) != 0) {
					msg_err ("call to header_foreach failed: %s",
							lua_tostring (L, -1));
					lua_settop (L, old_top);
					break;
				}
				else {
					if (lua_gettop (L) > old_top) {
						if (lua_isboolean (L, old_top + 1)) {
							if (lua_toboolean (L, old_top + 1)) {
								lua_settop (L, old_top);
								break;
							}
						}
					}
				}

				lua_settop (L, old_top);
			}
		}
	}

	return 0;
}

static gint
lua_mimepart_get_specific (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_part *part = lua_check_mimepart (L);

	if (part == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	if (part->part_type != RSPAMD_MIME_PART_CUSTOM_LUA) {
		lua_pushnil (L);
	}
	else {
		lua_rawgeti (L, LUA_REGISTRYINDEX, part->specific.lua_specific.cbref);
	}

	return 1;
}

static gint
lua_mimepart_get_urls (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_part *part = lua_check_mimepart (L);

	if (part == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	struct lua_tree_cb_data cb;
	struct rspamd_url *u;
	static const gint default_protocols_mask = PROTOCOL_HTTP|PROTOCOL_HTTPS|
											   PROTOCOL_FILE|PROTOCOL_FTP;
	gsize sz, max_urls = 0, i;

	if (part->urls == NULL) {
		lua_newtable (L);

		return 1;
	}

	if (!lua_url_cbdata_fill (L, 2, &cb, default_protocols_mask,
			~(0), max_urls)) {
		return luaL_error (L, "invalid arguments");
	}

	sz = part->urls->len;

	lua_createtable (L, sz, 0);

	PTR_ARRAY_FOREACH (part->urls, i, u) {
		lua_tree_url_callback (u, u, &cb);
	}

	lua_url_cbdata_dtor (&cb);

	return 1;
}

static gint
lua_mimepart_is_specific (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_part *part = lua_check_mimepart (L);

	if (part == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	lua_pushboolean (L, part->part_type == RSPAMD_MIME_PART_CUSTOM_LUA);

	return 1;
}

static gint
lua_mimepart_set_specific (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_part *part = lua_check_mimepart (L);

	if (part == NULL || lua_isnil (L, 2)) {
		return luaL_error (L, "invalid arguments");
	}

	if (part->part_type != RSPAMD_MIME_PART_UNDEFINED &&
			part->part_type != RSPAMD_MIME_PART_CUSTOM_LUA) {
		return luaL_error (L,
				"internal error: trying to set specific lua content on part of type %d",
				part->part_type);
	}

	if (part->part_type == RSPAMD_MIME_PART_CUSTOM_LUA) {
		/* Push old specific data */
		lua_rawgeti (L, LUA_REGISTRYINDEX, part->specific.lua_specific.cbref);
		luaL_unref (L, LUA_REGISTRYINDEX, part->specific.lua_specific.cbref);
	}
	else {
		part->part_type = RSPAMD_MIME_PART_CUSTOM_LUA;
		lua_pushnil (L);
	}

	/* Now, we push argument on the position 2 and save its reference */
	lua_pushvalue (L, 2);
	part->specific.lua_specific.cbref = luaL_ref (L, LUA_REGISTRYINDEX);
	/* Now stack has just a return value as luaL_ref removes value from stack */

	gint ltype = lua_type (L, 2);

	switch (ltype) {
	case LUA_TTABLE:
		part->specific.lua_specific.type = RSPAMD_LUA_PART_TABLE;
		break;
	case LUA_TSTRING:
		part->specific.lua_specific.type = RSPAMD_LUA_PART_STRING;
		break;
	case LUA_TUSERDATA:
		if (rspamd_lua_check_udata_maybe (L, 2, "rspamd{text}")) {
			part->specific.lua_specific.type = RSPAMD_LUA_PART_TEXT;
		}
		else {
			part->specific.lua_specific.type = RSPAMD_LUA_PART_UNKNOWN;
		}
		break;
	case LUA_TFUNCTION:
		part->specific.lua_specific.type = RSPAMD_LUA_PART_FUNCTION;
		break;
	default:
		part->specific.lua_specific.type = RSPAMD_LUA_PART_UNKNOWN;
		break;
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

