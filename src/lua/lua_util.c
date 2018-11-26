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
#include "html.h"
#include "tokenizers/tokenizers.h"
#include "unix-std.h"
#include "contrib/zstd/zstd.h"
#include "libmime/email_addr.h"
#include "linenoise.h"
#include <math.h>
#include <glob.h>
#include <zlib.h>

#include "unicode/uspoof.h"

/***
 * @module rspamd_util
 * This module contains some generic purpose utilities that could be useful for
 * testing and production rules.
 */

/***
 * @function util.create_event_base()
 * Creates new event base for processing asynchronous events
 * @return {ev_base} new event processing base
 */
LUA_FUNCTION_DEF (util, create_event_base);
/***
 * @function util.load_rspamd_config(filename)
 * Load rspamd config from the specified file
 * @return {confg} new configuration object suitable for access
 */
LUA_FUNCTION_DEF (util, load_rspamd_config);
/***
 * @function util.config_from_ucl(any, string)
 * Load rspamd config from ucl reperesented by any lua table
 * @return {confg} new configuration object suitable for access
 */
LUA_FUNCTION_DEF (util, config_from_ucl);
/***
 * @function util.encode_base64(input[, str_len, [newlines_type]])
 * Encodes data in base64 breaking lines if needed
 * @param {text or string} input input data
 * @param {number} str_len optional size of lines or 0 if split is not needed
 * @return {rspamd_text} encoded data chunk
 */
LUA_FUNCTION_DEF (util, encode_base64);
/***
 * @function util.decode_base64(input)
 * Decodes data from base64 ignoring whitespace characters
 * @param {text or string} input data to decode; if `rspamd{text}` is used then the string is modified **in-place**
 * @return {rspamd_text} decoded data chunk
 */
LUA_FUNCTION_DEF (util, decode_base64);

/***
 * @function util.encode_base32(input)
 * Encodes data in base32 breaking lines if needed
 * @param {text or string} input input data
 * @return {rspamd_text} encoded data chunk
 */
LUA_FUNCTION_DEF (util, encode_base32);
/***
 * @function util.decode_base32(input)
 * Decodes data from base32 ignoring whitespace characters
 * @param {text or string} input data to decode
 * @return {rspamd_text} decoded data chunk
 */
LUA_FUNCTION_DEF (util, decode_base32);

/***
 * @function util.decode_url(input)
 * Decodes data from url encoding
 * @param {text or string} input data to decode
 * @return {rspamd_text} decoded data chunk
 */
LUA_FUNCTION_DEF (util, decode_url);

/***
 * @function util.tokenize_text(input[, exceptions])
 * Create tokens from a text using optional exceptions list
 * @param {text/string} input input data
 * @param {table} exceptions, a table of pairs containing <start_pos,length> of exceptions in the input
 * @return {table/strings} list of strings representing words in the text
 */
LUA_FUNCTION_DEF (util, tokenize_text);
LUA_FUNCTION_DEF (util, process_message);
/***
 * @function util.tanh(num)
 * Calculates hyperbolic tanhent of the specified floating point value
 * @param {number} num input number
 * @return {number} hyperbolic tanhent of the variable
 */
LUA_FUNCTION_DEF (util, tanh);

/***
 * @function util.parse_html(input)
 * Parses HTML and returns the according text
 * @param {string|text} in input HTML
 * @return {rspamd_text} processed text with no HTML tags
 */
LUA_FUNCTION_DEF (util, parse_html);

/***
 * @function util.levenshtein_distance(s1, s2)
 * Returns levenstein distance between two strings
 * @param {string} s1 the first string
 * @param {string} s2 the second string
 * @return {number} number of differences in two strings
 */
LUA_FUNCTION_DEF (util, levenshtein_distance);

/***
 * @function util.parse_addr(str)
 * Parse rfc822 address to components. Returns a table of components:
 *
 * - `name`: name of address (e.g. Some User)
 * - `addr`: address part (e.g. user@example.com)
 *
 * @param {string} str input string
 * @return {table} resulting table of components
 */
LUA_FUNCTION_DEF (util, parse_addr);

/***
 * @function util.fold_header(name, value, [how, [stop_chars]])
 * Fold rfc822 header according to the folding rules
 *
 * @param {string} name name of the header
 * @param {string} value value of the header
 * @param {string} how "cr" for \r, "lf" for \n and "crlf" for \r\n (default)
 * @param {string} stop_chars also fold header when the
 * @return {string} Folded value of the header
 */
LUA_FUNCTION_DEF (util, fold_header);

/***
 * @function util.is_uppercase(str)
 * Returns true if a string is all uppercase
 *
 * @param {string} str input string
 * @return {bool} true if a string is all uppercase
 */
LUA_FUNCTION_DEF (util, is_uppercase);

/***
 * @function util.humanize_number(num)
 * Returns humanized representation of given number (like 1k instead of 1000)
 *
 * @param {number} num number to humanize
 * @return {string} humanized representation of a number
 */
LUA_FUNCTION_DEF (util, humanize_number);

/***
 * @function util.get_tld(host)
 * Returns effective second level domain part (eSLD) for the specified host
 *
 * @param {string} host hostname
 * @return {string} eSLD part of the hostname or the full hostname if eSLD was not found
 */
LUA_FUNCTION_DEF (util, get_tld);

/***
 * @function util.glob(pattern)
 * Returns results for the glob match for the specified pattern
 *
 * @param {string} pattern glob pattern to match ('?' and '*' are supported)
 * @return {table/string} list of matched files
 */
LUA_FUNCTION_DEF (util, glob);

/***
 * @function util.parse_mail_address(str, pool)
 * Parses email address and returns a table of tables in the following format:
 *
 * - `name` - name of internet address in UTF8, e.g. for `Vsevolod Stakhov <blah@foo.com>` it returns `Vsevolod Stakhov`
 * - `addr` - address part of the address
 * - `user` - user part (if present) of the address, e.g. `blah`
 * - `domain` - domain part (if present), e.g. `foo.com`
 *
 * @param {string} str input string
 * @param {rspamd_mempool} pool memory pool to use
 * @return {table/tables} parsed list of mail addresses
 */
LUA_FUNCTION_DEF (util, parse_mail_address);

/***
 * @function util.strlen_utf8(str)
 * Returns length of string encoded in utf-8 in characters.
 * If invalid characters are found, then this function returns number of bytes.
 * @param {string} str utf8 encoded string
 * @return {number} number of characters in string
 */
LUA_FUNCTION_DEF (util, strlen_utf8);

/***
 * @function util.strcasecmp(str1, str2)
 * Compares two utf8 strings regardless of their case. Return value >0, 0 and <0
 * if `str1` is more, equal or less than `str2`
 * @param {string} str1 utf8 encoded string
 * @param {string} str2 utf8 encoded string
 * @return {number} result of comparison
 */
LUA_FUNCTION_DEF (util, strcasecmp_utf8);

/***
 * @function util.strcasecmp(str1, str2)
 * Compares two ascii strings regardless of their case. Return value >0, 0 and <0
 * if `str1` is more, equal or less than `str2`
 * @param {string} str1 plain string
 * @param {string} str2 plain string
 * @return {number} result of comparison
 */
LUA_FUNCTION_DEF (util, strcasecmp_ascii);

/***
 * @function util.strequal_caseless(str1, str2)
 * Compares two utf8 strings regardless of their case. Return `true` if `str1` is
 * equal to `str2`
 * @param {string} str1 utf8 encoded string
 * @param {string} str2 utf8 encoded string
 * @return {bool} result of comparison
 */
LUA_FUNCTION_DEF (util, strequal_caseless);

/***
 * @function util.get_ticks()
 * Returns current number of ticks as floating point number
 * @return {number} number of current clock ticks (monotonically increasing)
 */
LUA_FUNCTION_DEF (util, get_ticks);

/***
 * @function util.get_time()
 * Returns current time as unix time in floating point representation
 * @return {number} number of seconds since 01.01.1970
 */
LUA_FUNCTION_DEF (util, get_time);

/***
 * @function util.time_to_string(seconds)
 * Converts time from Unix time to HTTP date format
 * @param {number} seconds unix timestamp
 * @return {string} date as HTTP date
 */
LUA_FUNCTION_DEF (util, time_to_string);

/***
 * @function util.stat(fname)
 * Performs stat(2) on a specified filepath and returns table of values
 *
 * - `size`: size of file in bytes
 * - `type`: type of filepath: `regular`, `directory`, `special`
 * - `mtime`: modification time as unix time
 *
 * @return {string,table} string is returned when error is occurred
 * @example
 *
 * local err,st = util.stat('/etc/password')
 *
 * if err then
 *   -- handle error
 * else
 *   print(st['size'])
 * end
 */
LUA_FUNCTION_DEF (util, stat);

/***
 * @function util.unlink(fname)
 * Removes the specified file from the filesystem
 *
 * @param {string} fname filename to remove
 * @return {boolean,[string]} true if file has been deleted or false,'error string'
 */
LUA_FUNCTION_DEF (util, unlink);

/***
 * @function util.lock_file(fname, [fd])
 * Lock the specified file. This function returns {number} which must be passed to `util.unlock_file` after usage
 * or you'll have a resource leak
 *
 * @param {string} fname filename to lock
 * @param {number} fd use the specified fd instead of opening one
 * @return {number|nil,string} number if locking was successful or nil + error otherwise
 */
LUA_FUNCTION_DEF (util, lock_file);

/***
 * @function util.unlock_file(fd, [close_fd])
 * Unlock the specified file closing the file descriptor associated.
 *
 * @param {number} fd descriptor to unlock
 * @param {boolean} close_fd close descriptor on unlocking (default: TRUE)
 * @return {boolean[,string]} true if a file was unlocked
 */
LUA_FUNCTION_DEF (util, unlock_file);

/***
 * @function util.create_file(fname, [mode])
 * Creates the specified file with the default mode 0644
 *
 * @param {string} fname filename to create
 * @param {number} mode open mode (you should use octal number here)
 * @return {number|nil,string} file descriptor or pair nil + error string
 */
LUA_FUNCTION_DEF (util, create_file);

/***
 * @function util.close_file(fd)
 * Closes descriptor fd
 *
 * @param {number} fd descriptor to close
 * @return {boolean[,string]} true if a file was closed
 */
LUA_FUNCTION_DEF (util, close_file);

/***
 * @function util.random_hex(size)
 * Returns random hex string of the specified size
 *
 * @param {number} len length of desired string in bytes
 * @return {string} string with random hex digests
 */
LUA_FUNCTION_DEF (util, random_hex);

/***
 * @function util.zstd_compress(data)
 * Compresses input using zstd compression
 *
 * @param {string/rspamd_text} data input data
 * @return {rspamd_text} compressed data
 */
LUA_FUNCTION_DEF (util, zstd_compress);

/***
 * @function util.zstd_decompress(data)
 * Decompresses input using zstd algorithm
 *
 * @param {string/rspamd_text} data compressed data
 * @return {error,rspamd_text} pair of error + decompressed text
 */
LUA_FUNCTION_DEF (util, zstd_decompress);

/***
 * @function util.gzip_decompress(data)
 * Decompresses input using gzip algorithm
 *
 * @param {string/rspamd_text} data compressed data
 * @return {error,rspamd_text} pair of error + decompressed text
 */
LUA_FUNCTION_DEF (util, gzip_decompress);

/***
 * @function util.gzip_compress(data)
 * Compresses input using gzip compression
 *
 * @param {string/rspamd_text} data input data
 * @return {rspamd_text} compressed data
 */
LUA_FUNCTION_DEF (util, gzip_compress);

/***
 * @function util.normalize_prob(prob, [bias = 0.5])
 * Normalize probabilities using polynom
 *
 * @param {number} prob probability param
 * @param {number} bias number to subtract for making the final solution
 * @return {number} normalized number
 */
LUA_FUNCTION_DEF (util, normalize_prob);
/***
 * @function util.is_utf_spoofed(str, [str2])
 * Returns true if a string is spoofed (possibly with another string `str2`)
 * @return {boolean} true if a string is spoofed
 */
LUA_FUNCTION_DEF (util, is_utf_spoofed);

/***
 * @function util.is_valid_utf8(str)
 * Returns true if a string is valid UTF8 string
 * @return {boolean} true if a string is spoofed
 */
LUA_FUNCTION_DEF (util, is_valid_utf8);

/***
 * @function util.readline([prompt])
 * Returns string read from stdin with history and editing support
 * @return {string} string read from the input (with line endings stripped)
 */
LUA_FUNCTION_DEF (util, readline);

/***
 * @function util.readpassphrase([prompt])
 * Returns string read from stdin disabling echo
 * @return {string} string read from the input (with line endings stripped)
 */
LUA_FUNCTION_DEF (util, readpassphrase);

/***
 * @function util.file_exists(file)
 * Checks if a specified file exists and is available for reading
 * @return {boolean,string} true if file exists + string error if not
 */
LUA_FUNCTION_DEF (util, file_exists);

/***
 * @function util.mkdir(dir[, recursive])
 * Creates a specified directory
 * @return {boolean[,error]} true if directory has been created
 */
LUA_FUNCTION_DEF (util, mkdir);

/***
 * @function util.umask(mask)
 * Sets new umask. Accepts either numeric octal string, e.g. '022' or a plain
 * number, e.g. 0x12 (since Lua does not support octal integrals)
 * @return {number} old umask
 */
LUA_FUNCTION_DEF (util, umask);

/***
 * @function util.isatty()
 * Returns if stdout is a tty
 * @return {boolean} true in case of output being tty
 */
LUA_FUNCTION_DEF (util, isatty);

/***
 * @function util.pack(fmt, ...)
 *
 * Backport of Lua 5.3 `string.pack` function:
 * Returns a binary string containing the values v1, v2, etc. packed (that is,
 * serialized in binary form) according to the format string `fmt`
 * A format string is a sequence of conversion options. The conversion
 * options are as follows:
 *
 *    * <: sets little endian
 *    * >: sets big endian
 *    * =: sets native endian
 *    * ![n]: sets maximum alignment to n (default is native alignment)
 *    * b: a signed byte (char)
 *    * B: an unsigned byte (char)
 *    * h: a signed short (native size)
 *    * H: an unsigned short (native size)
 *    * l: a signed long (native size)
 *    * L: an unsigned long (native size)
 *    * j: a lua_Integer
 *    * J: a lua_Unsigned
 *    * T: a size_t (native size)
 *    * i[n]: a signed int with n bytes (default is native size)
 *    * I[n]: an unsigned int with n bytes (default is native size)
 *    * f: a float (native size)
 *    * d: a double (native size)
 *    * n: a lua_Number
 *    * cn: a fixed-sized string with n bytes
 *    * z: a zero-terminated string
 *    * s[n]: a string preceded by its length coded as an unsigned integer with
 *    * n bytes (default is a size_t)
 *    * x: one byte of padding
 *    * Xop: an empty item that aligns according to option op (which is otherwise ignored)
 *    * ' ': (empty space) ignored
 *
 * (A "[n]" means an optional integral numeral.) Except for padding, spaces,
 * and configurations (options "xX <=>!"), each option corresponds to an
 * argument (in string.pack) or a result (in string.unpack).
 *
 * For options "!n", "sn", "in", and "In", n can be any integer between 1 and
 * All integral options check overflows; string.pack checks whether the given
 * value fits in the given size; string.unpack checks whether the read value
 * fits in a Lua integer.
 *
 * Any format string starts as if prefixed by "!1=", that is, with maximum
 * alignment of 1 (no alignment) and native endianness.
 *
 * Alignment works as follows: For each option, the format gets extra padding
 * until the data starts at an offset that is a multiple of the minimum
 * between the option size and the maximum alignment; this minimum must be a
 * power of 2. Options "c" and "z" are not aligned; option "s" follows the
 * alignment of its starting integer.
 *
 * All padding is filled with zeros by string.pack (and ignored by unpack).
 */
LUA_FUNCTION_DEF (util, pack);

/***
 * @function util.packsize(fmt)
 *
 * Returns size of the packed binary string returned for the same `fmt` argument
 * by @see util.pack
 */
LUA_FUNCTION_DEF (util, packsize);

/***
 * @function util.unpack(fmt, s [, pos])
 * Unpacks string `s` according to the format string `fmt` as described in
 * @see util.pack
 *
 * @returns {multiple} list of unpacked values according to `fmt`
 */
LUA_FUNCTION_DEF (util, unpack);

/***
 *  @function util.caseless_hash(str[, seed])
 * Calculates caseless non-crypto hash from a string or rspamd text
 * @param str string or lua_text
 * @param seed mandatory seed (0xdeadbabe by default)
 * @return {int64} boxed int64_t
 */
LUA_FUNCTION_DEF (util, caseless_hash);

/***
 *  @function util.caseless_hash_fast(str[, seed])
 * Calculates caseless non-crypto hash from a string or rspamd text
 * @param str string or lua_text
 * @param seed mandatory seed (0xdeadbabe by default)
 * @return {number} number from int64_t
 */
LUA_FUNCTION_DEF (util, caseless_hash_fast);

/***
 *  @function util.get_hostname()
 * Returns hostname for this machine
 * @return {string} hostname
 */
LUA_FUNCTION_DEF (util, get_hostname);


static const struct luaL_reg utillib_f[] = {
	LUA_INTERFACE_DEF (util, create_event_base),
	LUA_INTERFACE_DEF (util, load_rspamd_config),
	LUA_INTERFACE_DEF (util, config_from_ucl),
	LUA_INTERFACE_DEF (util, process_message),
	LUA_INTERFACE_DEF (util, encode_base64),
	LUA_INTERFACE_DEF (util, decode_base64),
	LUA_INTERFACE_DEF (util, encode_base32),
	LUA_INTERFACE_DEF (util, decode_base32),
	LUA_INTERFACE_DEF (util, decode_url),
	LUA_INTERFACE_DEF (util, tokenize_text),
	LUA_INTERFACE_DEF (util, tanh),
	LUA_INTERFACE_DEF (util, parse_html),
	LUA_INTERFACE_DEF (util, levenshtein_distance),
	LUA_INTERFACE_DEF (util, parse_addr),
	LUA_INTERFACE_DEF (util, fold_header),
	LUA_INTERFACE_DEF (util, is_uppercase),
	LUA_INTERFACE_DEF (util, humanize_number),
	LUA_INTERFACE_DEF (util, get_tld),
	LUA_INTERFACE_DEF (util, glob),
	LUA_INTERFACE_DEF (util, parse_mail_address),
	LUA_INTERFACE_DEF (util, strlen_utf8),
	LUA_INTERFACE_DEF (util, strcasecmp_utf8),
	LUA_INTERFACE_DEF (util, strcasecmp_ascii),
	LUA_INTERFACE_DEF (util, strequal_caseless),
	LUA_INTERFACE_DEF (util, get_ticks),
	LUA_INTERFACE_DEF (util, get_time),
	LUA_INTERFACE_DEF (util, time_to_string),
	LUA_INTERFACE_DEF (util, stat),
	LUA_INTERFACE_DEF (util, unlink),
	LUA_INTERFACE_DEF (util, lock_file),
	LUA_INTERFACE_DEF (util, unlock_file),
	LUA_INTERFACE_DEF (util, create_file),
	LUA_INTERFACE_DEF (util, close_file),
	LUA_INTERFACE_DEF (util, random_hex),
	LUA_INTERFACE_DEF (util, zstd_compress),
	LUA_INTERFACE_DEF (util, zstd_decompress),
	LUA_INTERFACE_DEF (util, gzip_compress),
	LUA_INTERFACE_DEF (util, gzip_decompress),
	LUA_INTERFACE_DEF (util, normalize_prob),
	LUA_INTERFACE_DEF (util, caseless_hash),
	LUA_INTERFACE_DEF (util, caseless_hash_fast),
	LUA_INTERFACE_DEF (util, is_utf_spoofed),
	LUA_INTERFACE_DEF (util, is_valid_utf8),
	LUA_INTERFACE_DEF (util, readline),
	LUA_INTERFACE_DEF (util, readpassphrase),
	LUA_INTERFACE_DEF (util, file_exists),
	LUA_INTERFACE_DEF (util, mkdir),
	LUA_INTERFACE_DEF (util, umask),
	LUA_INTERFACE_DEF (util, isatty),
	LUA_INTERFACE_DEF (util, get_hostname),
	LUA_INTERFACE_DEF (util, pack),
	LUA_INTERFACE_DEF (util, unpack),
	LUA_INTERFACE_DEF (util, packsize),
	{NULL, NULL}
};

LUA_FUNCTION_DEF (int64, tostring);
LUA_FUNCTION_DEF (int64, tonumber);
LUA_FUNCTION_DEF (int64, hex);

static const struct luaL_reg int64lib_m[] = {
	LUA_INTERFACE_DEF (int64, tostring),
	LUA_INTERFACE_DEF (int64, tonumber),
	LUA_INTERFACE_DEF (int64, hex),
	{"__tostring", lua_int64_tostring},
	{NULL, NULL}
};

LUA_FUNCTION_DEF (ev_base, loop);

static const struct luaL_reg ev_baselib_m[] = {
	LUA_INTERFACE_DEF (ev_base, loop),
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};

static gint64
lua_check_int64 (lua_State * L, gint pos)
{
	void *ud = rspamd_lua_check_udata (L, pos, "rspamd{int64}");
	luaL_argcheck (L, ud != NULL, pos, "'int64' expected");
	return ud ? *((gint64 *)ud) : 0LL;
}


static gint
lua_util_create_event_base (lua_State *L)
{
	LUA_TRACE_POINT;
	struct event_base **pev_base;

	pev_base = lua_newuserdata (L, sizeof (struct event_base *));
	rspamd_lua_setclass (L, "rspamd{ev_base}", -1);
	*pev_base = event_init ();

	return 1;
}

static gint
lua_util_load_rspamd_config (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg, **pcfg;
	const gchar *cfg_name;

	cfg_name = luaL_checkstring (L, 1);

	if (cfg_name) {
		cfg = rspamd_config_new (RSPAMD_CONFIG_INIT_SKIP_LUA);
		cfg->lua_state = L;

		if (rspamd_config_read (cfg, cfg_name, NULL, NULL, NULL)) {
			msg_err_config ("cannot load config from %s", cfg_name);
			lua_pushnil (L);
		}
		else {
			rspamd_config_post_load (cfg, 0);
			pcfg = lua_newuserdata (L, sizeof (struct rspamd_config *));
			rspamd_lua_setclass (L, "rspamd{config}", -1);
			*pcfg = cfg;
		}
	}

	return 1;
}

static gint
parse_config_options (const char *str_options)
{
	gint ret = 0;
	gchar **vec;
	const gchar *str;
	guint i, l;

	vec = g_strsplit_set (str_options, ",;", -1);
	if (vec) {
		l = g_strv_length (vec);
		for (i = 0; i < l; i ++) {
			str = vec[i];

			if (g_ascii_strcasecmp (str, "INIT_URL") == 0) {
				ret |= RSPAMD_CONFIG_INIT_URL;
			} else if (g_ascii_strcasecmp (str, "INIT_LIBS") == 0) {
				ret |= RSPAMD_CONFIG_INIT_LIBS;
			} else if (g_ascii_strcasecmp (str, "INIT_SYMCACHE") == 0) {
				ret |= RSPAMD_CONFIG_INIT_SYMCACHE;
			} else if (g_ascii_strcasecmp (str, "INIT_VALIDATE") == 0) {
				ret |= RSPAMD_CONFIG_INIT_VALIDATE;
			} else if (g_ascii_strcasecmp (str, "INIT_NO_TLD") == 0) {
				ret |= RSPAMD_CONFIG_INIT_NO_TLD;
			} else if (g_ascii_strcasecmp (str, "INIT_PRELOAD_MAPS") == 0) {
				ret |= RSPAMD_CONFIG_INIT_PRELOAD_MAPS;
			} else {
				msg_warn ("bad type: %s", str);
			}
		}

		g_strfreev (vec);
	}

	return ret;
}

static gint
lua_util_config_from_ucl (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = NULL, **pcfg;
	struct rspamd_rcl_section *top;
	GError *err = NULL;
	ucl_object_t *obj;
	const char *str_options = NULL;
	gint int_options = 0;


	obj = ucl_object_lua_import (L, 1);
	if (lua_gettop (L) == 2) {
		if (lua_type (L, 2) == LUA_TSTRING) {
			str_options = lua_tostring (L, 2);
			int_options = parse_config_options(str_options);
		}
		else {
			msg_err_config ("config_from_ucl: second parameter is expected to be string");
			ucl_object_unref (obj);
			lua_pushnil (L);
		}
	}

	if (obj) {
		cfg = rspamd_config_new (RSPAMD_CONFIG_INIT_SKIP_LUA);
		cfg->lua_state = L;

		cfg->rcl_obj = obj;
		cfg->cache = rspamd_symcache_new (cfg);
		top = rspamd_rcl_config_init (cfg, NULL);

		if (!rspamd_rcl_parse (top, cfg, cfg, cfg->cfg_pool, cfg->rcl_obj, &err)) {
			msg_err_config ("rcl parse error: %s", err->message);
			ucl_object_unref (obj);
			lua_pushnil (L);
		}
		else {

			if (int_options & RSPAMD_CONFIG_INIT_LIBS) {
				cfg->libs_ctx = rspamd_init_libs ();
			}

			rspamd_config_post_load (cfg, int_options);
			pcfg = lua_newuserdata (L, sizeof (struct rspamd_config *));
			rspamd_lua_setclass (L, "rspamd{config}", -1);
			*pcfg = cfg;
		}
	}

	return 1;
}

static gboolean
lua_util_task_fin (struct rspamd_task *task, void *ud)
{
	ucl_object_t **target = ud;

	*target = rspamd_protocol_write_ucl (task, RSPAMD_PROTOCOL_DEFAULT);
	rdns_resolver_release (task->resolver->r);

	return TRUE;
}

static gint
lua_util_process_message (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config (L, 1);
	const gchar *message;
	gsize mlen;
	struct rspamd_task *task;
	struct event_base *base;
	ucl_object_t *res = NULL;

	message = luaL_checklstring (L, 2, &mlen);

	if (cfg != NULL && message != NULL) {
		base = event_init ();
		rspamd_init_filters (cfg, FALSE);
		task = rspamd_task_new (NULL, cfg, NULL, NULL, base);
		task->msg.begin = rspamd_mempool_alloc (task->task_pool, mlen);
		rspamd_strlcpy ((gpointer)task->msg.begin, message, mlen);
		task->msg.len = mlen;
		task->fin_callback = lua_util_task_fin;
		task->fin_arg = &res;
		task->resolver = dns_resolver_init (NULL, base, cfg);
		task->s = rspamd_session_create (task->task_pool, rspamd_task_fin,
					rspamd_task_restore, (event_finalizer_t)rspamd_task_free, task);

		if (!rspamd_task_load_message (task, NULL, message, mlen)) {
			lua_pushnil (L);
		}
		else {
			if (rspamd_task_process (task, RSPAMD_TASK_PROCESS_ALL)) {
				event_base_loop (base, 0);

				if (res != NULL) {
					ucl_object_push_lua (L, res, true);

					ucl_object_unref (res);
				}
				else {
					ucl_object_push_lua (L,
							rspamd_protocol_write_ucl (task, RSPAMD_PROTOCOL_DEFAULT),
							true);
					rdns_resolver_release (task->resolver->r);
					rspamd_session_destroy (task->s);
				}
			}
			else {
				lua_pushnil (L);
			}
		}

		event_base_free (base);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_util_encode_base64 (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_text *t;
	const gchar *s = NULL;
	gchar *out;
	gsize inlen, outlen;
	guint str_lim = 0;
	gboolean fold = FALSE;

	if (lua_type (L, 1) == LUA_TSTRING) {
		s = luaL_checklstring (L, 1, &inlen);
	}
	else if (lua_type (L, 1) == LUA_TUSERDATA) {
		t = lua_check_text (L, 1);

		if (t != NULL) {
			s = t->start;
			inlen = t->len;
		}
	}

	if (lua_gettop (L) > 1) {
		str_lim = luaL_checknumber (L, 2);

		fold = !!(str_lim > 0);
	}

	if (s == NULL) {
		lua_pushnil (L);
	}
	else {

		if (fold) {
			out = rspamd_encode_base64 (s, inlen, str_lim, &outlen);
		}
		else {
			enum rspamd_newlines_type how = RSPAMD_TASK_NEWLINES_CRLF;

			if (lua_type (L, 3) == LUA_TSTRING) {
				const gchar *how_str = lua_tostring (L, 3);

				if (g_ascii_strcasecmp (how_str, "cr") == 0) {
					how = RSPAMD_TASK_NEWLINES_CR;
				}
				else if (g_ascii_strcasecmp (how_str, "lf") == 0) {
					how = RSPAMD_TASK_NEWLINES_LF;
				}
				else if (g_ascii_strcasecmp (how_str, "crlf") != 0) {
					return luaL_error (L, "invalid newline style: %s", how_str);
				}
			}

			out = rspamd_encode_base64_fold (s, inlen, str_lim, &outlen, how);
		}

		if (out != NULL) {
			t = lua_newuserdata (L, sizeof (*t));
			rspamd_lua_setclass (L, "rspamd{text}", -1);
			t->start = out;
			t->len = outlen;
			/* Need destruction */
			t->flags = RSPAMD_TEXT_FLAG_OWN;
		}
		else {
			lua_pushnil (L);
		}
	}

	return 1;
}

static gint
lua_util_decode_base64 (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_text *t;
	const gchar *s = NULL;
	gsize inlen, outlen;
	gboolean zero_copy = FALSE, grab_own = FALSE;
	gint state = 0;
	guint save = 0;

	if (lua_type (L, 1) == LUA_TSTRING) {
		s = luaL_checklstring (L, 1, &inlen);
	}
	else if (lua_type (L, 1) == LUA_TUSERDATA) {
		t = lua_check_text (L, 1);

		if (t != NULL) {
			s = t->start;
			inlen = t->len;
		}
	}

	if (s != NULL) {
		if (zero_copy) {
			/* Decode in place */
			outlen = g_base64_decode_step (s, inlen, (guchar *)s, &state, &save);
			t = lua_newuserdata (L, sizeof (*t));
			rspamd_lua_setclass (L, "rspamd{text}", -1);
			t->start = s;
			t->len = outlen;

			if (grab_own) {
				t->flags |= RSPAMD_TEXT_FLAG_OWN;
			}
			else {
				t->flags = 0;
			}
		}
		else {
			t = lua_newuserdata (L, sizeof (*t));
			rspamd_lua_setclass (L, "rspamd{text}", -1);
			t->len = (inlen / 4) * 3 + 3;
			t->start = g_malloc (t->len);
			outlen = g_base64_decode_step (s, inlen, (guchar *)t->start,
					&state, &save);
			t->len = outlen;
			t->flags = RSPAMD_TEXT_FLAG_OWN;
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_util_encode_base32 (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_text *t;
	const gchar *s = NULL;
	gchar *out;
	gsize inlen, outlen;

	if (lua_type (L, 1) == LUA_TSTRING) {
		s = luaL_checklstring (L, 1, &inlen);
	}
	else if (lua_type (L, 1) == LUA_TUSERDATA) {
		t = lua_check_text (L, 1);

		if (t != NULL) {
			s = t->start;
			inlen = t->len;
		}
	}

	if (s == NULL) {
		lua_pushnil (L);
	}
	else {
		out = rspamd_encode_base32 (s, inlen);

		if (out != NULL) {
			t = lua_newuserdata (L, sizeof (*t));
			outlen = strlen (out);
			rspamd_lua_setclass (L, "rspamd{text}", -1);
			t->start = out;
			t->len = outlen;
			/* Need destruction */
			t->flags = RSPAMD_TEXT_FLAG_OWN;
		}
		else {
			lua_pushnil (L);
		}
	}

	return 1;
}

static gint
lua_util_decode_base32 (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_text *t;
	const gchar *s = NULL;
	gsize inlen, outlen;

	if (lua_type (L, 1) == LUA_TSTRING) {
		s = luaL_checklstring (L, 1, &inlen);
	}
	else if (lua_type (L, 1) == LUA_TUSERDATA) {
		t = lua_check_text (L, 1);

		if (t != NULL) {
			s = t->start;
			inlen = t->len;
		}
	}

	if (s != NULL) {
		t = lua_newuserdata (L, sizeof (*t));
		rspamd_lua_setclass (L, "rspamd{text}", -1);
		t->start = rspamd_decode_base32 (s, inlen, &outlen);
		t->len = outlen;
		t->flags = RSPAMD_TEXT_FLAG_OWN;
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_util_decode_url (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_text *t;
	const gchar *s = NULL;
	gsize inlen;

	if (lua_type (L, 1) == LUA_TSTRING) {
		s = luaL_checklstring (L, 1, &inlen);
	}
	else if (lua_type (L, 1) == LUA_TUSERDATA) {
		t = lua_check_text (L, 1);

		if (t != NULL) {
			s = t->start;
			inlen = t->len;
		}
	}

	if (s != NULL) {
		t = lua_newuserdata (L, sizeof (*t));
		rspamd_lua_setclass (L, "rspamd{text}", -1);
		t->start = g_malloc (inlen);
		memcpy ((char *)t->start, s, inlen);
		t->len = rspamd_url_decode ((char *)t->start, s, inlen);
		t->flags = RSPAMD_TEXT_FLAG_OWN;
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}


static gint
lua_util_tokenize_text (lua_State *L)
{
	LUA_TRACE_POINT;
	const gchar *in = NULL;
	gsize len, pos, ex_len, i;
	GList *exceptions = NULL, *cur;
	struct rspamd_lua_text *t;
	struct rspamd_process_exception *ex;
	UText utxt = UTEXT_INITIALIZER;
	GArray *res;
	rspamd_stat_token_t *w;

	if (lua_type (L, 1) == LUA_TSTRING) {
		in = luaL_checklstring (L, 1, &len);
	}
	else if (lua_type (L, 1) == LUA_TUSERDATA) {
		t = lua_check_text (L, 1);

		if (t) {
			in = t->start;
			len = t->len;
		}
	}

	if (in == NULL) {
		lua_pushnil (L);
		return 1;
	}

	if (lua_gettop (L) > 1 && lua_type (L, 2) == LUA_TTABLE) {
		lua_pushvalue (L, 2);
		lua_pushnil (L);

		while (lua_next (L, -2) != 0) {
			if (lua_type (L, -1) == LUA_TTABLE) {
				lua_rawgeti (L, -1, 1);
				pos = luaL_checknumber (L, -1);
				lua_pop (L, 1);
				lua_rawgeti (L, -1, 2);
				ex_len = luaL_checknumber (L, -1);
				lua_pop (L, 1);

				if (ex_len > 0) {
					ex = g_malloc0 (sizeof (*ex));
					ex->pos = pos;
					ex->len = ex_len;
					ex->type = RSPAMD_EXCEPTION_GENERIC;
					exceptions = g_list_prepend (exceptions, ex);
				}
			}
			lua_pop (L, 1);
		}

		lua_pop (L, 1);
	}

	if (exceptions) {
		exceptions = g_list_reverse (exceptions);
	}

	UErrorCode uc_err = U_ZERO_ERROR;
	utext_openUTF8 (&utxt,
			in,
			len,
			&uc_err);

	res = rspamd_tokenize_text ((gchar *)in, len,
			&utxt,
			RSPAMD_TOKENIZE_UTF, NULL,
			exceptions,
			NULL, NULL);

	if (res == NULL) {
		lua_pushnil (L);
	}
	else {
		lua_createtable (L, res->len, 0);

		for (i = 0; i < res->len; i ++) {
			w = &g_array_index (res, rspamd_stat_token_t, i);
			lua_pushlstring (L, w->original.begin, w->original.len);
			lua_rawseti (L, -2, i + 1);
		}
	}

	cur = exceptions;
	while (cur) {
		ex = cur->data;
		g_free (ex);
		cur = g_list_next (cur);
	}

	g_list_free (exceptions);
	utext_close (&utxt);

	return 1;
}

static gint
lua_util_tanh (lua_State *L)
{
	LUA_TRACE_POINT;
	gdouble in = luaL_checknumber (L, 1);

	lua_pushnumber (L, tanh (in));

	return 1;
}

static gint
lua_util_parse_html (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_text *t;
	const gchar *start = NULL;
	gsize len;
	GByteArray *res, *in;
	rspamd_mempool_t *pool;
	struct html_content *hc;

	if (lua_type (L, 1) == LUA_TUSERDATA) {
		t = lua_check_text (L, 1);

		if (t != NULL) {
			start = t->start;
			len = t->len;
		}
	}
	else if (lua_type (L, 1) == LUA_TSTRING) {
		start = luaL_checklstring (L, 1, &len);
	}

	if (start != NULL) {
		pool = rspamd_mempool_new (rspamd_mempool_suggest_size (), NULL);
		hc = rspamd_mempool_alloc0 (pool, sizeof (*hc));
		in = g_byte_array_sized_new (len);
		g_byte_array_append (in, start, len);

		res = rspamd_html_process_part (pool, hc, in);

		t = lua_newuserdata (L, sizeof (*t));
		rspamd_lua_setclass (L, "rspamd{text}", -1);
		t->start = res->data;
		t->len = res->len;
		t->flags = RSPAMD_TEXT_FLAG_OWN;

		g_byte_array_free (res, FALSE);
		g_byte_array_free (in, TRUE);
		rspamd_mempool_delete (pool);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_util_levenshtein_distance (lua_State *L)
{
	LUA_TRACE_POINT;
	const gchar *s1, *s2;
	gsize s1len, s2len;
	gint dist = 0;
	guint replace_cost = 1;

	s1 = luaL_checklstring (L, 1, &s1len);
	s2 = luaL_checklstring (L, 2, &s2len);

	if (lua_isnumber (L, 3)) {
		replace_cost = lua_tonumber (L, 3);
	}

	if (s1 && s2) {
		dist = rspamd_strings_levenshtein_distance (s1, s1len, s2, s2len,
				replace_cost);
	}

	lua_pushinteger (L, dist);

	return 1;
}

static gint
lua_util_parse_addr (lua_State *L)
{
	LUA_TRACE_POINT;
	GPtrArray *addrs;
	gsize len;
	const gchar *str = luaL_checklstring (L, 1, &len);
	rspamd_mempool_t *pool;
	gboolean own_pool = FALSE;

	if (str) {

		if (lua_type (L, 2) == LUA_TUSERDATA) {
			pool = rspamd_lua_check_mempool (L, 2);

			if (pool == NULL) {
				return luaL_error (L, "invalid arguments");
			}
		}
		else {
			pool = rspamd_mempool_new (rspamd_mempool_suggest_size (), "lua util");
			own_pool = TRUE;
		}

		addrs = rspamd_email_address_from_mime (pool, str, len, NULL);

		if (addrs == NULL) {
			lua_pushnil (L);
		}
		else {
			lua_push_emails_address_list (L, addrs);
		}

		if (own_pool) {
			rspamd_mempool_delete (pool);
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_util_fold_header (lua_State *L)
{
	LUA_TRACE_POINT;
	const gchar *name, *value, *how, *stop_chars = NULL;
	GString *folded;

	name = luaL_checkstring (L, 1);
	value = luaL_checkstring (L, 2);

	if (name && value) {

		if (lua_isstring (L, 3)) {

			how = lua_tostring (L, 3);

			if (lua_isstring (L, 4)) {
				stop_chars = lua_tostring (L, 4);
			}

			if (strcmp (how, "cr") == 0) {
				folded = rspamd_header_value_fold (name, value, 0,
						RSPAMD_TASK_NEWLINES_CR, stop_chars);
			}
			else if (strcmp (how, "lf") == 0) {
				folded = rspamd_header_value_fold (name, value, 0,
						RSPAMD_TASK_NEWLINES_LF, stop_chars);
			}
			else {
				folded = rspamd_header_value_fold (name, value, 0,
						RSPAMD_TASK_NEWLINES_CRLF, stop_chars);
			}
		}
		else {
			folded = rspamd_header_value_fold (name, value, 0,
					RSPAMD_TASK_NEWLINES_CRLF, stop_chars);
		}

		if (folded) {
			lua_pushlstring (L, folded->str, folded->len);
			g_string_free (folded, TRUE);

			return 1;
		}
	}

	lua_pushnil (L);
	return 1;
}

static gint
lua_util_is_uppercase (lua_State *L)
{
	LUA_TRACE_POINT;
	const gchar *str;
	gsize sz;
	gint32 i = 0;
	UChar32 uc;
	guint nlc = 0, nuc = 0;

	str = luaL_checklstring (L, 1, &sz);

	if (str && sz > 0) {
		while (i >= 0 && i < sz) {
			U8_NEXT (str, i, sz, uc);

			if (uc < 0) {
				break;
			}

			if (u_isupper (uc)) {
				nuc++;
			}
			else if (u_islower (uc)) {
				nlc++;
			}
		}
	}

	if (nuc > 0 && nlc == 0) {
		lua_pushboolean (L, TRUE);
	}
	else {
		lua_pushboolean (L, FALSE);
	}

	return 1;
}

static gint
lua_util_humanize_number (lua_State *L)
{
	LUA_TRACE_POINT;
	gdouble number = luaL_checknumber (L, 1);
	gchar numbuf[32];


	rspamd_snprintf (numbuf, sizeof (numbuf), "%hL", (gint64)number);
	lua_pushstring (L, numbuf);

	return 1;
}

static gint
lua_util_get_tld (lua_State *L)
{
	LUA_TRACE_POINT;
	const gchar *host;
	gsize hostlen;
	rspamd_ftok_t tld;

	host = luaL_checklstring (L, 1, &hostlen);

	if (host) {
		if (!rspamd_url_find_tld (host, hostlen, &tld)) {
			lua_pushlstring (L, host, hostlen);
		}
		else {
			lua_pushlstring (L, tld.begin, tld.len);
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}


static gint
lua_util_glob (lua_State *L)
{
	LUA_TRACE_POINT;
	const gchar *pattern;
	glob_t gl;
	gint top, i, flags;

	top = lua_gettop (L);
	memset (&gl, 0, sizeof (gl));
	flags = GLOB_NOSORT;

	for (i = 1; i <= top; i ++, flags |= GLOB_APPEND) {
		pattern = luaL_checkstring (L, i);

		if (pattern) {
			glob (pattern, flags, NULL, &gl);
		}
	}

	lua_createtable (L, gl.gl_pathc, 0);
	/* Push results */
	for (i = 0; i < (gint)gl.gl_pathc; i ++) {
		lua_pushstring (L, gl.gl_pathv[i]);
		lua_rawseti (L, -2, i + 1);
	}

	globfree (&gl);

	return 1;
}

static gint
lua_util_parse_mail_address (lua_State *L)
{
	LUA_TRACE_POINT;
	GPtrArray *addrs;
	gsize len;
	const gchar *str = luaL_checklstring (L, 1, &len);
	rspamd_mempool_t *pool;
	gboolean own_pool = FALSE;

	if (str) {

		if (lua_type (L, 2) == LUA_TUSERDATA) {
			pool = rspamd_lua_check_mempool (L, 2);

			if (pool == NULL) {
				return luaL_error (L, "invalid arguments");
			}
		}
		else {
			pool = rspamd_mempool_new (rspamd_mempool_suggest_size (), "lua util");
			own_pool = TRUE;
		}

		addrs = rspamd_email_address_from_mime (pool, str, len, NULL);

		if (addrs == NULL) {
			lua_pushnil (L);
		}
		else {
			lua_push_emails_address_list (L, addrs);
		}

		if (own_pool) {
			rspamd_mempool_delete (pool);
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_util_strlen_utf8 (lua_State *L)
{
	LUA_TRACE_POINT;
	const gchar *str, *end;
	gsize len;

	str = lua_tolstring (L, 1, &len);

	if (str) {
		if (g_utf8_validate (str, len, &end)) {
			len = g_utf8_strlen (str, len);
		}
		else if (end != NULL && end > str) {
			len = (g_utf8_strlen (str, end - str)) /* UTF part */
					+ (len - (end - str)) /* raw part */;
		}

		lua_pushinteger (L, len);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_util_strcasecmp_utf8 (lua_State *L)
{
	LUA_TRACE_POINT;
	const gchar *str1, *str2;
	gsize len1, len2;
	gint ret = -1;

	str1 = lua_tolstring (L, 1, &len1);
	str2 = lua_tolstring (L, 2, &len2);

	if (str1 && str2) {

		if (len1 == len2) {
			ret = rspamd_lc_cmp (str1, str2, len1);
		}
		else {
			ret = len1 - len2;
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	lua_pushinteger (L, ret);
	return 1;
}

static gint
lua_util_strcasecmp_ascii (lua_State *L)
{
	LUA_TRACE_POINT;
	const gchar *str1, *str2;
	gsize len1, len2;
	gint ret = -1;

	str1 = lua_tolstring (L, 1, &len1);
	str2 = lua_tolstring (L, 2, &len2);

	if (str1 && str2) {

		if (len1 == len2) {
			ret = g_ascii_strncasecmp (str1, str2, len1);
		}
		else {
			ret = len1 - len2;
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	lua_pushinteger (L, ret);
	return 1;
}

static gint
lua_util_strequal_caseless (lua_State *L)
{
	LUA_TRACE_POINT;
	const gchar *str1, *str2;
	gsize len1, len2;
	gint ret = -1;

	str1 = lua_tolstring (L, 1, &len1);
	str2 = lua_tolstring (L, 2, &len2);

	if (str1 && str2) {

		if (len1 == len2) {
			ret = rspamd_lc_cmp (str1, str2, len1);
		}
		else {
			ret = len1 - len2;
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	lua_pushboolean (L, (ret == 0) ? true : false);
	return 1;
}

static gint
lua_util_get_ticks (lua_State *L)
{
	LUA_TRACE_POINT;
	gdouble ticks;
	gboolean rdtsc = FALSE;

	if (lua_isboolean (L, 1)) {
		rdtsc = lua_toboolean (L, 1);
	}

	ticks = rspamd_get_ticks (rdtsc);
	lua_pushnumber (L, ticks);

	return 1;
}

static gint
lua_util_get_time (lua_State *L)
{
	LUA_TRACE_POINT;
	gdouble seconds;
	struct timeval tv;

	if (gettimeofday (&tv, NULL) == 0) {
		seconds = tv_to_double (&tv);
	}
	else {
		seconds = time (NULL);
	}

	lua_pushnumber (L, seconds);

	return 1;
}

static gint
lua_util_time_to_string (lua_State *L)
{
	LUA_TRACE_POINT;
	gdouble seconds;
	struct timeval tv;
	char timebuf[128];

	if (lua_isnumber (L, 1)) {
		seconds = lua_tonumber (L, 1);
	}
	else {
		if (gettimeofday (&tv, NULL) == 0) {
			seconds = tv_to_double (&tv);
		}
		else {
			seconds = time (NULL);
		}
	}

	rspamd_http_date_format (timebuf, sizeof (timebuf), seconds);
	lua_pushstring (L, timebuf);

	return 1;
}

static gint
lua_util_stat (lua_State *L)
{
	LUA_TRACE_POINT;
	const gchar *fpath;
	struct stat st;

	fpath = luaL_checkstring (L, 1);

	if (fpath) {
		if (stat (fpath, &st) == -1) {
			lua_pushstring (L, strerror (errno));
			lua_pushnil (L);
		}
		else {
			lua_pushnil (L);
			lua_createtable (L, 0, 3);

			lua_pushstring (L, "size");
			lua_pushinteger (L, st.st_size);
			lua_settable (L, -3);

			lua_pushstring (L, "mtime");
			lua_pushinteger (L, st.st_mtime);
			lua_settable (L, -3);

			lua_pushstring (L, "type");
			if (S_ISREG (st.st_mode)) {
				lua_pushstring (L, "regular");
			}
			else if (S_ISDIR (st.st_mode)) {
				lua_pushstring (L, "directory");
			}
			else {
				lua_pushstring (L, "special");
			}
			lua_settable (L, -3);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 2;
}

static gint
lua_util_unlink (lua_State *L)
{
	LUA_TRACE_POINT;
	const gchar *fpath;
	gint ret;

	fpath = luaL_checkstring (L, 1);

	if (fpath) {
		ret = unlink (fpath);

		if (ret == -1) {
			lua_pushboolean (L, false);
			lua_pushstring (L, strerror (errno));

			return 2;
		}

		lua_pushboolean (L, true);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_util_lock_file (lua_State *L)
{
	LUA_TRACE_POINT;
	const gchar *fpath;
	gint fd = -1;
	gboolean own = FALSE;

#if !HAVE_FLOCK
	struct flock fl = {
		.l_type = F_WRLCK,
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = 0
	};
#endif

	fpath = luaL_checkstring (L, 1);

	if (fpath) {
		if (lua_isnumber (L, 2)) {
			fd = lua_tonumber (L, 2);
		}
		else {
			fd = open (fpath, O_RDONLY);
			own = TRUE;
		}

		if (fd == -1) {
			lua_pushnil (L);
			lua_pushstring (L, strerror (errno));

			return 2;
		}

#if HAVE_FLOCK
		if (flock (fd, LOCK_EX) == -1) {
#else
		if (fcntl (fd, F_SETLKW, &fl) == -1) {
#endif
			lua_pushnil (L);
			lua_pushstring (L, strerror (errno));

			if (own) {
				close (fd);
			}

			return 2;
		}

		lua_pushinteger (L, fd);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_util_unlock_file (lua_State *L)
{
	LUA_TRACE_POINT;
	gint fd = -1, ret, serrno;
	gboolean do_close = TRUE;

#if !HAVE_FLOCK
	struct flock fl = {
		.l_type = F_UNLCK,
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = 0
	};
#endif

	if (lua_isnumber (L, 1)) {
		fd = lua_tointeger (L, 1);

		if (lua_isboolean (L, 2)) {
			do_close = lua_toboolean (L, 2);
		}

#if HAVE_FLOCK
		ret = flock (fd, LOCK_UN);
#else
		ret = fcntl (fd, F_SETLKW, &fl);
#endif

		if (do_close) {
			serrno = errno;
			close (fd);
			errno = serrno;
		}

		if (ret == -1) {
			lua_pushboolean (L, false);
			lua_pushstring (L, strerror (errno));

			return 2;
		}

		lua_pushboolean (L, true);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_util_create_file (lua_State *L)
{
	LUA_TRACE_POINT;
	gint fd, mode = 00644;
	const gchar *fpath;

	fpath = luaL_checkstring (L, 1);

	if (fpath) {
		if (lua_isnumber (L, 2)) {
			mode = lua_tointeger (L, 2);
		}

		fd = rspamd_file_xopen (fpath, O_RDWR | O_CREAT | O_TRUNC, mode, 0);

		if (fd == -1) {
			lua_pushnil (L);
			lua_pushstring (L, strerror (errno));

			return 2;
		}

		lua_pushinteger (L, fd);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_util_close_file (lua_State *L)
{
	LUA_TRACE_POINT;
	gint fd = -1;

	if (lua_isnumber (L, 1)) {
		fd = lua_tointeger (L, 1);

		if (close (fd) == -1) {
			lua_pushboolean (L, false);
			lua_pushstring (L, strerror (errno));

			return 2;
		}

		lua_pushboolean (L, true);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_util_random_hex (lua_State *L)
{
	LUA_TRACE_POINT;
	gchar *buf;
	gint buflen;

	buflen = lua_tointeger (L, 1);

	if (buflen <= 0) {
		return luaL_error (L, "invalid arguments");
	}

	buf = g_malloc (buflen);
	rspamd_random_hex (buf, buflen);
	lua_pushlstring (L, buf, buflen);
	g_free (buf);

	return 1;
}

static gint
lua_util_zstd_compress (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_text *t = NULL, *res, tmp;
	gsize sz, r;

	if (lua_type (L, 1) == LUA_TSTRING) {
		t = &tmp;
		t->start = lua_tolstring (L, 1, &sz);
		t->len = sz;
	}
	else {
		t = lua_check_text (L, 1);
	}

	if (t == NULL || t->start == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	sz = ZSTD_compressBound (t->len);

	if (ZSTD_isError (sz)) {
		msg_err ("cannot compress data: %s", ZSTD_getErrorName (sz));
		lua_pushnil (L);

		return 1;
	}

	res = lua_newuserdata (L, sizeof (*res));
	res->start = g_malloc (sz);
	res->flags = RSPAMD_TEXT_FLAG_OWN;
	rspamd_lua_setclass (L, "rspamd{text}", -1);
	r = ZSTD_compress ((void *)res->start, sz, t->start, t->len, 1);

	if (ZSTD_isError (r)) {
		msg_err ("cannot compress data: %s", ZSTD_getErrorName (r));
		lua_pop (L, 1); /* Text will be freed here */
		lua_pushnil (L);

		return 1;
	}

	res->len = r;

	return 1;
}

static gint
lua_util_zstd_decompress (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_text *t = NULL, *res;
	gsize outlen, sz, r;
	ZSTD_DStream *zstream;
	ZSTD_inBuffer zin;
	ZSTD_outBuffer zout;
	gchar *out;

	if (lua_type (L, 1) == LUA_TSTRING) {
		t = g_alloca (sizeof (*t));
		t->start = lua_tolstring (L, 1, &sz);
		t->len = sz;
	}
	else {
		t = lua_check_text (L, 1);
	}

	if (t == NULL || t->start == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	zstream = ZSTD_createDStream ();
	ZSTD_initDStream (zstream);

	zin.pos = 0;
	zin.src = t->start;
	zin.size = t->len;

	if ((outlen = ZSTD_getDecompressedSize (zin.src, zin.size)) == 0) {
		outlen = ZSTD_DStreamOutSize ();
	}

	out = g_malloc (outlen);

	zout.dst = out;
	zout.pos = 0;
	zout.size = outlen;

	while (zin.pos < zin.size) {
		r = ZSTD_decompressStream (zstream, &zout, &zin);

		if (ZSTD_isError (r)) {
			msg_err ("cannot decompress data: %s", ZSTD_getErrorName (r));
			ZSTD_freeDStream (zstream);
			g_free (out);
			lua_pushstring (L, ZSTD_getErrorName (r));
			lua_pushnil (L);

			return 2;
		}

		if (zin.pos < zin.size && zout.pos == zout.size) {
			/* We need to extend output buffer */
			zout.size = zout.size * 1.5 + 1.0;
			out = g_realloc (zout.dst, zout.size);
			zout.dst = out;
		}
	}

	ZSTD_freeDStream (zstream);
	lua_pushnil (L); /* Error */
	res = lua_newuserdata (L, sizeof (*res));
	res->start = out;
	res->flags = RSPAMD_TEXT_FLAG_OWN;
	rspamd_lua_setclass (L, "rspamd{text}", -1);
	res->len = zout.pos;

	return 2;
}

static gint
lua_util_gzip_compress (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_text *t = NULL, *res, tmp;
	gsize sz;
	z_stream strm;
	gint rc;
	guchar *p;
	gsize remain;

	if (lua_type (L, 1) == LUA_TSTRING) {
		t = &tmp;
		t->start = lua_tolstring (L, 1, &sz);
		t->len = sz;
	}
	else {
		t = lua_check_text (L, 1);
	}

	if (t == NULL || t->start == NULL) {
		return luaL_error (L, "invalid arguments");
	}



	memset (&strm, 0, sizeof (strm));
	rc = deflateInit2 (&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
			MAX_WBITS + 16, MAX_MEM_LEVEL - 1, Z_DEFAULT_STRATEGY);

	if (rc != Z_OK) {
		return luaL_error (L, "cannot init zlib: %s", zError (rc));
	}

	sz = deflateBound (&strm, t->len);

	strm.avail_in = t->len;
	strm.next_in = (guchar *)t->start;

	res = lua_newuserdata (L, sizeof (*res));
	res->start = g_malloc (sz);
	res->flags = RSPAMD_TEXT_FLAG_OWN;
	rspamd_lua_setclass (L, "rspamd{text}", -1);

	p = (guchar *)res->start;
	remain = sz;

	while (strm.avail_in != 0) {
		strm.avail_out = remain;
		strm.next_out = p;

		rc = deflate (&strm, Z_FINISH);

		if (rc != Z_OK && rc != Z_BUF_ERROR) {
			if (rc == Z_STREAM_END) {
				break;
			}
			else {
				msg_err ("cannot compress data: %s", zError (rc));
				lua_pop (L, 1); /* Text will be freed here */
				lua_pushnil (L);
				deflateEnd (&strm);

				return 1;
			}
		}

		res->len = strm.total_out;

		if (strm.avail_out == 0 && strm.avail_in != 0) {
			/* Need to allocate more */
			remain = res->len;
			res->start = g_realloc ((gpointer)res->start, strm.avail_in + sz);
			sz = strm.avail_in + sz;
			p = (guchar *)res->start + remain;
			remain = sz - remain;
		}
	}

	deflateEnd (&strm);
	res->len = strm.total_out;

	return 1;
}


static gint
lua_util_gzip_decompress (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_text *t = NULL, *res, tmp;
	gsize sz;
	z_stream strm;
	gint rc;
	guchar *p;
	gsize remain;

	if (lua_type (L, 1) == LUA_TSTRING) {
		t = &tmp;
		t->start = lua_tolstring (L, 1, &sz);
		t->len = sz;
	}
	else {
		t = lua_check_text (L, 1);
	}

	if (t == NULL || t->start == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	memset (&strm, 0, sizeof (strm));
	/* windowBits +16 to decode gzip, zlib 1.2.0.4+ */
	rc = inflateInit2 (&strm, MAX_WBITS + 16);

	if (rc != Z_OK) {
		return luaL_error (L, "cannot init zlib");
	}

	strm.avail_in = t->len;
	strm.next_in = (guchar *)t->start;

	res = lua_newuserdata (L, sizeof (*res));
	res->start = g_malloc (sz);
	res->flags = RSPAMD_TEXT_FLAG_OWN;
	rspamd_lua_setclass (L, "rspamd{text}", -1);

	p = (guchar *)res->start;
	remain = sz;

	while (strm.avail_in != 0) {
		strm.avail_out = remain;
		strm.next_out = p;

		rc = inflate (&strm, Z_FINISH);

		if (rc != Z_OK && rc != Z_BUF_ERROR) {
			if (rc == Z_STREAM_END) {
				break;
			}
			else {
				msg_err ("cannot decompress data: %s", zError (rc));
				lua_pop (L, 1); /* Text will be freed here */
				lua_pushnil (L);
				inflateEnd (&strm);

				return 1;
			}
		}

		res->len = strm.total_out;

		if (strm.avail_out == 0 && strm.avail_in != 0) {
			/* Need to allocate more */
			remain = res->len;
			res->start = g_realloc ((gpointer)res->start, strm.avail_in + sz);
			sz = strm.avail_in + sz;
			p = (guchar *)res->start + remain;
			remain = sz - remain;
		}
	}

	inflateEnd (&strm);
	res->len = strm.total_out;

	return 2;
}


static gint
lua_util_normalize_prob (lua_State *L)
{
	LUA_TRACE_POINT;
	gdouble x, bias = 0.5;

	x = lua_tonumber (L, 1);

	if (lua_type (L, 2) == LUA_TNUMBER) {
		bias = lua_tonumber (L, 2);
	}

	lua_pushnumber (L, rspamd_normalize_probability (x, bias));

	return 1;
}

static gint
lua_util_caseless_hash (lua_State *L)
{
	LUA_TRACE_POINT;
	guint64 seed = 0xdeadbabe, h;
	struct rspamd_lua_text *t = NULL;
	gint64 *r;
	gsize sz;

	if (lua_type (L, 1) == LUA_TSTRING) {
		t = g_alloca (sizeof (*t));
		t->start = lua_tolstring (L, 1, &sz);
		t->len = sz;
	}
	else {
		t = lua_check_text (L, 1);
	}

	if (t == NULL || t->start == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	if (lua_type (L, 2) == LUA_TNUMBER) {
		seed = lua_tonumber (L, 2);
	}
	else if (lua_type (L, 2) == LUA_TUSERDATA) {
		seed = lua_check_int64 (L, 2);
	}

	h = rspamd_icase_hash (t->start, t->len, seed);
	r = lua_newuserdata (L, sizeof (*r));
	*r = h;
	rspamd_lua_setclass (L, "rspamd{int64}", -1);

	return 1;
}

static gint
lua_util_caseless_hash_fast (lua_State *L)
{
	LUA_TRACE_POINT;
	guint64 seed = 0xdeadbabe, h;
	struct rspamd_lua_text *t = NULL;
	gsize sz;
	union {
		guint64 i;
		double d;
	} u;

	if (lua_type (L, 1) == LUA_TSTRING) {
		t = g_alloca (sizeof (*t));
		t->start = lua_tolstring (L, 1, &sz);
		t->len = sz;
	}
	else {
		t = lua_check_text (L, 1);
	}

	if (t == NULL || t->start == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	if (lua_type (L, 2) == LUA_TNUMBER) {
		seed = lua_tonumber (L, 2);
	}
	else if (lua_type (L, 2) == LUA_TUSERDATA) {
		seed = lua_check_int64 (L, 2);
	}

	/*
	 * Here, we loose entropy from 64 bits to 52 bits roughly, however,
	 * it is still fine for practical applications
	 */

	h = rspamd_icase_hash (t->start, t->len, seed);
	u.i = G_GUINT64_CONSTANT(0x3FF) << 52 | h >> 12;
	lua_pushnumber (L, u.d - 1.0);

	return 1;
}

static gint
lua_util_is_utf_spoofed (lua_State *L)
{
	LUA_TRACE_POINT;
	gsize l1, l2;
	gint ret, nres = 2;
	const gchar *s1 = lua_tolstring (L, 1, &l1),
			*s2 = lua_tolstring (L, 2, &l2);
	static USpoofChecker *spc, *spc_sgl;
	UErrorCode uc_err = U_ZERO_ERROR;

	if (s1 && s2) {
		if (spc == NULL) {
			spc = uspoof_open (&uc_err);

			if (uc_err != U_ZERO_ERROR) {
				msg_err ("cannot init spoof checker: %s", u_errorName (uc_err));
				lua_pushboolean (L, false);

				return 1;
			}
		}

		ret = uspoof_areConfusableUTF8 (spc, s1, l1, s2, l2, &uc_err);
	}
	else if (s1) {
		/* We have just s1, not s2 */
		if (spc_sgl == NULL) {
			USet *allowed = uset_openEmpty ();

#if U_ICU_VERSION_MAJOR_NUM >= 51
			uset_addAll (allowed, uspoof_getRecommendedSet (&uc_err));
			uset_addAll (allowed, uspoof_getInclusionSet (&uc_err));
#endif

			spc_sgl = uspoof_open (&uc_err);

			if (uc_err != U_ZERO_ERROR) {
				msg_err ("cannot init spoof checker: %s", u_errorName (uc_err));
				lua_pushboolean (L, false);

				return 1;
			}

			uspoof_setChecks (spc_sgl,
					USPOOF_ALL_CHECKS & ~USPOOF_WHOLE_SCRIPT_CONFUSABLE,
					&uc_err);
#if U_ICU_VERSION_MAJOR_NUM >= 51
			uspoof_setAllowedChars (spc_sgl, allowed, &uc_err);
			uspoof_setRestrictionLevel (spc_sgl, USPOOF_MODERATELY_RESTRICTIVE);
#endif
		}

		ret = uspoof_checkUTF8 (spc_sgl, s1, l1, NULL, &uc_err);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	lua_pushboolean (L, !!(ret != 0));

	switch (ret) {
	case 0:
		nres = 1;
		break;
	case USPOOF_SINGLE_SCRIPT_CONFUSABLE:
		lua_pushstring (L, "single");
		break;
	case USPOOF_MIXED_SCRIPT_CONFUSABLE:
		lua_pushstring (L, "multiple");
		break;
	case USPOOF_WHOLE_SCRIPT_CONFUSABLE:
		lua_pushstring (L, "whole");
		break;
	default:
		lua_pushstring (L, "unknown");
		break;
	}

	return nres;
}

static gint
lua_util_get_hostname (lua_State *L)
{
	LUA_TRACE_POINT;
	gchar *hostbuf;
	gsize hostlen;

	hostlen = sysconf (_SC_HOST_NAME_MAX);

	if (hostlen <= 0) {
		hostlen = 256;
	}
	else {
		hostlen ++;
	}

	hostbuf = g_alloca (hostlen);
	memset (hostbuf, 0, hostlen);
	gethostname (hostbuf, hostlen - 1);

	lua_pushstring (L, hostbuf);

	return 1;
}

static gint
lua_util_is_valid_utf8 (lua_State *L)
{
	LUA_TRACE_POINT;
	const gchar *str;
	gsize len;

	str = lua_tolstring (L, 1, &len);

	if (str) {
		lua_pushboolean (L, g_utf8_validate (str, len, NULL));
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_util_readline (lua_State *L)
{
	LUA_TRACE_POINT;
	const gchar *prompt = "";
	gchar *input;

	if (lua_type (L, 1) == LUA_TSTRING) {
		prompt = lua_tostring (L, 1);
	}

	input = linenoise (prompt);

	if (input) {
		lua_pushstring (L, input);
		linenoiseHistoryAdd (input);
		linenoiseFree (input);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_util_readpassphrase (lua_State *L)
{
	LUA_TRACE_POINT;
	gchar test_password[8192];
	gsize r;

	r = rspamd_read_passphrase (test_password, sizeof (test_password), 0, NULL);

	if (r > 0) {
		lua_pushlstring (L, test_password, r);
	}
	else {
		lua_pushnil (L);
	}

	/* In fact, we still pass it to Lua which is not very safe */
	rspamd_explicit_memzero (test_password, sizeof (test_password));

	return 1;
}

static gint
lua_util_file_exists (lua_State *L)
{
	LUA_TRACE_POINT;
	const gchar *fname = luaL_checkstring (L, 1);
	gint serrno;

	if (fname) {
		if (access (fname, R_OK) == -1) {
			serrno = errno;
			lua_pushboolean (L, false);
			lua_pushstring (L, strerror (serrno));
		}
		else {
			lua_pushboolean (L, true);
			lua_pushnil (L);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 2;
}

static gint
lua_util_mkdir (lua_State *L)
{
	LUA_TRACE_POINT;
	const gchar *dname = luaL_checkstring (L, 1);
	gboolean recursive = FALSE;
	gint r = -1;

	if (dname) {
		if (lua_isboolean (L, 2)) {
			recursive = lua_toboolean (L, 2);
		}

		if (recursive) {
			char path[PATH_MAX];
			gsize len, i;

			len = rspamd_strlcpy (path, dname, sizeof (path));

			/* Strip last / */
			if (path[len - 1] == '/') {
				path[len - 1] = '\0';
				len --;
			}

			for (i = 1; i < len; i ++) {
				if (path[i] == '/') {
					path[i] = '\0';

					errno = 0;
					r = mkdir (path, S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH);

					if (r == -1 && errno != EEXIST) {
						break;
					}

					path[i] = '/';
				}
			}

			/* Final path component */
			r = mkdir (path, S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH);
		}
		else {
			r = mkdir (dname, S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH);
		}

		if (r == -1 && errno != EEXIST) {
			lua_pushboolean (L, false);
			lua_pushstring (L, strerror (errno));

			return 2;
		}

		lua_pushboolean (L, true);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}


static gint
lua_util_umask (lua_State *L)
{
	LUA_TRACE_POINT;
	mode_t mask = 0, old;

	if (lua_type (L, 1) == LUA_TSTRING) {
		const gchar *str = lua_tostring (L, 1);

		if (str[0] == '0') {
			/* e.g. '022' */
			mask = strtol (str, NULL, 8);
		}
		else {
			/* XXX: implement modestring parsing at some point */
			return luaL_error (L, "invalid arguments");
		}
	}
	else if (lua_type (L, 1) == LUA_TNUMBER) {
		mask = lua_tonumber (L, 1);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	old = umask (mask);

	lua_pushinteger (L, old);

	return 1;
}

static gint
lua_util_isatty (lua_State *L)
{
	LUA_TRACE_POINT;
	if (isatty (STDOUT_FILENO)) {
		lua_pushboolean (L, true);
	}
	else {
		lua_pushboolean (L, false);
	}

	return 1;
}

/* Backport from Lua 5.3 */

/******************************************************************************
* Copyright (C) 1994-2016 Lua.org, PUC-Rio.
*
* Permission is hereby granted, free of charge, to any person obtaining
* a copy of this software and associated documentation files (the
* "Software"), to deal in the Software without restriction, including
* without limitation the rights to use, copy, modify, merge, publish,
* distribute, sublicense, and/or sell copies of the Software, and to
* permit persons to whom the Software is furnished to do so, subject to
* the following conditions:
*
* The above copyright notice and this permission notice shall be
* included in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
* IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
* CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
* TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
* SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
******************************************************************************/

/*
** {======================================================
** PACK/UNPACK
** =======================================================
*/


/* value used for padding */
#if !defined(LUA_PACKPADBYTE)
#define LUA_PACKPADBYTE        0x00
#endif

/* maximum size for the binary representation of an integer */
#define MAXINTSIZE    16

/* number of bits in a character */
#define NB    CHAR_BIT

/* mask for one character (NB 1's) */
#define MC    ((1 << NB) - 1)

/* size of a lua_Integer */
#define SZINT    ((int)sizeof(lua_Integer))

#define MAX_SIZET    ((size_t)(~(size_t)0))

#define MAXSIZE  \
	(sizeof(size_t) < sizeof(int) ? MAX_SIZET : (size_t)(INT_MAX))


/* dummy union to get native endianness */
static const union {
	int dummy;
	char little;  /* true if machine is little endian */
} nativeendian = {1};


/* dummy structure to get native alignment requirements */
struct cD {
	char c;
	union {
		double d;
		void *p;
		lua_Integer i;
		lua_Number n;
	} u;
};

#define MAXALIGN    (offsetof(struct cD, u))

/*
** Union for serializing floats
*/
typedef union Ftypes {
	float f;
	double d;
	lua_Number n;
	char buff[5 * sizeof (lua_Number)];  /* enough for any float type */
} Ftypes;


/*
** information to pack/unpack stuff
*/
typedef struct Header {
	lua_State *L;
	int islittle;
	int maxalign;
} Header;

/*
** options for pack/unpack
*/
typedef enum KOption {
	Kint,        /* signed integers */
	Kuint,    /* unsigned integers */
	Kfloat,    /* floating-point numbers */
	Kchar,    /* fixed-length strings */
	Kstring,    /* strings with prefixed length */
	Kzstr,    /* zero-terminated strings */
	Kpadding,    /* padding */
	Kpaddalign,    /* padding for alignment */
	Knop        /* no-op (configuration or spaces) */
} KOption;

#if LUA_VERSION_NUM < 503
#define lua_Unsigned size_t

typedef struct luaL_Buffer_53 {
	luaL_Buffer b; /* make incorrect code crash! */
	char *ptr;
	size_t nelems;
	size_t capacity;
	lua_State *L2;
} luaL_Buffer_53;

#define luaL_Buffer luaL_Buffer_53
#define COMPAT53_PREFIX lua
#undef COMPAT53_API
#if defined(__GNUC__) || defined(__clang__)
# define COMPAT53_API __attribute__((__unused__)) static
#else
# define COMPAT53_API static
#endif

#define COMPAT53_CONCAT_HELPER(a, b) a##b
#define COMPAT53_CONCAT(a, b) COMPAT53_CONCAT_HELPER(a, b)

#define luaL_buffinit COMPAT53_CONCAT(COMPAT53_PREFIX, _buffinit_53)
COMPAT53_API void luaL_buffinit (lua_State *L, luaL_Buffer_53 *B);
#define luaL_prepbuffsize COMPAT53_CONCAT(COMPAT53_PREFIX, _prepbufsize_53)
COMPAT53_API char *luaL_prepbuffsize (luaL_Buffer_53 *B, size_t s);
#define luaL_addlstring COMPAT53_CONCAT(COMPAT53_PREFIX, _addlstring_53)
COMPAT53_API void luaL_addlstring (luaL_Buffer_53 *B, const char *s, size_t l);
#define luaL_addvalue COMPAT53_CONCAT(COMPAT53_PREFIX, _addvalue_53)
COMPAT53_API void luaL_addvalue (luaL_Buffer_53 *B);
#define luaL_pushresult COMPAT53_CONCAT(COMPAT53_PREFIX, _pushresult_53)
COMPAT53_API void luaL_pushresult (luaL_Buffer_53 *B);
#undef luaL_buffinitsize
#define luaL_buffinitsize(L, B, s) \
  (luaL_buffinit(L, B), luaL_prepbuffsize(B, s))

#undef luaL_prepbuffer
#define luaL_prepbuffer(B) \
  luaL_prepbuffsize(B, LUAL_BUFFERSIZE)

#undef luaL_addchar
#define luaL_addchar(B, c) \
  ((void)((B)->nelems < (B)->capacity || luaL_prepbuffsize(B, 1)), \
   ((B)->ptr[(B)->nelems++] = (c)))

#undef luaL_addsize
#define luaL_addsize(B, s) \
  ((B)->nelems += (s))

#undef luaL_addstring
#define luaL_addstring(B, s) \
  luaL_addlstring(B, s, strlen(s))

#undef luaL_pushresultsize
#define luaL_pushresultsize(B, s) \
  (luaL_addsize(B, s), luaL_pushresult(B))

COMPAT53_API void
luaL_buffinit (lua_State *L, luaL_Buffer_53 *B)
{
	/* make it crash if used via pointer to a 5.1-style luaL_Buffer */
#if LUA_VERSION_NUM < 502
	B->b.p = NULL;
	B->b.L = NULL;
	B->b.lvl = 0;
	/* reuse the buffer from the 5.1-style luaL_Buffer though! */
	B->ptr = B->b.buffer;
	B->nelems = 0;
#elif LUA_VERSION_NUM == 502
        B->ptr = B->b.b;
	B->nelems = B->b.n;
#endif
	B->capacity = LUAL_BUFFERSIZE;
        B->L2 = L;
}


COMPAT53_API char *
luaL_prepbuffsize (luaL_Buffer_53 *B, size_t s)
{
	if (B->capacity - B->nelems < s) { /* needs to grow */
		char *newptr = NULL;
		size_t newcap = B->capacity * 2;
		if (newcap - B->nelems < s)
			newcap = B->nelems + s;
		if (newcap < B->capacity) /* overflow */
			luaL_error (B->L2, "buffer too large");
		newptr = (char *) lua_newuserdata (B->L2, newcap);
		memcpy(newptr, B->ptr, B->nelems);
#if LUA_VERSION_NUM < 502
		if (B->ptr != B->b.buffer)
#elif LUA_VERSION_NUM == 502
		if (B->ptr != B->b.b)
#endif
			lua_replace (B->L2, -2); /* remove old buffer */
		B->ptr = newptr;
		B->capacity = newcap;
	}
	return B->ptr + B->nelems;
}


COMPAT53_API void
luaL_addlstring (luaL_Buffer_53 *B, const char *s, size_t l)
{
	memcpy(luaL_prepbuffsize (B, l), s, l);
	luaL_addsize(B, l);
}


COMPAT53_API void
luaL_addvalue (luaL_Buffer_53 *B)
{
	size_t len = 0;
	const char *s = lua_tolstring (B->L2, -1, &len);
	if (!s)
		luaL_error (B->L2, "cannot convert value to string");
#if LUA_VERSION_NUM < 502
	if (B->ptr != B->b.buffer)
#elif LUA_VERSION_NUM == 502
	if (B->ptr != B->b.b)
#endif
		lua_insert (B->L2, -2); /* userdata buffer must be at stack top */
	luaL_addlstring (B, s, len);
#if LUA_VERSION_NUM < 502
	lua_remove (B->L2, B->ptr != B->b.buffer ? -2 : -1);
#elif LUA_VERSION_NUM == 502
	lua_remove (B->L2, B->ptr != B->b.b ? -2 : -1);
#endif
}


COMPAT53_API void
luaL_pushresult (luaL_Buffer_53 *B)
{
	lua_pushlstring (B->L2, B->ptr, B->nelems);
#if LUA_VERSION_NUM < 502
	if (B->ptr != B->b.buffer)
#elif LUA_VERSION_NUM == 502
	if (B->ptr != B->b.b)
#endif
		lua_replace (B->L2, -2); /* remove userdata buffer */
}

#endif

/*
** Read an integer numeral from string 'fmt' or return 'df' if
** there is no numeral
*/
static int
digit (int c)
{
	return '0' <= c && c <= '9';
}

static int
getnum (const char **fmt, int df)
{
	if (!digit (**fmt))  /* no number? */
		return df;  /* return default value */
	else {
		int a = 0;
		do {
			a = a * 10 + (*((*fmt)++) - '0');
		} while (digit (**fmt) && a <= ((int) MAXSIZE - 9) / 10);
		return a;
	}
}


/*
** Read an integer numeral and raises an error if it is larger
** than the maximum size for integers.
*/
static int
getnumlimit (Header *h, const char **fmt, int df)
{
	int sz = getnum (fmt, df);
	if (sz > MAXINTSIZE || sz <= 0)
		luaL_error (h->L, "integral size (%d) out of limits [1,%d]",
				sz, MAXINTSIZE);
	return sz;
}


/*
** Initialize Header
*/
static void
initheader (lua_State *L, Header *h)
{
	h->L = L;
	h->islittle = nativeendian.little;
	h->maxalign = 1;
}


/*
** Read and classify next option. 'size' is filled with option's size.
*/
static KOption
getoption (Header *h, const char **fmt, int *size)
{
	int opt = *((*fmt)++);
	*size = 0;  /* default */
	switch (opt) {
	case 'b':
		*size = sizeof (char);
		return Kint;
	case 'B':
		*size = sizeof (char);
		return Kuint;
	case 'h':
		*size = sizeof (short);
		return Kint;
	case 'H':
		*size = sizeof (short);
		return Kuint;
	case 'l':
		*size = sizeof (long);
		return Kint;
	case 'L':
		*size = sizeof (long);
		return Kuint;
	case 'j':
		*size = sizeof (lua_Integer);
		return Kint;
	case 'J':
		*size = sizeof (lua_Integer);
		return Kuint;
	case 'T':
		*size = sizeof (size_t);
		return Kuint;
	case 'f':
		*size = sizeof (float);
		return Kfloat;
	case 'd':
		*size = sizeof (double);
		return Kfloat;
	case 'n':
		*size = sizeof (lua_Number);
		return Kfloat;
	case 'i':
		*size = getnumlimit (h, fmt, sizeof (int));
		return Kint;
	case 'I':
		*size = getnumlimit (h, fmt, sizeof (int));
		return Kuint;
	case 's':
		*size = getnumlimit (h, fmt, sizeof (size_t));
		return Kstring;
	case 'c':
		*size = getnum (fmt, -1);
		if (*size == -1)
			luaL_error (h->L, "missing size for format option 'c'");
		return Kchar;
	case 'z':
		return Kzstr;
	case 'x':
		*size = 1;
		return Kpadding;
	case 'X':
		return Kpaddalign;
	case ' ':
		break;
	case '<':
		h->islittle = 1;
		break;
	case '>':
		h->islittle = 0;
		break;
	case '=':
		h->islittle = nativeendian.little;
		break;
	case '!':
		h->maxalign = getnumlimit (h, fmt, MAXALIGN);
		break;
	default:
		luaL_error (h->L, "invalid format option '%c'", opt);
	}
	return Knop;
}


/*
** Read, classify, and fill other details about the next option.
** 'psize' is filled with option's size, 'notoalign' with its
** alignment requirements.
** Local variable 'size' gets the size to be aligned. (Kpadal option
** always gets its full alignment, other options are limited by
** the maximum alignment ('maxalign'). Kchar option needs no alignment
** despite its size.
*/
static KOption
getdetails (Header *h, size_t totalsize,
		const char **fmt, int *psize, int *ntoalign)
{
	KOption opt = getoption (h, fmt, psize);
	int align = *psize;  /* usually, alignment follows size */
	if (opt == Kpaddalign) {  /* 'X' gets alignment from following option */
		if (**fmt == '\0' || getoption (h, fmt, &align) == Kchar || align == 0)
			luaL_argerror (h->L, 1, "invalid next option for option 'X'");
	}
	if (align <= 1 || opt == Kchar)  /* need no alignment? */
		*ntoalign = 0;
	else {
		if (align > h->maxalign)  /* enforce maximum alignment */
			align = h->maxalign;
		if ((align & (align - 1)) != 0)  /* is 'align' not a power of 2? */
			luaL_argerror (h->L, 1, "format asks for alignment not power of 2");
		*ntoalign = (align - (int) (totalsize & (align - 1))) & (align - 1);
	}
	return opt;
}


/*
** Pack integer 'n' with 'size' bytes and 'islittle' endianness.
** The final 'if' handles the case when 'size' is larger than
** the size of a Lua integer, correcting the extra sign-extension
** bytes if necessary (by default they would be zeros).
*/
static void
packint (luaL_Buffer *b, lua_Unsigned n,
		int islittle, int size, int neg)
{
	char *buff = luaL_prepbuffsize (b, size);
	int i;
	buff[islittle ? 0 : size - 1] = (char) (n & MC);  /* first byte */
	for (i = 1; i < size; i++) {
		n >>= NB;
		buff[islittle ? i : size - 1 - i] = (char) (n & MC);
	}
	if (neg && size > SZINT) {  /* negative number need sign extension? */
		for (i = SZINT; i < size; i++)  /* correct extra bytes */
			buff[islittle ? i : size - 1 - i] = (char) MC;
	}
	luaL_addsize(b, size);  /* add result to buffer */
}


/*
** Copy 'size' bytes from 'src' to 'dest', correcting endianness if
** given 'islittle' is different from native endianness.
*/
static void
copywithendian (volatile char *dest, volatile const char *src,
		int size, int islittle)
{
	if (islittle == nativeendian.little) {
		while (size-- != 0)
			*(dest++) = *(src++);
	}
	else {
		dest += size - 1;
		while (size-- != 0)
			*(dest--) = *(src++);
	}
}


static int
lua_util_pack (lua_State *L)
{
	luaL_Buffer b;
	Header h;
	const char *fmt = luaL_checkstring(L, 1);  /* format string */
	int arg = 1;  /* current argument to pack */
	size_t totalsize = 0;  /* accumulate total size of result */
	initheader (L, &h);
	lua_pushnil (L);  /* mark to separate arguments from string buffer */
	luaL_buffinit (L, &b);

	while (*fmt != '\0') {
		int size, ntoalign;
		KOption opt = getdetails (&h, totalsize, &fmt, &size, &ntoalign);
		totalsize += ntoalign + size;
		while (ntoalign-- > 0)
			luaL_addchar(&b, LUA_PACKPADBYTE);  /* fill alignment */
		arg++;
		switch (opt) {
		case Kint: {  /* signed integers */
			lua_Integer n = luaL_checkinteger (L, arg);
			if (size < SZINT) {  /* need overflow check? */
				lua_Integer lim = (lua_Integer) 1 << ((size * NB) - 1);
				luaL_argcheck(L, -lim <= n && n < lim, arg, "integer overflow");
			}
			packint (&b, (lua_Unsigned) n, h.islittle, size, (n < 0));
			break;
		}
		case Kuint: {  /* unsigned integers */
			lua_Integer n = luaL_checkinteger (L, arg);
			if (size < SZINT)  /* need overflow check? */
				luaL_argcheck(L,
						(lua_Unsigned) n < ((lua_Unsigned) 1 << (size * NB)),
						arg,
						"unsigned overflow");
			packint (&b, (lua_Unsigned) n, h.islittle, size, 0);
			break;
		}
		case Kfloat: {  /* floating-point options */
			volatile Ftypes u;
			char *buff = luaL_prepbuffsize (&b, size);
			lua_Number n = luaL_checknumber (L, arg);  /* get argument */
			if (size == sizeof (u.f))
				u.f = (float) n;  /* copy it into 'u' */
			else if (size == sizeof (u.d))
				u.d = (double) n;
			else
				u.n = n;
			/* move 'u' to final result, correcting endianness if needed */
			copywithendian (buff, u.buff, size, h.islittle);
			luaL_addsize(&b, size);
			break;
		}
		case Kchar: {  /* fixed-size string */
			size_t len;
			const char *s = luaL_checklstring (L, arg, &len);
			if ((size_t) size <=
					len)  /* string larger than (or equal to) needed? */
				luaL_addlstring (&b,
						s,
						size);  /* truncate string to asked size */
			else {  /* string smaller than needed */
				luaL_addlstring (&b, s, len);  /* add it all */
				while (len++ < (size_t) size)  /* pad extra space */
					luaL_addchar(&b, LUA_PACKPADBYTE);
			}
			break;
		}
		case Kstring: {  /* strings with length count */
			size_t len;
			const char *s = luaL_checklstring (L, arg, &len);
			luaL_argcheck(L, size >= (int) sizeof (size_t) ||
					len < ((size_t) 1 << (size * NB)),
					arg, "string length does not fit in given size");
			packint (&b,
					(lua_Unsigned) len,
					h.islittle,
					size,
					0);  /* pack length */
			luaL_addlstring (&b, s, len);
			totalsize += len;
			break;
		}
		case Kzstr: {  /* zero-terminated string */
			size_t len;
			const char *s = luaL_checklstring (L, arg, &len);
			luaL_argcheck(L, strlen (s) == len, arg, "string contains zeros");
			luaL_addlstring (&b, s, len);
			luaL_addchar(&b, '\0');  /* add zero at the end */
			totalsize += len + 1;
			break;
		}
		case Kpadding:
			luaL_addchar(&b, LUA_PACKPADBYTE);  /* FALLTHROUGH */
		case Kpaddalign:
		case Knop:
			arg--;  /* undo increment */
			break;
		}
	}
	luaL_pushresult (&b);
	return 1;
}


static int
lua_util_packsize (lua_State *L)
{
	Header h;
	const char *fmt = luaL_checkstring(L, 1);  /* format string */
	size_t totalsize = 0;  /* accumulate total size of result */
	initheader (L, &h);
	while (*fmt != '\0') {
		int size, ntoalign;
		KOption opt = getdetails (&h, totalsize, &fmt, &size, &ntoalign);
		size += ntoalign;  /* total space used by option */
		luaL_argcheck(L, totalsize <= MAXSIZE - size, 1,
				"format result too large");
		totalsize += size;
		switch (opt) {
		case Kstring:  /* strings with length count */
		case Kzstr:    /* zero-terminated string */
			luaL_argerror (L, 1, "variable-length format");
			/* call never return, but to avoid warnings: *//* FALLTHROUGH */
		default:
			break;
		}
	}
	lua_pushinteger (L, (lua_Integer) totalsize);
	return 1;
}


/*
** Unpack an integer with 'size' bytes and 'islittle' endianness.
** If size is smaller than the size of a Lua integer and integer
** is signed, must do sign extension (propagating the sign to the
** higher bits); if size is larger than the size of a Lua integer,
** it must check the unread bytes to see whether they do not cause an
** overflow.
*/
static lua_Integer
unpackint (lua_State *L, const char *str,
		int islittle, int size, int issigned)
{
	lua_Unsigned res = 0;
	int i;
	int limit = (size <= SZINT) ? size : SZINT;
	for (i = limit - 1; i >= 0; i--) {
		res <<= NB;
		res |= (lua_Unsigned) (
		unsigned char)str[islittle ? i : size - 1 - i];
	}
	if (size < SZINT) {  /* real size smaller than lua_Integer? */
		if (issigned) {  /* needs sign extension? */
			lua_Unsigned mask = (lua_Unsigned) 1 << (size * NB - 1);
			res = ((res ^ mask) - mask);  /* do sign extension */
		}
	}
	else if (size > SZINT) {  /* must check unread bytes */
		int mask = (!issigned || (lua_Integer) res >= 0) ? 0 : MC;
		for (i = limit; i < size; i++) {
			if ((unsigned char) str[islittle ? i : size - 1 - i] != mask)
				luaL_error (L,
						"%d-byte integer does not fit into Lua Integer",
						size);
		}
	}
	return (lua_Integer) res;
}

static lua_Integer
posrelat (lua_Integer pos, size_t len)
{
	if (pos >= 0)
		return pos;
	else if (0u - (size_t) pos > len)
		return 0;
	else
		return (lua_Integer) len + pos + 1;
}

static int
lua_util_unpack (lua_State *L)
{
	Header h;
	const char *fmt = luaL_checkstring(L, 1);
	size_t ld;
	const char *data = luaL_checklstring (L, 2, &ld);
	size_t pos = (size_t) posrelat (luaL_optinteger (L, 3, 1), ld) - 1;
	int n = 0;  /* number of results */
	luaL_argcheck(L, pos <= ld, 3, "initial position out of string");
	initheader (L, &h);
	while (*fmt != '\0') {
		int size, ntoalign;
		KOption opt = getdetails (&h, pos, &fmt, &size, &ntoalign);
		if ((size_t) ntoalign + size > ~pos || pos + ntoalign + size > ld)
			luaL_argerror (L, 2, "data string too short");
		pos += ntoalign;  /* skip alignment */
		/* stack space for item + next position */
		luaL_checkstack (L, 2, "too many results");
		n++;
		switch (opt) {
		case Kint:
		case Kuint: {
			lua_Integer res = unpackint (L, data + pos, h.islittle, size,
					(opt == Kint));
			lua_pushinteger (L, res);
			break;
		}
		case Kfloat: {
			volatile Ftypes u;
			lua_Number num;
			copywithendian (u.buff, data + pos, size, h.islittle);
			if (size == sizeof (u.f))
				num = (lua_Number) u.f;
			else if (size == sizeof (u.d))
				num = (lua_Number) u.d;
			else
				num = u.n;
			lua_pushnumber (L, num);
			break;
		}
		case Kchar: {
			lua_pushlstring (L, data + pos, size);
			break;
		}
		case Kstring: {
			size_t len = (size_t) unpackint (L,
					data + pos,
					h.islittle,
					size,
					0);
			luaL_argcheck(L,
					pos + len + size <= ld,
					2,
					"data string too short");
			lua_pushlstring (L, data + pos + size, len);
			pos += len;  /* skip string */
			break;
		}
		case Kzstr: {
			size_t len = (int) strlen (data + pos);
			lua_pushlstring (L, data + pos, len);
			pos += len + 1;  /* skip string plus final '\0' */
			break;
		}
		case Kpaddalign:
		case Kpadding:
		case Knop:
			n--;  /* undo increment */
			break;
		}
		pos += size;
	}
	lua_pushinteger (L, pos + 1);  /* next position */
	return n + 1;
}

static gint
lua_load_util (lua_State * L)
{
	lua_newtable (L);
	luaL_register (L, NULL, utillib_f);

	return 1;
}

void
luaopen_util (lua_State * L)
{
	rspamd_lua_new_class (L, "rspamd{ev_base}", ev_baselib_m);
	lua_pop (L, 1);
	rspamd_lua_new_class (L, "rspamd{int64}", int64lib_m);
	lua_pop (L, 1);
	rspamd_lua_add_preload (L, "rspamd_util", lua_load_util);
}

static int
lua_int64_tostring (lua_State *L)
{
	gint64 n = lua_check_int64 (L, 1);
	gchar buf[32];

	rspamd_snprintf (buf, sizeof (buf), "%uL", n);
	lua_pushstring (L, buf);

	return 1;
}

static int
lua_int64_tonumber (lua_State *L)
{
	gint64 n = lua_check_int64 (L, 1);
	gdouble d;

	d = n;
	lua_pushnumber (L, d);

	return 1;
}

static int
lua_int64_hex (lua_State *L)
{
	gint64 n = lua_check_int64 (L, 1);
	gchar buf[32];

	rspamd_snprintf (buf, sizeof (buf), "%XL", n);
	lua_pushstring (L, buf);

	return 1;
}

static int
lua_ev_base_loop (lua_State *L)
{
	int flags = 0;
	struct event_base *ev_base;

	ev_base = lua_check_ev_base (L, 1);
	if (lua_isnumber (L, 2)) {
		flags = lua_tonumber (L, 2);
	}

	int ret = event_base_loop (ev_base, flags);
	lua_pushinteger (L, ret);

	return 1;
}
