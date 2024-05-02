/*
 * Copyright 2024 Vsevolod Stakhov
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
#include "unix-std.h"
#include "lua_compress.h"
#include "libmime/email_addr.h"
#include "libmime/content_type.h"
#include "libmime/mime_headers.h"
#include "libutil/hash.h"

#include "lua_parsers.h"

#ifdef WITH_LUA_REPL
#include "replxx.h"
#endif

#include <math.h>
#include <glob.h>

#include "unicode/uspoof.h"
#include "unicode/uscript.h"
#include "contrib/fastutf8/fastutf8.h"

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
LUA_FUNCTION_DEF(util, create_event_base);
/***
 * @function util.load_rspamd_config(filename)
 * Load rspamd config from the specified file
 * @return {confg} new configuration object suitable for access
 */
LUA_FUNCTION_DEF(util, load_rspamd_config);
/***
 * @function util.config_from_ucl(any, string)
 * Load rspamd config from ucl represented by any lua table
 * @return {confg} new configuration object suitable for access
 */
LUA_FUNCTION_DEF(util, config_from_ucl);
/***
 * @function util.encode_base64(input[, str_len, [newlines_type]])
 * Encodes data in base64 breaking lines if needed
 * @param {text or string} input input data
 * @param {number} str_len optional size of lines or 0 if split is not needed
 * @return {rspamd_text} encoded data chunk
 */
LUA_FUNCTION_DEF(util, encode_base64);
/***
 * @function util.encode_qp(input[, str_len, [newlines_type]])
 * Encodes data in quoted printable breaking lines if needed
 * @param {text or string} input input data
 * @param {number} str_len optional size of lines or 0 if split is not needed
 * @return {rspamd_text} encoded data chunk
 */
LUA_FUNCTION_DEF(util, encode_qp);

/***
 * @function util.decode_qp(input)
 * Decodes data from quoted printable
 * @param {text or string} input input data
 * @return {rspamd_text} decoded data chunk
 */
LUA_FUNCTION_DEF(util, decode_qp);

/***
 * @function util.decode_base64(input)
 * Decodes data from base64 ignoring whitespace characters
 * @param {text or string} input data to decode; if `rspamd{text}` is used then the string is modified **in-place**
 * @return {rspamd_text} decoded data chunk
 */
LUA_FUNCTION_DEF(util, decode_base64);

/***
 * @function util.encode_base32(input, [b32type = 'default'])
 * Encodes data in base32 breaking lines if needed
 * @param {text or string} input input data
 * @param {string} b32type base32 type (default, bleach, rfc)
 * @return {rspamd_text} encoded data chunk
 */
LUA_FUNCTION_DEF(util, encode_base32);
/***
 * @function util.decode_base32(input, [b32type = 'default'])
 * Decodes data from base32 ignoring whitespace characters
 * @param {text or string} input data to decode
 * @param {string} b32type base32 type (default, bleach, rfc)
 * @return {rspamd_text} decoded data chunk
 */
LUA_FUNCTION_DEF(util, decode_base32);

/***
 * @function util.decode_url(input)
 * Decodes data from url encoding
 * @param {text or string} input data to decode
 * @return {rspamd_text} decoded data chunk
 */
LUA_FUNCTION_DEF(util, decode_url);

/***
 * @function util.tokenize_text(input[, exceptions])
 * Create tokens from a text using optional exceptions list
 * @param {text/string} input input data
 * @param {table} exceptions, a table of pairs containing <start_pos,length> of exceptions in the input
 * @return {table/strings} list of strings representing words in the text
 */
LUA_FUNCTION_DEF(util, tokenize_text);
LUA_FUNCTION_DEF(util, process_message);
/***
 * @function util.tanh(num)
 * Calculates hyperbolic tangent of the specified floating point value
 * @param {number} num input number
 * @return {number} hyperbolic tangent of the variable
 */
LUA_FUNCTION_DEF(util, tanh);

/***
 * @function util.parse_html(input)
 * Parses HTML and returns the according text
 * @param {string|text} in input HTML
 * @return {rspamd_text} processed text with no HTML tags
 */
LUA_FUNCTION_DEF(util, parse_html);

/***
 * @function util.levenshtein_distance(s1, s2)
 * Returns levenstein distance between two strings
 * @param {string} s1 the first string
 * @param {string} s2 the second string
 * @return {number} number of differences in two strings
 */
LUA_FUNCTION_DEF(util, levenshtein_distance);

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
LUA_FUNCTION_DEF(util, fold_header);

/***
 * @function util.is_uppercase(str)
 * Returns true if a string is all uppercase
 *
 * @param {string} str input string
 * @return {bool} true if a string is all uppercase
 */
LUA_FUNCTION_DEF(util, is_uppercase);

/***
 * @function util.humanize_number(num)
 * Returns humanized representation of given number (like 1k instead of 1000)
 *
 * @param {number} num number to humanize
 * @return {string} humanized representation of a number
 */
LUA_FUNCTION_DEF(util, humanize_number);

/***
 * @function util.get_tld(host)
 * Returns effective second level domain part (eSLD) for the specified host
 *
 * @param {string} host hostname
 * @return {string} eSLD part of the hostname or the full hostname if eSLD was not found
 */
LUA_FUNCTION_DEF(util, get_tld);

/***
 * @function util.glob(pattern)
 * Returns results for the glob match for the specified pattern
 *
 * @param {string} pattern glob pattern to match ('?' and '*' are supported)
 * @return {table/string} list of matched files
 */
LUA_FUNCTION_DEF(util, glob);

/***
 * @function util.parse_mail_address(str, [pool])
 * Parses email address and returns a table of tables in the following format:
 *
 * - `raw` - the original value without any processing
 * - `name` - name of internet address in UTF8, e.g. for `Vsevolod Stakhov <blah@foo.com>` it returns `Vsevolod Stakhov`
 * - `addr` - address part of the address
 * - `user` - user part (if present) of the address, e.g. `blah`
 * - `domain` - domain part (if present), e.g. `foo.com`
 * - `flags` - table with following keys set to true if given condition fulfilled:
 *   - [valid] - valid SMTP address in conformity with https://tools.ietf.org/html/rfc5321#section-4.1.
 *   - [ip] - domain is IPv4/IPv6 address
 *   - [braced] - angled `<blah@foo.com>` address
 *   - [quoted] - quoted user part
 *   - [empty] - empty address
 *   - [backslash] - user part contains backslash
 *   - [8bit] - contains 8bit characters
 *
 * @param {string} str input string
 * @param {rspamd_mempool} pool memory pool to use
 * @return {table/tables} parsed list of mail addresses
 */
LUA_FUNCTION_DEF(util, parse_mail_address);

/***
 * @function util.strlen_utf8(str)
 * Returns length of string encoded in utf-8 in characters.
 * If invalid characters are found, then this function returns number of bytes.
 * @param {string} str utf8 encoded string
 * @return {number} number of characters in string
 */
LUA_FUNCTION_DEF(util, strlen_utf8);

/***
 * @function util.lower_utf8(str)
 * Converts utf8 string to lower case
 * @param {string} str utf8 encoded string
 * @return {string} lowercased utf8 string
 */
LUA_FUNCTION_DEF(util, lower_utf8);

/***
 * @function util.normalize_utf8(str)
 *  Gets a string in UTF8 and normalises it to NFKC_Casefold form
 * @param {string} str utf8 encoded string
 * @return {string,integer} lowercased utf8 string + result of the normalisation (use bit.band to check):
 * RSPAMD_UNICODE_NORM_NORMAL = 0,
 * RSPAMD_UNICODE_NORM_UNNORMAL = (1 << 0),
 * RSPAMD_UNICODE_NORM_ZERO_SPACES = (1 << 1),
 * RSPAMD_UNICODE_NORM_ERROR = (1 << 2),
 * RSPAMD_UNICODE_NORM_OVERFLOW = (1 << 3)
 */
LUA_FUNCTION_DEF(util, normalize_utf8);


/***
 * @function util.transliterate(str)
 * Converts utf8 encoded string to latin transliteration
 * @param {string/text} str utf8 encoded string
 * @return {text} transliterated string
 */
LUA_FUNCTION_DEF(util, transliterate);

/***
 * @function util.strequal_caseless(str1, str2)
 * Compares two strings regardless of their case using ascii comparison.
 * Returns `true` if `str1` is equal to `str2`
 * @param {string} str1 utf8 encoded string
 * @param {string} str2 utf8 encoded string
 * @return {bool} result of comparison
 */
LUA_FUNCTION_DEF(util, strequal_caseless);


/***
 * @function util.strequal_caseless_utf8(str1, str2)
 * Compares two utf8 strings regardless of their case using utf8 collation rules.
 * Returns `true` if `str1` is equal to `str2`
 * @param {string} str1 utf8 encoded string
 * @param {string} str2 utf8 encoded string
 * @return {bool} result of comparison
 */
LUA_FUNCTION_DEF(util, strequal_caseless_utf8);


/***
 * @function util.get_ticks()
 * Returns current number of ticks as floating point number
 * @return {number} number of current clock ticks (monotonically increasing)
 */
LUA_FUNCTION_DEF(util, get_ticks);

/***
 * @function util.get_time()
 * Returns current time as unix time in floating point representation
 * @return {number} number of seconds since 01.01.1970
 */
LUA_FUNCTION_DEF(util, get_time);

/***
 * @function util.time_to_string(seconds)
 * Converts time from Unix time to HTTP date format
 * @param {number} seconds unix timestamp
 * @return {string} date as HTTP date
 */
LUA_FUNCTION_DEF(util, time_to_string);

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
LUA_FUNCTION_DEF(util, stat);

/***
 * @function util.unlink(fname)
 * Removes the specified file from the filesystem
 *
 * @param {string} fname filename to remove
 * @return {boolean,[string]} true if file has been deleted or false,'error string'
 */
LUA_FUNCTION_DEF(util, unlink);

/***
 * @function util.lock_file(fname, [fd])
 * Lock the specified file. This function returns {number} which must be passed to `util.unlock_file` after usage
 * or you'll have a resource leak
 *
 * @param {string} fname filename to lock
 * @param {number} fd use the specified fd instead of opening one
 * @return {number|nil,string} number if locking was successful or nil + error otherwise
 */
LUA_FUNCTION_DEF(util, lock_file);

/***
 * @function util.unlock_file(fd, [close_fd])
 * Unlock the specified file closing the file descriptor associated.
 *
 * @param {number} fd descriptor to unlock
 * @param {boolean} close_fd close descriptor on unlocking (default: TRUE)
 * @return {boolean[,string]} true if a file was unlocked
 */
LUA_FUNCTION_DEF(util, unlock_file);

/***
 * @function util.create_file(fname, [mode])
 * Creates the specified file with the default mode 0644
 *
 * @param {string} fname filename to create
 * @param {number} mode open mode (you should use octal number here)
 * @return {number|nil,string} file descriptor or pair nil + error string
 */
LUA_FUNCTION_DEF(util, create_file);

/***
 * @function util.close_file(fd)
 * Closes descriptor fd
 *
 * @param {number} fd descriptor to close
 * @return {boolean[,string]} true if a file was closed
 */
LUA_FUNCTION_DEF(util, close_file);

/***
 * @function util.random_hex(size)
 * Returns random hex string of the specified size
 *
 * @param {number} len length of desired string in bytes
 * @return {string} string with random hex digests
 */
LUA_FUNCTION_DEF(util, random_hex);

/***
 * @function util.zstd_compress(data, [level=1])
 * Compresses input using zstd compression
 *
 * @param {string/rspamd_text} data input data
 * @return {rspamd_text} compressed data
 */
LUA_FUNCTION_DEF(util, zstd_compress);

/***
 * @function util.zstd_decompress(data)
 * Decompresses input using zstd algorithm
 *
 * @param {string/rspamd_text} data compressed data
 * @return {error,rspamd_text} pair of error + decompressed text
 */
LUA_FUNCTION_DEF(util, zstd_decompress);

/***
 * @function util.gzip_decompress(data, [size_limit])
 * Decompresses input using gzip algorithm
 *
 * @param {string/rspamd_text} data compressed data
 * @param {integer} size_limit optional size limit
 * @return {rspamd_text} decompressed text
 */
LUA_FUNCTION_DEF(util, gzip_decompress);

/***
 * @function util.inflate(data, [size_limit])
 * Decompresses input using inflate algorithm
 *
 * @param {string/rspamd_text} data compressed data
 * @param {integer} size_limit optional size limit
 * @return {rspamd_text} decompressed text
 */
LUA_FUNCTION_DEF(util, inflate);

/***
 * @function util.gzip_compress(data, [level=1])
 * Compresses input using gzip compression
 *
 * @param {string/rspamd_text} data input data
 * @return {rspamd_text} compressed data
 */
LUA_FUNCTION_DEF(util, gzip_compress);

/***
 * @function util.normalize_prob(prob, [bias = 0.5])
 * Normalize probabilities using polynom
 *
 * @param {number} prob probability param
 * @param {number} bias number to subtract for making the final solution
 * @return {number} normalized number
 */
LUA_FUNCTION_DEF(util, normalize_prob);
/***
 * @function util.is_utf_spoofed(str, [str2])
 * Returns true if a string is spoofed (possibly with another string `str2`)
 * @return {boolean} true if a string is spoofed
 */
LUA_FUNCTION_DEF(util, is_utf_spoofed);

/**
* @function util.is_utf_mixed_script(str)
* Returns true if a string contains mixed unicode scripts
* @param {string} String to check
* @return {boolean} true if a string contains chars with mixed unicode script
*/
LUA_FUNCTION_DEF(util, is_utf_mixed_script);

/**
* @function util.is_utf_outside_range(str, range_start, range_end)
* Returns true if a string contains chars outside range
* @param {string} String to check
* @param {number} start of character range similar to uset_addRange
* @param {number} end of character range similar to uset_addRange
* @return {boolean} true if a string contains chars outside selected utf range
*/
LUA_FUNCTION_DEF(util, is_utf_outside_range);

/***
* @function util.get_string_stats(str)
* Returns table with number of letters and digits in string
* @return {table} with string stats keys are "digits" and "letters"
*/
LUA_FUNCTION_DEF(util, get_string_stats);

/***
 * @function util.is_valid_utf8(str)
 * Returns true if a string is valid UTF8 string
 * @return {boolean} true if a string is spoofed
 */
LUA_FUNCTION_DEF(util, is_valid_utf8);

/***
 * @function util.has_obscured_unicode(str)
 * Returns true if a string has obscure UTF symbols (zero width spaces, order marks), ignores invalid utf characters
 * @return {boolean} true if a has obscured unicode characters (+ character and offset if found)
 */
LUA_FUNCTION_DEF(util, has_obscured_unicode);

/***
 * @function util.readline([prompt])
 * Returns string read from stdin with history and editing support
 * @return {string} string read from the input (with line endings stripped)
 */
LUA_FUNCTION_DEF(util, readline);

/***
 * @function util.readpassphrase([prompt])
 * Returns string read from stdin disabling echo
 * @return {string} string read from the input (with line endings stripped)
 */
LUA_FUNCTION_DEF(util, readpassphrase);

/***
 * @function util.file_exists(file)
 * Checks if a specified file exists and is available for reading
 * @return {boolean,string} true if file exists + string error if not
 */
LUA_FUNCTION_DEF(util, file_exists);

/***
 * @function util.mkdir(dir[, recursive])
 * Creates a specified directory
 * @return {boolean[,error]} true if directory has been created
 */
LUA_FUNCTION_DEF(util, mkdir);

/***
 * @function util.umask(mask)
 * Sets new umask. Accepts either numeric octal string, e.g. '022' or a plain
 * number, e.g. 0x12 (since Lua does not support octal integrals)
 * @return {number} old umask
 */
LUA_FUNCTION_DEF(util, umask);

/***
 * @function util.isatty()
 * Returns if stdout is a tty
 * @return {boolean} true in case of output being tty
 */
LUA_FUNCTION_DEF(util, isatty);

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
LUA_FUNCTION_DEF(util, pack);

/***
 * @function util.packsize(fmt)
 *
 * Returns size of the packed binary string returned for the same `fmt` argument
 * by @see util.pack
 */
LUA_FUNCTION_DEF(util, packsize);

/***
 * @function util.unpack(fmt, s [, pos])
 * Unpacks string `s` according to the format string `fmt` as described in
 * @see util.pack
 *
 * @returns {multiple} list of unpacked values according to `fmt`
 */
LUA_FUNCTION_DEF(util, unpack);

/***
 *  @function util.caseless_hash(str[, seed])
 * Calculates caseless non-crypto hash from a string or rspamd text
 * @param str string or lua_text
 * @param seed mandatory seed (0xdeadbabe by default)
 * @return {int64} boxed int64_t
 */
LUA_FUNCTION_DEF(util, caseless_hash);

/***
 *  @function util.caseless_hash_fast(str[, seed])
 * Calculates caseless non-crypto hash from a string or rspamd text
 * @param str string or lua_text
 * @param seed mandatory seed (0xdeadbabe by default)
 * @return {number} number from int64_t
 */
LUA_FUNCTION_DEF(util, caseless_hash_fast);

/***
 *  @function util.get_hostname()
 * Returns hostname for this machine
 * @return {string} hostname
 */
LUA_FUNCTION_DEF(util, get_hostname);

/***
 *  @function util.parse_content_type(ct_string, mempool)
 * Parses content-type string to a table:
 * - `type`
 * - `subtype`
 * - `charset`
 * - `boundary`
 * - other attributes
 *
 * @param {string} ct_string content type as string
 * @param {rspamd_mempool} mempool needed to store temporary data (e.g. task pool)
 * @return table or nil if cannot parse content type
 */
LUA_FUNCTION_DEF(util, parse_content_type);

/***
 *  @function util.mime_header_encode(hdr)
 * Encodes header if needed
 * @param {string} hdr input header
 * @return encoded header
 */
LUA_FUNCTION_DEF(util, mime_header_encode);

/***
 *  @function util.btc_polymod(input_values)
 * Performs bitcoin polymod function
 * @param {table|numbers} input_values
 * @return {boolean} true if polymod has been successful
 */
LUA_FUNCTION_DEF(util, btc_polymod);

/***
 * @function util.parse_smtp_date(str[, local_tz])
 * Converts an SMTP date string to unix timestamp
 * @param {string} str input string
 * @param {boolean} local_tz convert to local tz if `true`
 * @return {number} time as unix timestamp (converted to float)
 */
LUA_FUNCTION_DEF(util, parse_smtp_date);


static const struct luaL_reg utillib_f[] = {
	LUA_INTERFACE_DEF(util, create_event_base),
	LUA_INTERFACE_DEF(util, load_rspamd_config),
	LUA_INTERFACE_DEF(util, config_from_ucl),
	LUA_INTERFACE_DEF(util, process_message),
	LUA_INTERFACE_DEF(util, encode_base64),
	LUA_INTERFACE_DEF(util, encode_qp),
	LUA_INTERFACE_DEF(util, decode_qp),
	LUA_INTERFACE_DEF(util, decode_base64),
	LUA_INTERFACE_DEF(util, encode_base32),
	LUA_INTERFACE_DEF(util, decode_base32),
	LUA_INTERFACE_DEF(util, decode_url),
	LUA_INTERFACE_DEF(util, tokenize_text),
	LUA_INTERFACE_DEF(util, tanh),
	LUA_INTERFACE_DEF(util, parse_html),
	LUA_INTERFACE_DEF(util, levenshtein_distance),
	LUA_INTERFACE_DEF(util, fold_header),
	LUA_INTERFACE_DEF(util, is_uppercase),
	LUA_INTERFACE_DEF(util, humanize_number),
	LUA_INTERFACE_DEF(util, get_tld),
	LUA_INTERFACE_DEF(util, glob),
	{"parse_addr", lua_util_parse_mail_address},
	LUA_INTERFACE_DEF(util, parse_mail_address),
	LUA_INTERFACE_DEF(util, strlen_utf8),
	LUA_INTERFACE_DEF(util, lower_utf8),
	LUA_INTERFACE_DEF(util, normalize_utf8),
	LUA_INTERFACE_DEF(util, transliterate),
	LUA_INTERFACE_DEF(util, strequal_caseless),
	LUA_INTERFACE_DEF(util, strequal_caseless_utf8),
	LUA_INTERFACE_DEF(util, get_ticks),
	LUA_INTERFACE_DEF(util, get_time),
	LUA_INTERFACE_DEF(util, time_to_string),
	LUA_INTERFACE_DEF(util, stat),
	LUA_INTERFACE_DEF(util, unlink),
	LUA_INTERFACE_DEF(util, lock_file),
	LUA_INTERFACE_DEF(util, unlock_file),
	LUA_INTERFACE_DEF(util, create_file),
	LUA_INTERFACE_DEF(util, close_file),
	LUA_INTERFACE_DEF(util, random_hex),
	LUA_INTERFACE_DEF(util, zstd_compress),
	LUA_INTERFACE_DEF(util, zstd_decompress),
	LUA_INTERFACE_DEF(util, gzip_compress),
	LUA_INTERFACE_DEF(util, gzip_decompress),
	LUA_INTERFACE_DEF(util, inflate),
	LUA_INTERFACE_DEF(util, normalize_prob),
	LUA_INTERFACE_DEF(util, caseless_hash),
	LUA_INTERFACE_DEF(util, caseless_hash_fast),
	LUA_INTERFACE_DEF(util, is_utf_spoofed),
	LUA_INTERFACE_DEF(util, is_utf_mixed_script),
	LUA_INTERFACE_DEF(util, is_utf_outside_range),
	LUA_INTERFACE_DEF(util, get_string_stats),
	LUA_INTERFACE_DEF(util, is_valid_utf8),
	LUA_INTERFACE_DEF(util, has_obscured_unicode),
	LUA_INTERFACE_DEF(util, readline),
	LUA_INTERFACE_DEF(util, readpassphrase),
	LUA_INTERFACE_DEF(util, file_exists),
	LUA_INTERFACE_DEF(util, mkdir),
	LUA_INTERFACE_DEF(util, umask),
	LUA_INTERFACE_DEF(util, isatty),
	LUA_INTERFACE_DEF(util, get_hostname),
	LUA_INTERFACE_DEF(util, parse_content_type),
	LUA_INTERFACE_DEF(util, mime_header_encode),
	LUA_INTERFACE_DEF(util, pack),
	LUA_INTERFACE_DEF(util, unpack),
	LUA_INTERFACE_DEF(util, packsize),
	LUA_INTERFACE_DEF(util, btc_polymod),
	LUA_INTERFACE_DEF(util, parse_smtp_date),
	{NULL, NULL}};

LUA_FUNCTION_DEF(int64, tostring);
LUA_FUNCTION_DEF(int64, fromstring);
LUA_FUNCTION_DEF(int64, tonumber);
LUA_FUNCTION_DEF(int64, hex);

static const struct luaL_reg int64lib_f[] = {
	LUA_INTERFACE_DEF(int64, fromstring),
	{NULL, NULL}};
static const struct luaL_reg int64lib_m[] = {
	LUA_INTERFACE_DEF(int64, tostring),
	LUA_INTERFACE_DEF(int64, tonumber),
	LUA_INTERFACE_DEF(int64, hex),
	{"__tostring", lua_int64_tostring},
	{NULL, NULL}};

LUA_FUNCTION_DEF(ev_base, loop);

static const struct luaL_reg ev_baselib_m[] = {
	LUA_INTERFACE_DEF(ev_base, loop),
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}};

static int64_t
lua_check_int64(lua_State *L, int pos)
{
	void *ud = rspamd_lua_check_udata(L, pos, rspamd_int64_classname);
	luaL_argcheck(L, ud != NULL, pos, "'int64' expected");
	return ud ? *((int64_t *) ud) : 0LL;
}


static int
lua_util_create_event_base(lua_State *L)
{
	LUA_TRACE_POINT;
	struct ev_loop **pev_base;

	pev_base = lua_newuserdata(L, sizeof(struct ev_loop *));
	rspamd_lua_setclass(L, rspamd_ev_base_classname, -1);
	*pev_base = ev_loop_new(EVFLAG_SIGNALFD | EVBACKEND_ALL);

	return 1;
}

static int
lua_util_load_rspamd_config(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg, **pcfg;
	const char *cfg_name;

	cfg_name = luaL_checkstring(L, 1);

	if (cfg_name) {
		cfg = rspamd_config_new(RSPAMD_CONFIG_INIT_SKIP_LUA);
		cfg->lua_state = L;

		if (rspamd_config_read(cfg, cfg_name, NULL, NULL, NULL, FALSE, NULL)) {
			msg_err_config("cannot load config from %s", cfg_name);
			lua_pushnil(L);
		}
		else {
			rspamd_config_post_load(cfg, 0);
			pcfg = lua_newuserdata(L, sizeof(struct rspamd_config *));
			rspamd_lua_setclass(L, rspamd_config_classname, -1);
			*pcfg = cfg;
		}
	}

	return 1;
}

static int
parse_config_options(const char *str_options)
{
	int ret = 0;
	char **vec;
	const char *str;
	unsigned int i, l;

	vec = g_strsplit_set(str_options, ",;", -1);
	if (vec) {
		l = g_strv_length(vec);
		for (i = 0; i < l; i++) {
			str = vec[i];

			if (g_ascii_strcasecmp(str, "INIT_URL") == 0) {
				ret |= RSPAMD_CONFIG_INIT_URL;
			}
			else if (g_ascii_strcasecmp(str, "INIT_LIBS") == 0) {
				ret |= RSPAMD_CONFIG_INIT_LIBS;
			}
			else if (g_ascii_strcasecmp(str, "INIT_SYMCACHE") == 0) {
				ret |= RSPAMD_CONFIG_INIT_SYMCACHE;
			}
			else if (g_ascii_strcasecmp(str, "INIT_VALIDATE") == 0) {
				ret |= RSPAMD_CONFIG_INIT_VALIDATE;
			}
			else if (g_ascii_strcasecmp(str, "INIT_NO_TLD") == 0) {
				ret |= RSPAMD_CONFIG_INIT_NO_TLD;
			}
			else if (g_ascii_strcasecmp(str, "INIT_PRELOAD_MAPS") == 0) {
				ret |= RSPAMD_CONFIG_INIT_PRELOAD_MAPS;
			}
			else {
				msg_warn("bad type: %s", str);
			}
		}

		g_strfreev(vec);
	}

	return ret;
}

static int
lua_util_config_from_ucl(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = NULL, **pcfg;
	struct rspamd_rcl_sections_map *top;
	GError *err = NULL;
	ucl_object_t *obj;
	const char *str_options = NULL;
	int int_options = 0;


	obj = ucl_object_lua_import(L, 1);
	if (lua_gettop(L) == 2) {
		if (lua_type(L, 2) == LUA_TSTRING) {
			str_options = lua_tostring(L, 2);
			int_options = parse_config_options(str_options);
		}
		else {
			msg_err("config_from_ucl: second parameter is expected to be string");
			ucl_object_unref(obj);
			lua_pushnil(L);
		}
	}

	if (obj) {
		cfg = rspamd_config_new(RSPAMD_CONFIG_INIT_SKIP_LUA);
		cfg->lua_state = L;

		cfg->cfg_ucl_obj = obj;
		top = rspamd_rcl_config_init(cfg, NULL);

		if (!rspamd_rcl_parse(top, cfg, cfg, cfg->cfg_pool, cfg->cfg_ucl_obj, &err)) {
			msg_err("rcl parse error: %s", err->message);
			ucl_object_unref(obj);
			lua_pushnil(L);
		}
		else {

			if (int_options & RSPAMD_CONFIG_INIT_LIBS) {
				cfg->libs_ctx = rspamd_init_libs();
			}

			rspamd_config_post_load(cfg, int_options);
			pcfg = lua_newuserdata(L, sizeof(struct rspamd_config *));
			rspamd_lua_setclass(L, rspamd_config_classname, -1);
			*pcfg = cfg;
		}

		rspamd_rcl_sections_free(top);
	}

	return 1;
}

static gboolean
lua_util_task_fin(struct rspamd_task *task, void *ud)
{
	ucl_object_t **target = ud;

	*target = rspamd_protocol_write_ucl(task, RSPAMD_PROTOCOL_DEFAULT);
	rdns_resolver_release(task->resolver->r);

	return TRUE;
}

static int
lua_util_process_message(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_config *cfg = lua_check_config(L, 1);
	const char *message;
	gsize mlen;
	struct rspamd_task *task;
	struct ev_loop *base;
	ucl_object_t *res = NULL;

	message = luaL_checklstring(L, 2, &mlen);

	if (cfg != NULL && message != NULL) {
		base = ev_loop_new(EVFLAG_SIGNALFD | EVBACKEND_ALL);
		rspamd_init_filters(cfg, false, false);
		task = rspamd_task_new(NULL, cfg, NULL, NULL, base, FALSE);
		task->msg.begin = rspamd_mempool_alloc(task->task_pool, mlen);
		rspamd_strlcpy((gpointer) task->msg.begin, message, mlen);
		task->msg.len = mlen;
		task->fin_callback = lua_util_task_fin;
		task->fin_arg = &res;
		task->resolver = rspamd_dns_resolver_init(NULL, base, cfg);
		task->s = rspamd_session_create(task->task_pool, rspamd_task_fin,
										NULL, (event_finalizer_t) rspamd_task_free, task);

		if (!rspamd_task_load_message(task, NULL, message, mlen)) {
			lua_pushnil(L);
		}
		else {
			if (rspamd_task_process(task, RSPAMD_TASK_PROCESS_ALL)) {
				ev_loop(base, 0);

				if (res != NULL) {
					ucl_object_push_lua(L, res, true);

					ucl_object_unref(res);
				}
				else {
					ucl_object_push_lua(L,
										rspamd_protocol_write_ucl(task, RSPAMD_PROTOCOL_DEFAULT),
										true);
					rdns_resolver_release(task->resolver->r);
					rspamd_session_destroy(task->s);
				}
			}
			else {
				lua_pushnil(L);
			}
		}

		ev_loop_destroy(base);
	}
	else {
		lua_pushnil(L);
	}

	return 1;
}

static int
lua_util_encode_base64(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_text *t;
	char *out;
	gsize outlen;
	long str_lim = 0;
	gboolean fold = FALSE;

	t = lua_check_text_or_string(L, 1);

	if (lua_gettop(L) > 1) {
		str_lim = luaL_checkinteger(L, 2);
		fold = str_lim > 0;
	}

	if (t == NULL) {
		return luaL_error(L, "invalid arguments");
	}
	else {

		if (fold) {
			out = rspamd_encode_base64(t->start, t->len, str_lim, &outlen);
		}
		else {
			enum rspamd_newlines_type how = RSPAMD_TASK_NEWLINES_CRLF;

			if (lua_type(L, 3) == LUA_TSTRING) {
				const char *how_str = lua_tostring(L, 3);

				if (g_ascii_strcasecmp(how_str, "cr") == 0) {
					how = RSPAMD_TASK_NEWLINES_CR;
				}
				else if (g_ascii_strcasecmp(how_str, "lf") == 0) {
					how = RSPAMD_TASK_NEWLINES_LF;
				}
				else if (g_ascii_strcasecmp(how_str, "crlf") != 0) {
					return luaL_error(L, "invalid newline style: %s", how_str);
				}
			}

			out = rspamd_encode_base64_fold(t->start, t->len, str_lim, &outlen, how);
		}

		if (out != NULL) {
			lua_new_text(L, out, outlen, TRUE);
		}
		else {
			lua_pushnil(L);
		}
	}

	return 1;
}

static int
lua_util_encode_qp(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_text *t;
	const char *s = NULL;
	char *out;
	gsize inlen, outlen;
	unsigned int str_lim = 0;

	if (lua_type(L, 1) == LUA_TSTRING) {
		s = luaL_checklstring(L, 1, &inlen);
	}
	else if (lua_type(L, 1) == LUA_TUSERDATA) {
		t = lua_check_text(L, 1);

		if (t != NULL) {
			s = t->start;
			inlen = t->len;
		}
	}

	if (lua_gettop(L) > 1) {
		str_lim = luaL_checknumber(L, 2);
	}

	if (s == NULL) {
		lua_pushnil(L);
	}
	else {
		enum rspamd_newlines_type how = RSPAMD_TASK_NEWLINES_CRLF;

		if (lua_type(L, 3) == LUA_TSTRING) {
			const char *how_str = lua_tostring(L, 3);

			if (g_ascii_strcasecmp(how_str, "cr") == 0) {
				how = RSPAMD_TASK_NEWLINES_CR;
			}
			else if (g_ascii_strcasecmp(how_str, "lf") == 0) {
				how = RSPAMD_TASK_NEWLINES_LF;
			}
			else if (g_ascii_strcasecmp(how_str, "crlf") != 0) {
				return luaL_error(L, "invalid newline style: %s", how_str);
			}
		}

		out = rspamd_encode_qp_fold(s, inlen, str_lim, &outlen, how);

		if (out != NULL) {
			t = lua_newuserdata(L, sizeof(*t));
			rspamd_lua_setclass(L, rspamd_text_classname, -1);
			t->start = out;
			t->len = outlen;
			/* Need destruction */
			t->flags = RSPAMD_TEXT_FLAG_OWN;
		}
		else {
			lua_pushnil(L);
		}
	}

	return 1;
}

static int
lua_util_decode_qp(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_text *t, *out;
	const char *s = NULL;
	gsize inlen = 0;
	gssize outlen;

	if (lua_type(L, 1) == LUA_TSTRING) {
		s = luaL_checklstring(L, 1, &inlen);
	}
	else if (lua_type(L, 1) == LUA_TUSERDATA) {
		t = lua_check_text(L, 1);

		if (t != NULL) {
			s = t->start;
			inlen = t->len;
		}
	}

	if (s == NULL) {
		lua_pushnil(L);
	}
	else {
		out = lua_newuserdata(L, sizeof(*t));
		rspamd_lua_setclass(L, rspamd_text_classname, -1);
		out->start = g_malloc(inlen + 1);
		out->flags = RSPAMD_TEXT_FLAG_OWN;
		outlen = rspamd_decode_qp_buf(s, inlen, (char *) out->start, inlen + 1);

		if (outlen > 0) {
			out->len = outlen;
		}
		else {
			/*
			 * It removes out and frees memory on gc due to RSPAMD_TEXT_FLAG_OWN
			 */
			lua_pop(L, 1);
			lua_pushnil(L);
		}
	}

	return 1;
}

static int
lua_util_decode_base64(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_text *t;
	const char *s = NULL;
	gsize inlen = 0, outlen;

	if (lua_type(L, 1) == LUA_TSTRING) {
		s = luaL_checklstring(L, 1, &inlen);
	}
	else if (lua_type(L, 1) == LUA_TUSERDATA) {
		t = lua_check_text(L, 1);

		if (t != NULL) {
			s = t->start;
			inlen = t->len;
		}
	}

	if (s != NULL) {
		t = lua_newuserdata(L, sizeof(*t));
		rspamd_lua_setclass(L, rspamd_text_classname, -1);
		t->len = (inlen / 4) * 3 + 3;
		t->start = g_malloc(t->len);

		rspamd_cryptobox_base64_decode(s, inlen, (unsigned char *) t->start,
									   &outlen);
		t->len = outlen;
		t->flags = RSPAMD_TEXT_FLAG_OWN;
	}
	else {
		lua_pushnil(L);
	}

	return 1;
}

static int
lua_util_encode_base32(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_text *t;
	const char *s = NULL;
	char *out;
	enum rspamd_base32_type btype = RSPAMD_BASE32_DEFAULT;
	gsize inlen, outlen;

	if (lua_type(L, 1) == LUA_TSTRING) {
		s = luaL_checklstring(L, 1, &inlen);
	}
	else if (lua_type(L, 1) == LUA_TUSERDATA) {
		t = lua_check_text(L, 1);

		if (t != NULL) {
			s = t->start;
			inlen = t->len;
		}
	}

	if (lua_type(L, 2) == LUA_TSTRING) {
		btype = rspamd_base32_decode_type_from_str(lua_tostring(L, 2));

		if (btype == RSPAMD_BASE32_INVALID) {
			return luaL_error(L, "invalid b32 type: %s", lua_tostring(L, 2));
		}
	}

	if (s == NULL) {
		return luaL_error(L, "invalid arguments");
	}
	else {
		out = rspamd_encode_base32(s, inlen, btype);

		if (out != NULL) {
			t = lua_newuserdata(L, sizeof(*t));
			outlen = strlen(out);
			rspamd_lua_setclass(L, rspamd_text_classname, -1);
			t->start = out;
			t->len = outlen;
			/* Need destruction */
			t->flags = RSPAMD_TEXT_FLAG_OWN;
		}
		else {
			lua_pushnil(L);
		}
	}

	return 1;
}

static int
lua_util_decode_base32(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_text *t;
	const char *s = NULL;
	gsize inlen, outlen;
	enum rspamd_base32_type btype = RSPAMD_BASE32_DEFAULT;

	if (lua_type(L, 1) == LUA_TSTRING) {
		s = luaL_checklstring(L, 1, &inlen);
	}
	else if (lua_type(L, 1) == LUA_TUSERDATA) {
		t = lua_check_text(L, 1);

		if (t != NULL) {
			s = t->start;
			inlen = t->len;
		}
	}

	if (lua_type(L, 2) == LUA_TSTRING) {
		btype = rspamd_base32_decode_type_from_str(lua_tostring(L, 2));

		if (btype == RSPAMD_BASE32_INVALID) {
			return luaL_error(L, "invalid b32 type: %s", lua_tostring(L, 2));
		}
	}

	if (s != NULL) {
		unsigned char *decoded;

		decoded = rspamd_decode_base32(s, inlen, &outlen, btype);

		if (decoded) {
			t = lua_newuserdata(L, sizeof(*t));
			rspamd_lua_setclass(L, rspamd_text_classname, -1);
			t->start = (const char *) decoded;
			t->len = outlen;
			t->flags = RSPAMD_TEXT_FLAG_OWN;
		}
		else {
			lua_pushnil(L);
		}
	}
	else {
		lua_pushnil(L);
	}

	return 1;
}

static int
lua_util_decode_url(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_text *t;

	t = lua_check_text_or_string(L, 1);

	if (t != NULL) {
		struct rspamd_lua_text *out = lua_new_text(L, NULL, t->len, TRUE);

		out->len = rspamd_url_decode((char *) out->start, t->start, t->len);
	}
	else {
		lua_pushnil(L);
	}

	return 1;
}


static int
lua_util_tokenize_text(lua_State *L)
{
	return lua_parsers_tokenize_text(L);
}

static int
lua_util_tanh(lua_State *L)
{
	LUA_TRACE_POINT;
	double in = luaL_checknumber(L, 1);

	lua_pushnumber(L, tanh(in));

	return 1;
}

static int
lua_util_parse_html(lua_State *L)
{
	return lua_parsers_parse_html(L);
}

static int
lua_util_levenshtein_distance(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_text *t1, *t2;
	int dist = 0;
	unsigned int replace_cost = 1;

	t1 = lua_check_text_or_string(L, 1);
	t2 = lua_check_text_or_string(L, 2);
	if (lua_isnumber(L, 3)) {
		replace_cost = lua_tointeger(L, 3);
	}

	if (t1 && t2) {
		dist = rspamd_strings_levenshtein_distance(t1->start, t1->len, t2->start, t2->len,
												   replace_cost);
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	lua_pushinteger(L, dist);

	return 1;
}

static int
lua_util_fold_header(lua_State *L)
{
	LUA_TRACE_POINT;
	const char *how, *stop_chars = NULL;
	struct rspamd_lua_text *name, *value;
	GString *folded;

	name = lua_check_text_or_string(L, 1);
	value = lua_check_text_or_string(L, 2);

	if (name && value) {

		if (lua_isstring(L, 3)) {

			how = lua_tostring(L, 3);

			if (lua_isstring(L, 4)) {
				stop_chars = lua_tostring(L, 4);
			}

			if (strcmp(how, "cr") == 0) {
				folded = rspamd_header_value_fold(name->start, name->len,
												  value->start, value->len,
												  0,
												  RSPAMD_TASK_NEWLINES_CR, stop_chars);
			}
			else if (strcmp(how, "lf") == 0) {
				folded = rspamd_header_value_fold(name->start, name->len,
												  value->start, value->len, 0,
												  RSPAMD_TASK_NEWLINES_LF, stop_chars);
			}
			else {
				folded = rspamd_header_value_fold(name->start, name->len,
												  value->start, value->len, 0,
												  RSPAMD_TASK_NEWLINES_CRLF, stop_chars);
			}
		}
		else {
			folded = rspamd_header_value_fold(name->start, name->len,
											  value->start, value->len, 0,
											  RSPAMD_TASK_NEWLINES_CRLF, stop_chars);
		}

		if (folded) {
			lua_pushlstring(L, folded->str, folded->len);
			g_string_free(folded, TRUE);

			return 1;
		}
	}

	lua_pushnil(L);
	return 1;
}

static int
lua_util_is_uppercase(lua_State *L)
{
	LUA_TRACE_POINT;
	int32_t i = 0;
	UChar32 uc;
	bool is_upper = false, is_lower = false, is_other = false;

	struct rspamd_lua_text *t = lua_check_text_or_string(L, 1);
	if (t) {
		while (i >= 0 && i < t->len) {
			U8_NEXT(t->start, i, t->len, uc);

			if (uc < 0) {
				break;
			}

			if (u_isupper(uc)) {
				is_upper = true;
			}
			else if (u_islower(uc)) {
				is_lower = true;
				break;
			}
			else if (u_charType(uc) == U_OTHER_LETTER) {
				is_other = true;
				break;
			}
		}
	}

	if (is_upper && !is_lower && !is_other) {
		lua_pushboolean(L, TRUE);
	}
	else {
		lua_pushboolean(L, FALSE);
	}

	return 1;
}

static int
lua_util_humanize_number(lua_State *L)
{
	LUA_TRACE_POINT;
	int64_t number = luaL_checkinteger(L, 1);
	char numbuf[32];


	rspamd_snprintf(numbuf, sizeof(numbuf), "%hL", number);
	lua_pushstring(L, numbuf);

	return 1;
}

static int
lua_util_get_tld(lua_State *L)
{
	LUA_TRACE_POINT;
	const char *host;
	gsize hostlen;
	rspamd_ftok_t tld;

	host = luaL_checklstring(L, 1, &hostlen);

	if (host) {
		if (!rspamd_url_find_tld(host, hostlen, &tld)) {
			lua_pushlstring(L, host, hostlen);
		}
		else {
			lua_pushlstring(L, tld.begin, tld.len);
		}
	}
	else {
		lua_pushnil(L);
	}

	return 1;
}


static int
lua_util_glob(lua_State *L)
{
	LUA_TRACE_POINT;
	const char *pattern;
	glob_t gl;
	int top, i, flags = 0;

	top = lua_gettop(L);
	memset(&gl, 0, sizeof(gl));

	for (i = 1; i <= top; i++, flags |= GLOB_APPEND) {
		pattern = luaL_checkstring(L, i);

		if (pattern) {
			if (glob(pattern, flags, NULL, &gl) != 0) {
				/* There is no way to return error here, so just create an table */
				lua_createtable(L, 0, 0);
				globfree(&gl);

				return 1;
			}
		}
	}

	lua_createtable(L, gl.gl_pathc, 0);
	/* Push results */
	for (i = 0; i < (int) gl.gl_pathc; i++) {
		lua_pushstring(L, gl.gl_pathv[i]);
		lua_rawseti(L, -2, i + 1);
	}

	globfree(&gl);

	return 1;
}

static int
lua_util_parse_mail_address(lua_State *L)
{
	return lua_parsers_parse_mail_address(L);
}

static int
lua_util_strlen_utf8(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_text *t;

	t = lua_check_text_or_string(L, 1);

	if (t) {
		int32_t i = 0, nchars = 0;
		UChar32 uc;

		while (i < t->len) {
			U8_NEXT((uint8_t *) t->start, i, t->len, uc);
			nchars++;
		}

		lua_pushinteger(L, nchars);
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return 1;
}

static int
lua_util_lower_utf8(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_text *t;

	char *dst;
	UChar32 uc;
	UBool err = 0;
	int32_t i = 0, j = 0;

	t = lua_check_text_or_string(L, 1);

	if (t) {
		dst = g_malloc(t->len);

		while (i < t->len && err == 0) {
			U8_NEXT((uint8_t *) t->start, i, t->len, uc);
			uc = u_tolower(uc);
			U8_APPEND(dst, j, t->len, uc, err);
		}

		if (lua_isstring(L, 1)) {
			lua_pushlstring(L, dst, j);
			g_free(dst);
		}
		else {
			t = lua_new_text(L, dst, j, FALSE);
			/* We have actually allocated text data before */
			t->flags |= RSPAMD_TEXT_FLAG_OWN;
		}
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return 1;
}

static int
lua_util_normalize_utf8(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_text *t;
	bool is_text = lua_type(L, 1) == LUA_TUSERDATA;

	t = lua_check_text_or_string(L, 1);

	if (!t) {
		return luaL_error(L, "invalid arguments");
	}

	char *cpy = g_malloc(t->len + 1);
	memcpy(cpy, t->start, t->len);
	cpy[t->len] = '\0';
	gsize len = t->len;
	enum rspamd_utf8_normalise_result res = rspamd_normalise_unicode_inplace(cpy, &len);

	if (is_text) {
		struct rspamd_lua_text *out = lua_new_text(L, cpy, len, FALSE);
		out->flags |= RSPAMD_TEXT_FLAG_OWN;
	}
	else {
		lua_pushlstring(L, cpy, len);
		g_free(cpy);
	}

	lua_pushinteger(L, res);

	return 2;
}

static int
lua_util_transliterate(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_text *t;
	t = lua_check_text_or_string(L, 1);

	if (!t) {
		return luaL_error(L, "invalid arguments");
	}

	gsize outlen;
	char *transliterated = rspamd_utf8_transliterate(t->start, t->len, &outlen);
	lua_new_text(L, transliterated, outlen, TRUE);

	return 1;
}

static int
lua_util_strequal_caseless(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_text *t1, *t2;
	int ret = -1;

	t1 = lua_check_text_or_string(L, 1);
	t2 = lua_check_text_or_string(L, 2);

	if (t1 && t2) {

		if (t1->len == t2->len) {
			ret = rspamd_lc_cmp(t1->start, t2->start, t1->len);
		}
		else {
			ret = t1->len - t2->len;
		}
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	lua_pushboolean(L, (ret == 0) ? true : false);
	return 1;
}

static int
lua_util_strequal_caseless_utf8(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_text *t1, *t2;
	int ret = -1;

	t1 = lua_check_text_or_string(L, 1);
	t2 = lua_check_text_or_string(L, 2);

	if (t1 && t2) {
		ret = rspamd_utf8_strcmp_sizes(t1->start, t1->len, t2->start, t2->len);
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	lua_pushboolean(L, (ret == 0) ? true : false);

	return 1;
}

static int
lua_util_get_ticks(lua_State *L)
{
	LUA_TRACE_POINT;
	double ticks;
	gboolean rdtsc = FALSE;

	if (lua_isboolean(L, 1)) {
		rdtsc = lua_toboolean(L, 1);
	}

	ticks = rspamd_get_ticks(rdtsc);
	lua_pushnumber(L, ticks);

	return 1;
}

static int
lua_util_get_time(lua_State *L)
{
	LUA_TRACE_POINT;

	lua_pushnumber(L, ev_time());

	return 1;
}

static int
lua_util_time_to_string(lua_State *L)
{
	LUA_TRACE_POINT;
	double seconds;
	char timebuf[128];

	if (lua_isnumber(L, 1)) {
		seconds = lua_tonumber(L, 1);
	}
	else {
		seconds = ev_time();
	}

	rspamd_http_date_format(timebuf, sizeof(timebuf), seconds);
	lua_pushstring(L, timebuf);

	return 1;
}

static int
lua_util_stat(lua_State *L)
{
	LUA_TRACE_POINT;
	const char *fpath;
	struct stat st;

	fpath = luaL_checkstring(L, 1);

	if (fpath) {
		if (stat(fpath, &st) == -1) {
			lua_pushstring(L, strerror(errno));
			lua_pushnil(L);
		}
		else {
			lua_pushnil(L);
			lua_createtable(L, 0, 3);

			lua_pushstring(L, "size");
			lua_pushinteger(L, st.st_size);
			lua_settable(L, -3);

			lua_pushstring(L, "mtime");
			lua_pushinteger(L, st.st_mtime);
			lua_settable(L, -3);

			lua_pushstring(L, "type");
			if (S_ISREG(st.st_mode)) {
				lua_pushstring(L, "regular");
			}
			else if (S_ISDIR(st.st_mode)) {
				lua_pushstring(L, "directory");
			}
			else {
				lua_pushstring(L, "special");
			}
			lua_settable(L, -3);
		}
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return 2;
}

static int
lua_util_unlink(lua_State *L)
{
	LUA_TRACE_POINT;
	const char *fpath;
	int ret;

	fpath = luaL_checkstring(L, 1);

	if (fpath) {
		ret = unlink(fpath);

		if (ret == -1) {
			lua_pushboolean(L, false);
			lua_pushstring(L, strerror(errno));

			return 2;
		}

		lua_pushboolean(L, true);
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return 1;
}

static int
lua_util_lock_file(lua_State *L)
{
	LUA_TRACE_POINT;
	const char *fpath;
	int fd = -1;
	gboolean own = FALSE;

#if !HAVE_FLOCK
	struct flock fl = {
		.l_type = F_WRLCK,
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = 0};
#endif

	fpath = luaL_checkstring(L, 1);

	if (fpath) {
		if (lua_isnumber(L, 2)) {
			fd = lua_tointeger(L, 2);
		}
		else {
			fd = open(fpath, O_RDONLY);
			own = TRUE;
		}

		if (fd == -1) {
			lua_pushnil(L);
			lua_pushstring(L, strerror(errno));

			return 2;
		}

#if HAVE_FLOCK
		if (flock(fd, LOCK_EX) == -1) {
#else
		if (fcntl(fd, F_SETLKW, &fl) == -1) {
#endif
			lua_pushnil(L);
			lua_pushstring(L, strerror(errno));

			if (own) {
				close(fd);
			}

			return 2;
		}

		lua_pushinteger(L, fd);
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return 1;
}

static int
lua_util_unlock_file(lua_State *L)
{
	LUA_TRACE_POINT;
	int fd = -1, ret, serrno;
	gboolean do_close = TRUE;

#if !HAVE_FLOCK
	struct flock fl = {
		.l_type = F_UNLCK,
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = 0};
#endif

	if (lua_isnumber(L, 1)) {
		fd = lua_tointeger(L, 1);

		if (lua_isboolean(L, 2)) {
			do_close = lua_toboolean(L, 2);
		}

#if HAVE_FLOCK
		ret = flock(fd, LOCK_UN);
#else
		ret = fcntl(fd, F_SETLKW, &fl);
#endif

		if (do_close) {
			serrno = errno;
			close(fd);
			errno = serrno;
		}

		if (ret == -1) {
			lua_pushboolean(L, false);
			lua_pushstring(L, strerror(errno));

			return 2;
		}

		lua_pushboolean(L, true);
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return 1;
}

static int
lua_util_create_file(lua_State *L)
{
	LUA_TRACE_POINT;
	int fd, mode = 00644;
	const char *fpath;

	fpath = luaL_checkstring(L, 1);

	if (fpath) {
		if (lua_isnumber(L, 2)) {
			mode = lua_tointeger(L, 2);
		}

		fd = rspamd_file_xopen(fpath, O_RDWR | O_CREAT | O_TRUNC, mode, 0);

		if (fd == -1) {
			lua_pushnil(L);
			lua_pushstring(L, strerror(errno));

			return 2;
		}

		lua_pushinteger(L, fd);
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return 1;
}

static int
lua_util_close_file(lua_State *L)
{
	LUA_TRACE_POINT;
	int fd = -1;

	if (lua_isnumber(L, 1)) {
		fd = lua_tointeger(L, 1);

		if (close(fd) == -1) {
			lua_pushboolean(L, false);
			lua_pushstring(L, strerror(errno));

			return 2;
		}

		lua_pushboolean(L, true);
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return 1;
}

static int
lua_util_random_hex(lua_State *L)
{
	LUA_TRACE_POINT;
	char *buf;
	int buflen;

	buflen = lua_tointeger(L, 1);

	if (buflen <= 0) {
		return luaL_error(L, "invalid arguments");
	}

	buf = g_malloc(buflen);
	rspamd_random_hex(buf, buflen);
	lua_pushlstring(L, buf, buflen);
	g_free(buf);

	return 1;
}

static int
lua_util_zstd_compress(lua_State *L)
{
	return lua_compress_zstd_compress(L);
}

static int
lua_util_zstd_decompress(lua_State *L)
{
	return lua_compress_zstd_decompress(L);
}

static int
lua_util_gzip_compress(lua_State *L)
{
	return lua_compress_zlib_compress(L);
}

static int
lua_util_gzip_decompress(lua_State *L)
{
	return lua_compress_zlib_decompress(L, true);
}

static int
lua_util_inflate(lua_State *L)
{
	return lua_compress_zlib_decompress(L, false);
}

static int
lua_util_normalize_prob(lua_State *L)
{
	LUA_TRACE_POINT;
	double x, bias = 0.5;

	x = lua_tonumber(L, 1);

	if (lua_type(L, 2) == LUA_TNUMBER) {
		bias = lua_tonumber(L, 2);
	}

	lua_pushnumber(L, rspamd_normalize_probability(x, bias));

	return 1;
}

static int
lua_util_caseless_hash(lua_State *L)
{
	LUA_TRACE_POINT;
	uint64_t seed = 0xdeadbabe, h;
	struct rspamd_lua_text *t = NULL;
	int64_t *r;

	t = lua_check_text_or_string(L, 1);

	if (t == NULL || t->start == NULL) {
		return luaL_error(L, "invalid arguments");
	}

	if (lua_type(L, 2) == LUA_TNUMBER) {
		seed = lua_tointeger(L, 2);
	}
	else if (lua_type(L, 2) == LUA_TUSERDATA) {
		seed = lua_check_int64(L, 2);
	}

	h = rspamd_icase_hash(t->start, t->len, seed);
	r = lua_newuserdata(L, sizeof(*r));
	*r = h;
	rspamd_lua_setclass(L, rspamd_int64_classname, -1);

	return 1;
}

static int
lua_util_caseless_hash_fast(lua_State *L)
{
	LUA_TRACE_POINT;
	uint64_t seed = 0xdeadbabe, h;
	struct rspamd_lua_text *t = NULL;
	union {
		uint64_t i;
		double d;
	} u;

	t = lua_check_text_or_string(L, 1);

	if (t == NULL || t->start == NULL) {
		return luaL_error(L, "invalid arguments");
	}

	if (lua_type(L, 2) == LUA_TNUMBER) {
		seed = lua_tointeger(L, 2);
	}
	else if (lua_type(L, 2) == LUA_TUSERDATA) {
		seed = lua_check_int64(L, 2);
	}

	/*
	 * Here, we loose entropy from 64 bits to 52 bits roughly, however,
	 * it is still fine for practical applications
	 */

	h = rspamd_icase_hash(t->start, t->len, seed);
	u.i = G_GUINT64_CONSTANT(0x3FF) << 52 | h >> 12;
	lua_pushnumber(L, u.d - 1.0);

	return 1;
}

static int
lua_util_is_utf_spoofed(lua_State *L)
{
	LUA_TRACE_POINT;
	gsize l1, l2;
	int ret, nres = 2;
	const char *s1 = lua_tolstring(L, 1, &l1),
			   *s2 = lua_tolstring(L, 2, &l2);
	static USpoofChecker *spc, *spc_sgl;
	UErrorCode uc_err = U_ZERO_ERROR;

	if (s1 && s2) {
		if (spc == NULL) {
			spc = uspoof_open(&uc_err);

			if (uc_err != U_ZERO_ERROR) {
				msg_err("cannot init spoof checker: %s", u_errorName(uc_err));
				lua_pushboolean(L, false);

				return 1;
			}
		}

		ret = uspoof_areConfusableUTF8(spc, s1, l1, s2, l2, &uc_err);
	}
	else if (s1) {
		/* We have just s1, not s2 */
		if (spc_sgl == NULL) {
			spc_sgl = uspoof_open(&uc_err);

			if (uc_err != U_ZERO_ERROR) {
				msg_err("cannot init spoof checker: %s", u_errorName(uc_err));
				lua_pushboolean(L, false);

				return 1;
			}

			uspoof_setChecks(spc_sgl,
							 USPOOF_INVISIBLE | USPOOF_MIXED_SCRIPT_CONFUSABLE | USPOOF_ANY_CASE,
							 &uc_err);
			if (uc_err != U_ZERO_ERROR) {
				msg_err("Cannot set proper checks for uspoof: %s", u_errorName(uc_err));
				lua_pushboolean(L, false);
				uspoof_close(spc);
				return 1;
			}
		}

		ret = uspoof_checkUTF8(spc_sgl, s1, l1, NULL, &uc_err);
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	lua_pushboolean(L, !!(ret != 0));

	switch (ret) {
	case 0:
		nres = 1;
		break;
	case USPOOF_SINGLE_SCRIPT_CONFUSABLE:
		lua_pushstring(L, "single");
		break;
	case USPOOF_MIXED_SCRIPT_CONFUSABLE:
		lua_pushstring(L, "multiple");
		break;
	case USPOOF_WHOLE_SCRIPT_CONFUSABLE:
		lua_pushstring(L, "whole");
		break;
	default:
		lua_pushstring(L, "unknown");
		break;
	}

	return nres;
}

static int
lua_util_is_utf_mixed_script(lua_State *L)
{
	LUA_TRACE_POINT;
	gsize len_of_string;
	const unsigned char *string_to_check = lua_tolstring(L, 1, &len_of_string);
	UScriptCode last_script_code = USCRIPT_INVALID_CODE;
	UErrorCode uc_err = U_ZERO_ERROR;

	if (string_to_check) {
		uint index = 0;
		UChar32 char_to_check = 0;

		while (index < len_of_string) {
			U8_NEXT(string_to_check, index, len_of_string, char_to_check);

			if (char_to_check < 0) {
				return luaL_error(L, "passed string is not valid utf");
			}

			UScriptCode current_script_code = uscript_getScript(char_to_check, &uc_err);

			if (uc_err != U_ZERO_ERROR) {
				msg_err("cannot get unicode script for character, error: %s",
						u_errorName(uc_err));
				lua_pushboolean(L, false);

				return 1;
			}

			if (current_script_code != USCRIPT_COMMON &&
				current_script_code != USCRIPT_INHERITED) {

				if (last_script_code == USCRIPT_INVALID_CODE) {
					last_script_code = current_script_code;
				}
				else {
					if (last_script_code != current_script_code) {
						lua_pushboolean(L, true);

						return 1;
					}
				}
			}
		}
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	lua_pushboolean(L, false);

	return 1;
}

static int
lua_util_get_string_stats(lua_State *L)
{
	LUA_TRACE_POINT;
	int num_of_digits = 0, num_of_letters = 0;
	struct rspamd_lua_text *t;

	t = lua_check_text_or_string(L, 1);

	if (t) {
		const char *p = t->start, *end = t->start + t->len;
		while (p < end) {
			if (g_ascii_isdigit(*p)) {
				num_of_digits++;
			}
			else if (g_ascii_isalpha(*p)) {
				num_of_letters++;
			}
			p++;
		}
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	lua_createtable(L, 0, 2);
	lua_pushstring(L, "digits");
	lua_pushinteger(L, num_of_digits);
	lua_settable(L, -3);
	lua_pushstring(L, "letters");
	lua_pushinteger(L, num_of_letters);
	lua_settable(L, -3);

	return 1;
}


static int
lua_util_is_utf_outside_range(lua_State *L)
{
	LUA_TRACE_POINT;
	int ret;
	struct rspamd_lua_text *t = lua_check_text_or_string(L, 1);
	uint32_t range_start = lua_tointeger(L, 2);
	uint32_t range_end = lua_tointeger(L, 3);

	static rspamd_lru_hash_t *validators;

	if (validators == NULL) {
		validators = rspamd_lru_hash_new_full(16, g_free, (GDestroyNotify) uspoof_close, g_int64_hash, g_int64_equal);
	}

	if (t) {
		uint64_t hash_key = (uint64_t) range_end << 32 || range_start;

		USpoofChecker *validator = rspamd_lru_hash_lookup(validators, &hash_key, 0);

		UErrorCode uc_err = U_ZERO_ERROR;

		if (validator == NULL) {
			USet *allowed_chars;
			uint64_t *creation_hash_key = g_malloc(sizeof(uint64_t));
			*creation_hash_key = hash_key;

			validator = uspoof_open(&uc_err);
			if (uc_err != U_ZERO_ERROR) {
				msg_err("cannot init spoof checker: %s", u_errorName(uc_err));
				lua_pushboolean(L, false);
				uspoof_close(validator);
				g_free(creation_hash_key);
				return 1;
			}

			allowed_chars = uset_openEmpty();
			uset_addRange(allowed_chars, range_start, range_end);
			uspoof_setAllowedChars(validator, allowed_chars, &uc_err);

			uspoof_setChecks(validator,
							 USPOOF_CHAR_LIMIT | USPOOF_ANY_CASE, &uc_err);

			uset_close(allowed_chars);

			if (uc_err != U_ZERO_ERROR) {
				msg_err("Cannot configure uspoof: %s", u_errorName(uc_err));
				lua_pushboolean(L, false);
				uspoof_close(validator);
				g_free(creation_hash_key);
				return 1;
			}

			rspamd_lru_hash_insert(validators, creation_hash_key, validator,
								   0, 0);
		}

		int32_t pos = 0;
		ret = uspoof_checkUTF8(validator, t->start, t->len, &pos,
							   &uc_err);
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	lua_pushboolean(L, !!(ret != 0));

	return 1;
}


static int
lua_util_get_hostname(lua_State *L)
{
	LUA_TRACE_POINT;
	char *hostbuf;
	gsize hostlen;

	hostlen = sysconf(_SC_HOST_NAME_MAX);

	if (hostlen <= 0) {
		hostlen = 256;
	}
	else {
		hostlen++;
	}

	hostbuf = g_alloca(hostlen);
	memset(hostbuf, 0, hostlen);
	gethostname(hostbuf, hostlen - 1);

	lua_pushstring(L, hostbuf);

	return 1;
}

static int
lua_util_parse_content_type(lua_State *L)
{
	return lua_parsers_parse_content_type(L);
}


static int
lua_util_mime_header_encode(lua_State *L)
{
	LUA_TRACE_POINT;
	gsize len;
	const char *hdr = luaL_checklstring(L, 1, &len);
	char *encoded;

	if (!hdr) {
		return luaL_error(L, "invalid arguments");
	}

	encoded = rspamd_mime_header_encode(hdr, len);
	lua_pushstring(L, encoded);
	g_free(encoded);

	return 1;
}

static int
lua_util_is_valid_utf8(lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_text *t = lua_check_text_or_string(L, 1);

	if (t) {
		goffset error_offset = rspamd_fast_utf8_validate(t->start, t->len);

		if (error_offset == 0) {
			lua_pushboolean(L, true);
		}
		else {
			lua_pushboolean(L, false);
			lua_pushinteger(L, error_offset);

			return 2;
		}
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return 1;
}

static int
lua_util_has_obscured_unicode(lua_State *L)
{
	LUA_TRACE_POINT;
	int32_t i = 0, prev_i;
	UChar32 uc;

	struct rspamd_lua_text *t = lua_check_text_or_string(L, 1);

	while (i < t->len) {
		prev_i = i;
		U8_NEXT(t->start, i, t->len, uc);

		if (uc > 0) {
			if (IS_OBSCURED_CHAR(uc)) {
				lua_pushboolean(L, true);
				lua_pushinteger(L, uc);     /* Character */
				lua_pushinteger(L, prev_i); /* Offset */

				return 3;
			}
		}
	}

	lua_pushboolean(L, false);

	return 1;
}

static int
lua_util_readline(lua_State *L)
{
	LUA_TRACE_POINT;
	const char *prompt = "";
	char *input = NULL;

	if (lua_type(L, 1) == LUA_TSTRING) {
		prompt = lua_tostring(L, 1);
	}
#ifdef WITH_LUA_REPL
	static Replxx *rx_instance = NULL;

	if (rx_instance == NULL) {
		rx_instance = replxx_init();
		/* See https://github.com/AmokHuginnsson/replxx/issues/137 */
		replxx_history_add(rx_instance, "");
	}

	input = (char *) replxx_input(rx_instance, prompt);

	if (input) {
		lua_pushstring(L, input);
	}
	else {
		lua_pushnil(L);
	}
#else
	size_t linecap = 0;
	ssize_t linelen;

	fprintf(stdout, "%s ", prompt);

	linelen = getline(&input, &linecap, stdin);

	if (linelen > 0) {
		if (input[linelen - 1] == '\n') {
			linelen--;
		}

		lua_pushlstring(L, input, linelen);
		free(input);
	}
	else {
		lua_pushnil(L);
	}
#endif

	return 1;
}

static int
lua_util_readpassphrase(lua_State *L)
{
	LUA_TRACE_POINT;
	char test_password[8192];
	gsize r;

	r = rspamd_read_passphrase(test_password, sizeof(test_password), 0, NULL);

	if (r > 0) {
		lua_pushlstring(L, test_password, r);
	}
	else {
		lua_pushnil(L);
	}

	/* In fact, we still pass it to Lua which is not very safe */
	rspamd_explicit_memzero(test_password, sizeof(test_password));

	return 1;
}

static int
lua_util_file_exists(lua_State *L)
{
	LUA_TRACE_POINT;
	const char *fname = luaL_checkstring(L, 1);
	int serrno;

	if (fname) {
		if (access(fname, R_OK) == -1) {
			serrno = errno;
			lua_pushboolean(L, false);
			lua_pushstring(L, strerror(serrno));
		}
		else {
			lua_pushboolean(L, true);
			lua_pushnil(L);
		}
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return 2;
}

static int
lua_util_mkdir(lua_State *L)
{
	LUA_TRACE_POINT;
	const char *dname = luaL_checkstring(L, 1);
	gboolean recursive = FALSE;
	int r = -1;

	if (dname) {
		if (lua_isboolean(L, 2)) {
			recursive = lua_toboolean(L, 2);
		}

		if (recursive) {
			char path[PATH_MAX];
			gsize len, i;

			len = rspamd_strlcpy(path, dname, sizeof(path));

			/* Strip last / */
			if (path[len - 1] == '/') {
				path[len - 1] = '\0';
				len--;
			}

			for (i = 1; i < len; i++) {
				if (path[i] == '/') {
					path[i] = '\0';

					errno = 0;
					r = mkdir(path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);

					if (r == -1 && errno != EEXIST) {
						break;
					}

					path[i] = '/';
				}
			}

			/* Final path component */
			r = mkdir(path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
		}
		else {
			r = mkdir(dname, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
		}

		if (r == -1 && errno != EEXIST) {
			lua_pushboolean(L, false);
			lua_pushstring(L, strerror(errno));

			return 2;
		}

		lua_pushboolean(L, true);
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	return 1;
}


static int
lua_util_umask(lua_State *L)
{
	LUA_TRACE_POINT;
	mode_t mask = 0, old;

	if (lua_type(L, 1) == LUA_TSTRING) {
		const char *str = lua_tostring(L, 1);

		if (str[0] == '0') {
			/* e.g. '022' */
			mask = strtol(str, NULL, 8);
		}
		else {
			/* XXX: implement modestring parsing at some point */
			return luaL_error(L, "invalid arguments");
		}
	}
	else if (lua_type(L, 1) == LUA_TNUMBER) {
		mask = lua_tointeger(L, 1);
	}
	else {
		return luaL_error(L, "invalid arguments");
	}

	old = umask(mask);

	lua_pushinteger(L, old);

	return 1;
}

static int
lua_util_isatty(lua_State *L)
{
	LUA_TRACE_POINT;
	if (isatty(STDOUT_FILENO)) {
		lua_pushboolean(L, true);
	}
	else {
		lua_pushboolean(L, false);
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
#define LUA_PACKPADBYTE 0x00
#endif

/* maximum size for the binary representation of an integer */
#define MAXINTSIZE 16

/* number of bits in a character */
#define NB CHAR_BIT

/* mask for one character (NB 1's) */
#define MC ((1 << NB) - 1)

/* size of a lua_Integer */
#define SZINT ((int) sizeof(lua_Integer))

#define MAX_SIZET ((size_t) (~(size_t) 0))

#define MAXSIZE \
	(sizeof(size_t) < sizeof(int) ? MAX_SIZET : (size_t) (INT_MAX))


/* dummy union to get native endianness */
static const union {
	int dummy;
	char little; /* true if machine is little endian */
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

#define MAXALIGN (offsetof(struct cD, u))

/*
** Union for serializing floats
*/
typedef union Ftypes {
	float f;
	double d;
	lua_Number n;
	char buff[5 * sizeof(lua_Number)]; /* enough for any float type */
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
	Kint,       /* signed integers */
	Kuint,      /* unsigned integers */
	Kfloat,     /* floating-point numbers */
	Kchar,      /* fixed-length strings */
	Kstring,    /* strings with prefixed length */
	Kzstr,      /* zero-terminated strings */
	Kpadding,   /* padding */
	Kpaddalign, /* padding for alignment */
	Knop        /* no-op (configuration or spaces) */
} KOption;

#if LUA_VERSION_NUM <= 502
#define lua_Unsigned size_t
#endif

#if LUA_VERSION_NUM < 502

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
#define COMPAT53_API __attribute__((__unused__)) static
#else
#define COMPAT53_API static
#endif

#define COMPAT53_CONCAT_HELPER(a, b) a##b
#define COMPAT53_CONCAT(a, b) COMPAT53_CONCAT_HELPER(a, b)

#define luaL_buffinit COMPAT53_CONCAT(COMPAT53_PREFIX, _buffinit_53)
COMPAT53_API void luaL_buffinit(lua_State *L, luaL_Buffer_53 *B);
#define luaL_prepbuffsize COMPAT53_CONCAT(COMPAT53_PREFIX, _prepbufsize_53)
COMPAT53_API char *luaL_prepbuffsize(luaL_Buffer_53 *B, size_t s);
#define luaL_addlstring COMPAT53_CONCAT(COMPAT53_PREFIX, _addlstring_53)
COMPAT53_API void luaL_addlstring(luaL_Buffer_53 *B, const char *s, size_t l);
#define luaL_addvalue COMPAT53_CONCAT(COMPAT53_PREFIX, _addvalue_53)
COMPAT53_API void luaL_addvalue(luaL_Buffer_53 *B);
#define luaL_pushresult COMPAT53_CONCAT(COMPAT53_PREFIX, _pushresult_53)
COMPAT53_API void luaL_pushresult(luaL_Buffer_53 *B);
#undef luaL_buffinitsize
#define luaL_buffinitsize(L, B, s) \
	(luaL_buffinit(L, B), luaL_prepbuffsize(B, s))

#undef luaL_prepbuffer
#define luaL_prepbuffer(B) \
	luaL_prepbuffsize(B, LUAL_BUFFERSIZE)

#undef luaL_addchar
#define luaL_addchar(B, c)                                            \
	((void) ((B)->nelems < (B)->capacity || luaL_prepbuffsize(B, 1)), \
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
luaL_buffinit(lua_State *L, luaL_Buffer_53 *B)
{
	/* make it crash if used via pointer to a 5.1-style luaL_Buffer */
	B->b.p = NULL;
	B->b.L = NULL;
	B->b.lvl = 0;
	/* reuse the buffer from the 5.1-style luaL_Buffer though! */
	B->ptr = B->b.buffer;
	B->nelems = 0;
	B->capacity = LUAL_BUFFERSIZE;
	B->L2 = L;
}


COMPAT53_API char *
luaL_prepbuffsize(luaL_Buffer_53 *B, size_t s)
{
	if (B->capacity - B->nelems < s) { /* needs to grow */
		char *newptr = NULL;
		size_t newcap = B->capacity * 2;
		if (newcap - B->nelems < s)
			newcap = B->nelems + s;
		if (newcap < B->capacity) /* overflow */
			luaL_error(B->L2, "buffer too large");
		newptr = (char *) lua_newuserdata(B->L2, newcap);
		memcpy(newptr, B->ptr, B->nelems);
		if (B->ptr != B->b.buffer) {
			lua_replace(B->L2, -2); /* remove old buffer */
		}
		B->ptr = newptr;
		B->capacity = newcap;
	}
	return B->ptr + B->nelems;
}


COMPAT53_API void
luaL_addlstring(luaL_Buffer_53 *B, const char *s, size_t l)
{
	memcpy(luaL_prepbuffsize(B, l), s, l);
	luaL_addsize(B, l);
}


COMPAT53_API void
luaL_addvalue(luaL_Buffer_53 *B)
{
	size_t len = 0;
	const char *s = lua_tolstring(B->L2, -1, &len);
	if (!s)
		luaL_error(B->L2, "cannot convert value to string");
	if (B->ptr != B->b.buffer) {
		lua_insert(B->L2, -2); /* userdata buffer must be at stack top */
	}
	luaL_addlstring(B, s, len);
	lua_remove(B->L2, B->ptr != B->b.buffer ? -2 : -1);
}


COMPAT53_API void
luaL_pushresult(luaL_Buffer_53 *B)
{
	lua_pushlstring(B->L2, B->ptr, B->nelems);
	if (B->ptr != B->b.buffer) {
		lua_replace(B->L2, -2); /* remove userdata buffer */
	}
}

#endif

/*
** Read an integer numeral from string 'fmt' or return 'df' if
** there is no numeral
*/
static int
digit(int c)
{
	return '0' <= c && c <= '9';
}

static int
getnum(const char **fmt, int df)
{
	if (!digit(**fmt)) /* no number? */
		return df;     /* return default value */
	else {
		int a = 0;
		do {
			a = a * 10 + (*((*fmt)++) - '0');
		} while (digit(**fmt) && a <= ((int) MAXSIZE - 9) / 10);
		return a;
	}
}


/*
** Read an integer numeral and raises an error if it is larger
** than the maximum size for integers.
*/
static int
getnumlimit(Header *h, const char **fmt, int df)
{
	int sz = getnum(fmt, df);
	if (sz > MAXINTSIZE || sz <= 0)
		luaL_error(h->L, "integral size (%d) out of limits [1,%d]",
				   sz, MAXINTSIZE);
	return sz;
}


/*
** Initialize Header
*/
static void
initheader(lua_State *L, Header *h)
{
	h->L = L;
	h->islittle = nativeendian.little;
	h->maxalign = 1;
}


/*
** Read and classify next option. 'size' is filled with option's size.
*/
static KOption
getoption(Header *h, const char **fmt, int *size)
{
	int opt = *((*fmt)++);
	*size = 0; /* default */
	switch (opt) {
	case 'b':
		*size = sizeof(char);
		return Kint;
	case 'B':
		*size = sizeof(char);
		return Kuint;
	case 'h':
		*size = sizeof(short);
		return Kint;
	case 'H':
		*size = sizeof(short);
		return Kuint;
	case 'l':
		*size = sizeof(long);
		return Kint;
	case 'L':
		*size = sizeof(long);
		return Kuint;
	case 'j':
		*size = sizeof(lua_Integer);
		return Kint;
	case 'J':
		*size = sizeof(lua_Integer);
		return Kuint;
	case 'T':
		*size = sizeof(size_t);
		return Kuint;
	case 'f':
		*size = sizeof(float);
		return Kfloat;
	case 'd':
		*size = sizeof(double);
		return Kfloat;
	case 'n':
		*size = sizeof(lua_Number);
		return Kfloat;
	case 'i':
		*size = getnumlimit(h, fmt, sizeof(int));
		return Kint;
	case 'I':
		*size = getnumlimit(h, fmt, sizeof(int));
		return Kuint;
	case 's':
		*size = getnumlimit(h, fmt, sizeof(size_t));
		return Kstring;
	case 'c':
		*size = getnum(fmt, -1);
		if (*size == -1)
			luaL_error(h->L, "missing size for format option 'c'");
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
		h->maxalign = getnumlimit(h, fmt, MAXALIGN);
		break;
	default:
		luaL_error(h->L, "invalid format option '%c'", opt);
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
getdetails(Header *h, size_t totalsize,
		   const char **fmt, int *psize, int *ntoalign)
{
	KOption opt = getoption(h, fmt, psize);
	int align = *psize;      /* usually, alignment follows size */
	if (opt == Kpaddalign) { /* 'X' gets alignment from following option */
		if (**fmt == '\0' || getoption(h, fmt, &align) == Kchar || align == 0)
			luaL_argerror(h->L, 1, "invalid next option for option 'X'");
	}
	if (align <= 1 || opt == Kchar) /* need no alignment? */
		*ntoalign = 0;
	else {
		if (align > h->maxalign) /* enforce maximum alignment */
			align = h->maxalign;
		if ((align & (align - 1)) != 0) /* is 'align' not a power of 2? */
			luaL_argerror(h->L, 1, "format asks for alignment not power of 2");
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
packint(luaL_Buffer *b, lua_Unsigned n,
		int islittle, int size, int neg)
{
	char *buff = luaL_prepbuffsize(b, size);
	int i;
	buff[islittle ? 0 : size - 1] = (char) (n & MC); /* first byte */
	for (i = 1; i < size; i++) {
		n >>= NB;
		buff[islittle ? i : size - 1 - i] = (char) (n & MC);
	}
	if (neg && size > SZINT) {         /* negative number need sign extension? */
		for (i = SZINT; i < size; i++) /* correct extra bytes */
			buff[islittle ? i : size - 1 - i] = (char) MC;
	}
	luaL_addsize(b, size); /* add result to buffer */
}


/*
** Copy 'size' bytes from 'src' to 'dest', correcting endianness if
** given 'islittle' is different from native endianness.
*/
static void
copywithendian(volatile char *dest, volatile const char *src,
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
lua_util_pack(lua_State *L)
{
	luaL_Buffer b;
	Header h;
	const char *fmt = luaL_checkstring(L, 1); /* format string */
	int arg = 1;                              /* current argument to pack */
	size_t totalsize = 0;                     /* accumulate total size of result */
	initheader(L, &h);
	lua_pushnil(L); /* mark to separate arguments from string buffer */
	luaL_buffinit(L, &b);

	while (*fmt != '\0') {
		int size, ntoalign;
		KOption opt = getdetails(&h, totalsize, &fmt, &size, &ntoalign);
		totalsize += ntoalign + size;
		while (ntoalign-- > 0)
			luaL_addchar(&b, LUA_PACKPADBYTE); /* fill alignment */
		arg++;
		switch (opt) {
		case Kint: { /* signed integers */
			lua_Integer n = luaL_checkinteger(L, arg);
			if (size < SZINT) { /* need overflow check? */
				lua_Integer lim = (lua_Integer) 1 << ((size * NB) - 1);
				luaL_argcheck(L, -lim <= n && n < lim, arg, "integer overflow");
			}
			packint(&b, (lua_Unsigned) n, h.islittle, size, (n < 0));
			break;
		}
		case Kuint: { /* unsigned integers */
			lua_Integer n = luaL_checkinteger(L, arg);
			if (size < SZINT) /* need overflow check? */
				luaL_argcheck(L,
							  (lua_Unsigned) n < ((lua_Unsigned) 1 << (size * NB)),
							  arg,
							  "unsigned overflow");
			packint(&b, (lua_Unsigned) n, h.islittle, size, 0);
			break;
		}
		case Kfloat: { /* floating-point options */
			volatile Ftypes u;
			char *buff = luaL_prepbuffsize(&b, size);
			lua_Number n = luaL_checknumber(L, arg); /* get argument */
			if (size == sizeof(u.f))
				u.f = (float) n; /* copy it into 'u' */
			else if (size == sizeof(u.d))
				u.d = (double) n;
			else
				u.n = n;
			/* move 'u' to final result, correcting endianness if needed */
			copywithendian(buff, u.buff, size, h.islittle);
			luaL_addsize(&b, size);
			break;
		}
		case Kchar: { /* fixed-size string */
			size_t len;
			const char *s = luaL_checklstring(L, arg, &len);
			if ((size_t) size <=
				len) /* string larger than (or equal to) needed? */
				luaL_addlstring(&b,
								s,
								size);        /* truncate string to asked size */
			else {                            /* string smaller than needed */
				luaL_addlstring(&b, s, len);  /* add it all */
				while (len++ < (size_t) size) /* pad extra space */
					luaL_addchar(&b, LUA_PACKPADBYTE);
			}
			break;
		}
		case Kstring: { /* strings with length count */
			size_t len;
			const char *s = luaL_checklstring(L, arg, &len);
			luaL_argcheck(L, size >= (int) sizeof(size_t) || len < ((size_t) 1 << (size * NB)),
						  arg, "string length does not fit in given size");
			packint(&b,
					(lua_Unsigned) len,
					h.islittle,
					size,
					0); /* pack length */
			luaL_addlstring(&b, s, len);
			totalsize += len;
			break;
		}
		case Kzstr: { /* zero-terminated string */
			size_t len;
			const char *s = luaL_checklstring(L, arg, &len);
			luaL_argcheck(L, strlen(s) == len, arg, "string contains zeros");
			luaL_addlstring(&b, s, len);
			luaL_addchar(&b, '\0'); /* add zero at the end */
			totalsize += len + 1;
			break;
		}
		case Kpadding:
			luaL_addchar(&b, LUA_PACKPADBYTE); /* FALLTHROUGH */
		case Kpaddalign:
		case Knop:
			arg--; /* undo increment */
			break;
		}
	}
	luaL_pushresult(&b);
	return 1;
}


static int
lua_util_packsize(lua_State *L)
{
	Header h;
	const char *fmt = luaL_checkstring(L, 1); /* format string */
	size_t totalsize = 0;                     /* accumulate total size of result */
	initheader(L, &h);
	while (*fmt != '\0') {
		int size, ntoalign;
		KOption opt = getdetails(&h, totalsize, &fmt, &size, &ntoalign);
		size += ntoalign; /* total space used by option */
		luaL_argcheck(L, totalsize <= MAXSIZE - size, 1,
					  "format result too large");
		totalsize += size;
		switch (opt) {
		case Kstring: /* strings with length count */
		case Kzstr:   /* zero-terminated string */
			luaL_argerror(L, 1, "variable-length format");
			/* call never return, but to avoid warnings: */ /* FALLTHROUGH */
		default:
			break;
		}
	}
	lua_pushinteger(L, (lua_Integer) totalsize);
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
unpackint(lua_State *L, const char *str,
		  int islittle, int size, int issigned)
{
	lua_Unsigned res = 0;
	int i;
	int limit = (size <= SZINT) ? size : SZINT;
	for (i = limit - 1; i >= 0; i--) {
		res <<= NB;
		res |= (lua_Unsigned) (unsigned char) str[islittle ? i : size - 1 - i];
	}
	if (size < SZINT) { /* real size smaller than lua_Integer? */
		if (issigned) { /* needs sign extension? */
			lua_Unsigned mask = (lua_Unsigned) 1 << (size * NB - 1);
			res = ((res ^ mask) - mask); /* do sign extension */
		}
	}
	else if (size > SZINT) { /* must check unread bytes */
		int mask = (!issigned || (lua_Integer) res >= 0) ? 0 : MC;
		for (i = limit; i < size; i++) {
			if ((unsigned char) str[islittle ? i : size - 1 - i] != mask)
				luaL_error(L,
						   "%d-byte integer does not fit into Lua Integer",
						   size);
		}
	}
	return (lua_Integer) res;
}

static lua_Integer
posrelat(lua_Integer pos, size_t len)
{
	if (pos >= 0)
		return pos;
	else if (0u - (size_t) pos > len)
		return 0;
	else
		return (lua_Integer) len + pos + 1;
}

static int
lua_util_unpack(lua_State *L)
{
	Header h;
	const char *fmt = luaL_checkstring(L, 1);
	size_t ld;
	const char *data;
	int n = 0; /* number of results */

	if (lua_type(L, 2) == LUA_TUSERDATA) {
		struct rspamd_lua_text *t = lua_check_text(L, 2);

		if (!t) {
			return luaL_error(L, "invalid arguments");
		}

		data = t->start;
		ld = t->len;
	}
	else {
		data = luaL_checklstring(L, 2, &ld);
	}

	size_t pos = (size_t) posrelat(luaL_optinteger(L, 3, 1), ld) - 1;
	luaL_argcheck(L, pos <= ld, 3, "initial position out of string");

	initheader(L, &h);

	while (*fmt != '\0') {
		int size, ntoalign;
		KOption opt = getdetails(&h, pos, &fmt, &size, &ntoalign);
		if ((size_t) ntoalign + size > ~pos || pos + ntoalign + size > ld)
			luaL_argerror(L, 2, "data string too short");
		pos += ntoalign; /* skip alignment */
		/* stack space for item + next position */
		luaL_checkstack(L, 2, "too many results");
		n++;
		switch (opt) {
		case Kint:
		case Kuint: {
			lua_Integer res = unpackint(L, data + pos, h.islittle, size,
										(opt == Kint));
			lua_pushinteger(L, res);
			break;
		}
		case Kfloat: {
			volatile Ftypes u;
			lua_Number num;
			copywithendian(u.buff, data + pos, size, h.islittle);
			if (size == sizeof(u.f))
				num = (lua_Number) u.f;
			else if (size == sizeof(u.d))
				num = (lua_Number) u.d;
			else
				num = u.n;
			lua_pushnumber(L, num);
			break;
		}
		case Kchar: {
			lua_pushlstring(L, data + pos, size);
			break;
		}
		case Kstring: {
			size_t len = (size_t) unpackint(L,
											data + pos,
											h.islittle,
											size,
											0);
			luaL_argcheck(L,
						  pos + len + size <= ld,
						  2,
						  "data string too short");
			lua_pushlstring(L, data + pos + size, len);
			pos += len; /* skip string */
			break;
		}
		case Kzstr: {
			size_t len = (int) strlen(data + pos);
			lua_pushlstring(L, data + pos, len);
			pos += len + 1; /* skip string plus final '\0' */
			break;
		}
		case Kpaddalign:
		case Kpadding:
		case Knop:
			n--; /* undo increment */
			break;
		}
		pos += size;
	}
	lua_pushinteger(L, pos + 1); /* next position */
	return n + 1;
}

static int
lua_util_btc_polymod(lua_State *L)
{
	uint64_t c = 1;

	if (lua_type(L, 1) != LUA_TTABLE) {
		return luaL_error(L, "invalid arguments");
	}

	for (lua_pushnil(L); lua_next(L, 1); lua_pop(L, 1)) {
		uint8_t c0 = c >> 35;
		uint64_t d = lua_tointeger(L, -1);

		c = ((c & 0x07ffffffff) << 5) ^ d;

		if (c0 & 0x01) c ^= 0x98f2bc8e61;
		if (c0 & 0x02) c ^= 0x79b76d99e2;
		if (c0 & 0x04) c ^= 0xf33e5fb3c4;
		if (c0 & 0x08) c ^= 0xae2eabe2a8;
		if (c0 & 0x10) c ^= 0x1e4f43e470;
	}

	if ((c ^ 1) == 0) {
		lua_pushboolean(L, true);
	}
	else {
		lua_pushboolean(L, false);
	}

	return 1;
}

static int
lua_util_parse_smtp_date(lua_State *L)
{
	return lua_parsers_parse_smtp_date(L);
}


static int
lua_load_util(lua_State *L)
{
	lua_newtable(L);
	luaL_register(L, NULL, utillib_f);

	return 1;
}

static int
lua_load_int64(lua_State *L)
{
	lua_newtable(L);
	luaL_register(L, NULL, int64lib_f);

	return 1;
}


void luaopen_util(lua_State *L)
{
	rspamd_lua_new_class(L, rspamd_ev_base_classname, ev_baselib_m);
	lua_pop(L, 1);
	rspamd_lua_new_class(L, rspamd_int64_classname, int64lib_m);
	lua_pop(L, 1);
	rspamd_lua_add_preload(L, "rspamd_util", lua_load_util);
	rspamd_lua_add_preload(L, "rspamd_int64", lua_load_int64);
}

static int
lua_int64_tostring(lua_State *L)
{
	int64_t n = lua_check_int64(L, 1);
	char buf[32];
	bool is_signed = false;

	if (lua_isboolean(L, 2)) {
		is_signed = lua_toboolean(L, 2);
	}

	if (is_signed) {
		rspamd_snprintf(buf, sizeof(buf), "%L", n);
	}
	else {
		rspamd_snprintf(buf, sizeof(buf), "%uL", n);
	}
	lua_pushstring(L, buf);

	return 1;
}

static int
lua_int64_fromstring(lua_State *L)
{
	struct rspamd_lua_text *t = lua_check_text_or_string(L, 1);

	if (t && t->len > 0) {
		uint64_t u64;
		const char *p = t->start;
		gsize len = t->len;
		bool neg = false;

		/*
		 * We use complicated negation to allow both signed and unsinged values to
		 * fit into result.
		 * So we read int64 as unsigned and copy it to signed number.
		 * If we wanted u64 this allows to have the same memory representation of
		 * signed and unsigned.
		 * If we wanted signed i64 we still can use -1000500 and it will be parsed
		 * properly
		 */
		if (*p == '-') {
			neg = true;
			p++;
			len--;
		}
		if (!rspamd_strtou64(p, len, &u64)) {
			lua_pushnil(L);
			lua_pushstring(L, "invalid number");
			return 2;
		}

		int64_t *i64_p = lua_newuserdata(L, sizeof(int64_t));
		rspamd_lua_setclass(L, rspamd_int64_classname, -1);
		memcpy(i64_p, &u64, sizeof(u64));

		if (neg) {
			*i64_p = -(*i64_p);
		}
	}
	else {
	}

	return 1;
}

static int
lua_int64_tonumber(lua_State *L)
{
	int64_t n = lua_check_int64(L, 1);
	double d;

	d = n;
	lua_pushinteger(L, d);

	return 1;
}

static int
lua_int64_hex(lua_State *L)
{
	int64_t n = lua_check_int64(L, 1);
	char buf[32];

	rspamd_snprintf(buf, sizeof(buf), "%XL", n);
	lua_pushstring(L, buf);

	return 1;
}

static int
lua_ev_base_loop(lua_State *L)
{
	int flags = 0;
	struct ev_loop *ev_base;

	ev_base = lua_check_ev_base(L, 1);
	if (lua_isnumber(L, 2)) {
		flags = lua_tointeger(L, 2);
	}

	int ret = ev_run(ev_base, flags);
	lua_pushinteger(L, ret);

	return 1;
}
