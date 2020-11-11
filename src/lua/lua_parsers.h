/*-
 * Copyright 2020 Vsevolod Stakhov
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

#ifndef RSPAMD_LUA_PARSERS_H
#define RSPAMD_LUA_PARSERS_H

#include "lua_common.h"

/***
 * @function parsers.tokenize_text(input[, exceptions])
 * Create tokens from a text using optional exceptions list
 * @param {text/string} input input data
 * @param {table} exceptions, a table of pairs containing <start_pos,length> of exceptions in the input
 * @return {table/strings} list of strings representing words in the text
 */
LUA_PUBLIC_FUNCTION_DEF (parsers, tokenize_text);

/***
 * @function parsers.parse_html(input)
 * Parses HTML and returns the according text
 * @param {string|text} in input HTML
 * @return {rspamd_text} processed text with no HTML tags
 */
LUA_PUBLIC_FUNCTION_DEF (parsers, parse_html);

/***
 * @function parsers.parse_mail_address(str, [pool])
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
LUA_PUBLIC_FUNCTION_DEF (parsers, parse_mail_address);

/***
 *  @function parsers.parse_content_type(ct_string, mempool)
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
LUA_PUBLIC_FUNCTION_DEF (parsers, parse_content_type);

/***
 * @function parsers.parse_smtp_date(str[, local_tz])
 * Converts an SMTP date string to unix timestamp
 * @param {string} str input string
 * @param {boolean} local_tz convert to local tz if `true`
 * @return {number} time as unix timestamp (converted to float)
 */
LUA_PUBLIC_FUNCTION_DEF (parsers, parse_smtp_date);


#endif //RSPAMD_LUA_PARSERS_H
