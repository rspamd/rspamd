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

#include "message.h"
#include "images.h"
#include "archives.h"
#include "utlist.h"
#include "unix-std.h"
#include "libmime/smtp_parsers.h"
#include "libserver/mempool_vars_internal.h"
#include "libserver/dkim.h"
#include "libserver/task.h"
#include "libserver/cfg_file_private.h"
#include "libmime/scan_result_private.h"
#include "libstat/stat_api.h"
#include "libserver/maps/map_helpers.h"

#include <math.h>
#include "libmime/received.h"

/***
 * @module rspamd_task
 * This module provides routines for tasks manipulation in rspamd. Tasks usually
 * represent messages being scanned, and this API provides access to such elements
 * as headers, symbols, metrics and so on and so forth. Normally, task objects
 * are passed to the lua callbacks allowing to check specific properties of messages
 * and add the corresponding symbols to the scan's results.
@example
rspamd_config.DATE_IN_PAST = function(task)
	local dm = task:get_date{format = 'message', gmt = true}
	local dt = task:get_date{format = 'connect', gmt = true}
	-- A day
	if dt - dm > 86400 then
		return true
	end

	return false
end
 */

/* Task methods */

/***
 * @function rspamd_task.create([cfg])
 * Create a new empty task
 * @return {rspamd_task} new task
 */
LUA_FUNCTION_DEF (task, create);
/***
 * @function rspamd_task.load_from_file(filename[, cfg])
 * Loads a message from specific file
 * @return {boolean,rspamd_task|error} status + new task or error message
 */
LUA_FUNCTION_DEF (task, load_from_file);
/***
 * @function rspamd_task.load_from_string(message[, cfg])
 * Loads a message from specific file
 * @return {boolean,rspamd_task|error} status + new task or error message
 */
LUA_FUNCTION_DEF (task, load_from_string);
/***
 * @method task:get_message()
 * Returns task raw message content as opaque text
 * @return {rspamd_text} task raw content
 */
LUA_FUNCTION_DEF (task, get_message);
/***
 * @method task:set_message(msg)
 * Updates task message with another message; It also parses a message to
 * fill the internal structures.
 * Input might be a string, a lua_text or a table of the former stuff.
 * @param {string/text/table} msg new message to set
 * @return {boolean,number} if a message has been set + its raw size
 */
LUA_FUNCTION_DEF (task, set_message);
/***
 * @method task:process_message()
 * Parses message
 */
LUA_FUNCTION_DEF (task, process_message);
/***
 * @method task:get_cfg()
 * Get configuration object for a task.
 * @return {rspamd_config} (config.md)[configuration object] for the task
 */
LUA_FUNCTION_DEF (task, get_cfg);
LUA_FUNCTION_DEF (task, set_cfg);
LUA_FUNCTION_DEF (task, destroy);
/***
 * @method task:get_mempool()
 * Returns memory pool valid for a lifetime of task. It is used internally by
 * many rspamd routines.
 * @return {rspamd_mempool} memory pool object
 */
LUA_FUNCTION_DEF (task, get_mempool);
/***
 * @method task:get_session()
 * Returns asynchronous session object that is used by many rspamd asynchronous
 * utilities internally.
 * @return {rspamd_session} session object
 */
LUA_FUNCTION_DEF (task, get_session);
/***
 * @method task:set_session(session)
 * Sets new async session for a task
 */
LUA_FUNCTION_DEF (task, set_session);
/***
 * @method task:get_ev_base()
 * Return asynchronous event base for using in callbacks and resolver.
 * @return {rspamd_ev_base} event base
 */
LUA_FUNCTION_DEF (task, get_ev_base);
/***
 * @method task:get_worker()
 * Returns a worker object associated with the task
 * @return {rspamd_worker} worker object
 */
LUA_FUNCTION_DEF (task, get_worker);
/***
 * @method task:insert_result([enforce_symbol,]symbol, weight[, option1, ...])
 * Insert specific symbol to the tasks scanning results assigning the initial
 * weight to it.
 * @param {boolean} enforce_symbol if represented and true, then insert symbol even if it is not registered in the metric
 * @param {string} symbol symbol to insert
 * @param {number} weight initial weight (this weight is multiplied by the metric weight)
 * @param {string} options list of optional options attached to a symbol inserted
@example
local function cb(task)
	if task:get_header('Some header') then
		task:insert_result('SOME_HEADER', 1.0, 'Got some header')
	end
end
 */
LUA_FUNCTION_DEF (task, insert_result);
/***
 * @method task:insert_result_named(shadow_result, [enforce_symbol,]symbol, weight[, option1, ...])
 * Insert specific symbol to the tasks scanning results assigning the initial
 * weight to it.
 * @param {string} shadow_result name of shadow result
 * @param {boolean} enforce_symbol if represented and true, then insert symbol even if it is not registered in the metric
 * @param {string} symbol symbol to insert
 * @param {number} weight initial weight (this weight is multiplied by the metric weight)
 * @param {string} options list of optional options attached to a symbol inserted
 */
LUA_FUNCTION_DEF (task, insert_result_named);

/***
 * @method task:adjust_result(symbol, score[, option1, ...])
 * Alters the existing symbol's score to a new score. It is not affected by
 * metric score or grow factor. You can also add new options
 * using this method. Symbol must be already inserted into metric or an error
 * will be emitted.
 * @param {string} symbol symbol to adjust
 * @param {number} score this value is NOT multiplied by the metric score
 * @param {string/table} options list of optional options attached to a symbol adjusted
 */
LUA_FUNCTION_DEF (task, adjust_result);

/***
 * @method task:remove_result(symbol[, shadow_result])
 * Removes the symbol from a named or unamed/default result
 * @param {string} symbol symbol to remove
 * @param {string} shadow_result name of shadow result
 * @return {boolean} true if a symbol has been removed
 */
LUA_FUNCTION_DEF (task, remove_result);
/***
 * @method task:set_pre_result(action, [message, [module], [score], [priority], [flags])
 * Sets pre-result for a task. It is used in pre-filters to specify early result
 * of the task scanned. If a pre-filter sets some result, then further processing
 * may be skipped. For selecting action it is possible to use global table
 * `rspamd_actions` or a string value:
 *
 * - `reject`: reject message permanently
 * - `add header`: add spam header
 * - `rewrite subject`: rewrite subject to spam subject
 * - `greylist`: greylist message
 * - `accept` or `no action`: whitelist message
 *
 * This function also accepts a table from Rspamd 2.6 with the following keys:
 * - action: string required
 * - message: string
 * - module: string
 * - score: number
 * - priority: integer
 * - flags: flags string
 * - result: named result if needed
 *
 * @param {rspamd_action or string} action a numeric or string action value
 * @param {string} message action message
 * @param {string} module optional module name
 * @param {number/nil} score optional explicit score
 * @param {number/nil} priority optional explicit priority
 * @param {string/nil} flags optional flags (e.g. 'least' for least action)
@example
local function cb(task)
	local gr = task:get_header('Greylist')
	if gr and gr == 'greylist' then
		task:set_pre_result('soft reject', 'Greylisting required')
	end
end
 */
LUA_FUNCTION_DEF (task, set_pre_result);

/***
 * @method task:has_pre_result()
 * Returns true if task has some pre-result being set.
 * If result has been set this function also returns pre result action,
 * message and module as strings in this order.
 *
 * @return {boolean,[string,string,string]} true if task has some pre-result being set
 */
LUA_FUNCTION_DEF (task, has_pre_result);
/***
 * @method task:append_message(message, [category])
 * Adds a message to scanning output.
 * @param {string} message
 * @param {category} message category
@example
local function cb(task)
	task:append_message('Example message')
end
 */
LUA_FUNCTION_DEF (task, append_message);
/***
 * @method task:get_urls([need_emails|list_protos][, need_images])
 * Get all URLs found in a message. Telephone urls and emails are not included unless explicitly asked in `list_protos`
 * @param {boolean} need_emails if `true` then reutrn also email urls, this can be a comma separated string of protocols desired or a table (e.g. `mailto` or `telephone`)
 * @param {boolean} need_images return urls from images (<img src=...>) as well
 * @return {table rspamd_url} list of all urls found
@example
local function phishing_cb(task)
	local urls = task:get_urls({'https', 'http'});

	if urls then
		for _,url in ipairs(urls) do
			if url:is_phished() then
				return true
			end
		end
	end
	return false
end
 */
LUA_FUNCTION_DEF (task, get_urls);
/***
 * @method task:get_urls_filtered([{flags_include}, [{flags_exclude}]], [{protocols_mask}])
 * Get urls managed by either exclude or include flags list
 * - If flags include are nil then all but excluded urls are returned
 * - If flags exclude are nil then only included explicitly urls are returned
 * - If both parameters are nil then all urls are included
 * @param {table} flags_include included flags
 * @param {table} flags_exclude excluded flags
 * @param {table} protocols_mask incude only specific protocols
 * @return {table rspamd_url} list of urls matching conditions
 */
LUA_FUNCTION_DEF (task, get_urls_filtered);
/***
 * @method task:has_urls([need_emails])
 * Returns 'true' if a task has urls listed
 * @param {boolean} need_emails if `true` then reutrn also email urls
 * @return {boolean} true if a task has urls (urls or emails if `need_emails` is true)
 */
LUA_FUNCTION_DEF (task, has_urls);
/***
 * @method task:inject_url(url)
 * Inserts an url into a task (useful for redirected urls)
 * @param {lua_url} url url to inject
 */
LUA_FUNCTION_DEF (task, inject_url);
/***
 * @method task:get_content()
 * Get raw content for the specified task
 * @return {text} the data contained in the task
 */
LUA_FUNCTION_DEF (task, get_content);

/***
 * @method task:get_filename()
 * Returns filename for a specific task
 * @return {string|nil} filename or nil if unknown
 */
LUA_FUNCTION_DEF (task, get_filename);

/***
 * @method task:get_rawbody()
 * Get raw body for the specified task
 * @return {text} the data contained in the task
 */
LUA_FUNCTION_DEF (task, get_rawbody);

/***
 * @method task:get_emails()
 * Get all email addresses found in a message.
 * @return {table rspamd_url} list of all email addresses found
 */
LUA_FUNCTION_DEF (task, get_emails);
/***
 * @method task:get_text_parts()
 * Get all text (and HTML) parts found in a message
 * @return {table rspamd_text_part} list of text parts
 */
LUA_FUNCTION_DEF (task, get_text_parts);
/***
 * @method task:get_parts()
 * Get all mime parts found in a message
 * @return {table rspamd_mime_part} list of mime parts
 */
LUA_FUNCTION_DEF (task, get_parts);
/***
 * @method task:get_meta_words([how='stem'])
 * Get meta words from task (subject and displayed names)
 * - `stem`: stemmed words (default)
 * - `norm`: normalised words (utf normalised + lowercased)
 * - `raw`: raw words in utf (if possible)
 * - `full`: list of tables, each table has the following fields:
 *   - [1] - stemmed word
 *   - [2] - normalised word
 *   - [3] - raw word
 *   - [4] - flags (table of strings)
 */
LUA_FUNCTION_DEF (task, get_meta_words);
/***
 * @method task:get_request_header(name)
 * Get value of a HTTP request header.
 * @param {string} name name of header to get
 * @return {rspamd_text} value of an HTTP header
 */
LUA_FUNCTION_DEF (task, get_request_header);
/***
 * @method task:set_request_header(name, value)
 * Set value of a HTTP request header. If value is omitted, then a header is removed
 * @param {string} name name of header to get
 * @param {rspamd_text/string} value new header's value
 */
LUA_FUNCTION_DEF (task, set_request_header);
/***
 * @method task:get_subject()
 * Returns task subject (either from the protocol override or from a header)
 * @return {string} value of a subject (decoded)
 */
LUA_FUNCTION_DEF (task, get_subject);
/***
 * @method task:get_header(name[, case_sensitive])
 * Get decoded value of a header specified with optional case_sensitive flag.
 * By default headers are searched in caseless matter.
 * @param {string} name name of header to get
 * @param {boolean} case_sensitive case sensitiveness flag to search for a header
 * @return {string} decoded value of a header
 */
LUA_FUNCTION_DEF (task, get_header);
/***
 * @method task:has_header(name[, case_sensitive])
 * Get decoded value of a header specified with optional case_sensitive flag.
 * By default headers are searched in the case insensitive matter.
 * @param {string} name name of header to get
 * @param {boolean} case_sensitive case sensitiveness flag to search for a header
 * @return {boolean} true if header exists
 */
LUA_FUNCTION_DEF (task, has_header);
/***
 * @method task:get_header_raw(name[, case_sensitive])
 * Get raw value of a header specified with optional case_sensitive flag.
 * By default headers are searched in caseless matter.
 * @param {string} name name of header to get
 * @param {boolean} case_sensitive case sensitiveness flag to search for a header
 * @return {string} raw value of a header
 */
LUA_FUNCTION_DEF (task, get_header_raw);
/***
 * @method task:get_header_full(name[, case_sensitive[, need_modified]])
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
 * @param {boolean} need_modified return a modified value of a header if presented
 * @return {list of tables} all values of a header as specified above
@example
function check_header_delimiter_tab(task, header_name)
	for _,rh in ipairs(task:get_header_full(header_name)) do
		if rh['tab_separated'] then return true end
	end
	return false
end
 */
LUA_FUNCTION_DEF (task, get_header_full);
/***
 * @method task:get_header_count(name[, case_sensitive])
 * Lightweight version if you need just a header's count
 *  * By default headers are searched in caseless matter.
 * @param {string} name name of header to get
 * @param {boolean} case_sensitive case sensitiveness flag to search for a header
 * @return {number} number of header's occurrencies or 0 if not found
 */
LUA_FUNCTION_DEF (task, get_header_count);
/***
 * @method task:get_raw_headers()
 * Get all undecoded headers of a message as a string
 * @return {rspamd_text} all raw headers for a message as opaque text
 */
LUA_FUNCTION_DEF (task, get_raw_headers);

/***
 * @method task:get_headers([need_modified=false])
 * Get all headers of a message in the same format as get_header_full
 * @return {table of headers data} all headers for a message
 */
LUA_FUNCTION_DEF (task, get_headers);

/***
 * @method task:modify_header(name, mods)
 * Modify an existing or non-existing header with the name `name`
 * Mods is a table with the following structure:
 * {
 *   "add" = { {order, value}, {order, value} },
 *   "remove" = {order, order, order}
 * }
 * Modifications are evaluated in order: remove, add, so headers are first
 * removed (if any) and then added
 * Order in remove starts from 1, where 0 means 'remove all', and negative value means
 * remove from the end
 * Order in addition means addition from the top: 0 means the most top header, 1 one after, etc
 * negative order means addtion to the end, e.g. -1 is appending header.
 * @return {bool} true if header could be modified (always true unless we don't have an unparsed message)
 */
LUA_FUNCTION_DEF (task, modify_header);

/***
 * @method task:get_received_headers()
 * Returns a list of tables of parsed received headers. A tables returned have
 * the following structure:
 *
 * - `from_hostname` - string that represents hostname provided by a peer
 * - `from_ip` - string representation of sending IP address
 * - `real_hostname` - hostname as resolved by MTA
 * - `real_ip` - rspamd_ip object representing sending IP address
 * - `by_hostname` - MTA hostname
 * - `proto` - protocol, e.g. ESMTP or ESMTPS
 * - `timestamp` - received timestamp
 * - `for` - for value (unparsed mailbox)
 *
 * Please note that in some situations rspamd cannot parse all the fields of received headers.
 * In that case you should check all strings for validity.
 * @return {table of tables} list of received headers described above
 */
LUA_FUNCTION_DEF (task, get_received_headers);
/***
 * @method task:get_queue_id()
 * Returns queue ID of the message being processed.
 */
LUA_FUNCTION_DEF (task, get_queue_id);
/***
 * @method task:get_uid()
 * Returns ID of the task being processed.
 */
LUA_FUNCTION_DEF (task, get_uid);
/***
 * @method task:get_resolver()
 * Returns ready to use rspamd_resolver object suitable for making asynchronous DNS requests.
 * @return {rspamd_resolver} resolver object associated with the task's session
 * @example
local logger = require "rspamd_logger"

local function task_cb(task)
	local function dns_cb(resolver, to_resolve, results, err)
		-- task object is available due to closure
		task:inc_dns_req()
		if results then
			logger.info(string.format('<%s> [%s] resolved for symbol: %s',
				task:get_message_id(), to_resolve, 'EXAMPLE_SYMBOL'))
			task:insert_result('EXAMPLE_SYMBOL', 1)
		end
	end
	local r = task:get_resolver()
	r:resolve_a(task:get_session(), task:get_mempool(), 'example.com', dns_cb)
end
 */
LUA_FUNCTION_DEF (task, get_resolver);
/***
 * @method task:set_resolver(resolver)
 * Sets rspamd_resolver for a specified task.
 */
LUA_FUNCTION_DEF (task, set_resolver);
/***
* @method task:inc_dns_req()
* Increment number of DNS requests for the task. Is used just for logging purposes.
*/
LUA_FUNCTION_DEF (task, inc_dns_req);
/***
 * @method task:get_dns_req()
 * Get number of dns requests being sent in the task
 * @return {number} number of DNS requests
 */
LUA_FUNCTION_DEF (task, get_dns_req);

/***
 * @method task:has_recipients([type])
 * Return true if there are SMTP or MIME recipients for a task.
 * @param {integer|string} type if specified has the following meaning: `0` or `any` means try SMTP recipients and fallback to MIME if failed, `1` or `smtp` means checking merely SMTP recipients and `2` or `mime` means MIME recipients only
 * @return {bool} `true` if there are recipients of the following type
 */
LUA_FUNCTION_DEF (task, has_recipients);

/***
 * @method task:get_recipients([type])
 * Return SMTP or MIME recipients for a task. This function returns list of internet addresses each one is a table with the following structure:
 *
 * - `name` - name of internet address in UTF8, e.g. for `Vsevolod Stakhov <blah@foo.com>` it returns `Vsevolod Stakhov`
 * - `addr` - address part of the address
 * - `user` - user part (if present) of the address, e.g. `blah`
 * - `domain` - domain part (if present), e.g. `foo.com`
 * @param {integer|string} type if specified has the following meaning: `0` or `any` means try SMTP recipients and fallback to MIME if failed, `1` or `smtp` means checking merely SMTP recipients and `2` or `mime` means MIME recipients only
 * @return {list of addresses} list of recipients or `nil`
 */
LUA_FUNCTION_DEF (task, get_recipients);

/***
 * @method task:get_principal_recipient()
 * Returns a single string with so called `principal recipient` for a message. The order
 * of check is the following:
 *
 * - deliver-to request header
 * - the first recipient (envelope)
 * - the first recipient (mime)
 * @return {string} principal recipient
 */
LUA_FUNCTION_DEF (task, get_principal_recipient);
/***
 * @method task:get_reply_sender()
 * Returns a single string with address that should be used to reply on a message
 *
 * - reply-to header
 * - from header
 * - smtp from as a last resort
 * @return {address} email address
 */
LUA_FUNCTION_DEF (task, get_reply_sender);

/***
 * @method task:set_recipients([type], {rcpt1, rcpt2...}, [how='add'])
 * Sets recipients for a task. This function accepts table that will be converted to the address.
 * If some fields are missing they are subsequently reconstructed by this function. E.g. if you
 * specify 'user' and 'domain', then address and raw string will be reconstructed
 *
 * - `name` - name of internet address in UTF8, e.g. for `Vsevolod Stakhov <blah@foo.com>` it returns `Vsevolod Stakhov`
 * - `addr` - address part of the address
 * - `user` - user part (if present) of the address, e.g. `blah`
 * - `domain` - domain part (if present), e.g. `foo.com`
 * @param {integer|string} type if specified has the following meaning: `0` or `any` means try SMTP recipients and fallback to MIME if failed, `1` or `smtp` means checking merely SMTP recipients and `2` or `mime` means MIME recipients only
 * @param {list of tables} recipients recipients to set
 * @param {string} how define how to set recipients: `rewrite` - rewrite existing recipients, `alias` - treat existing recipients as aliased recipients, `add` - add new recipients
 * @return {boolean} result of the operation
 */
LUA_FUNCTION_DEF (task, set_recipients);

/***
 * @method task:has_from([type])
 * Return true if there is SMTP or MIME sender for a task.
 * @param {integer|string} type if specified has the following meaning: `0` or `any` means try SMTP recipients and fallback to MIME if failed, `1` or `smtp` means checking merely SMTP recipients and `2` or `mime` means MIME recipients only
 * @return {bool} `true` if there is sender of the following type
 */
LUA_FUNCTION_DEF (task, has_from);

/***
 * @method task:get_from([type])
 * Return SMTP or MIME sender for a task. This function returns an internet address which one is a table with the following structure:
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
 * @param {integer|string} type if specified has the following meaning: `0` or `any` means try SMTP sender and fallback to MIME if failed, `1` or `smtp` means checking merely SMTP sender and `2` or `mime` means MIME `From:` only
 * @return {address} sender or `nil`
 */
LUA_FUNCTION_DEF (task, get_from);

/***
 * @method task:set_from(type, addr)
 * Sets sender for a task. This function accepts table that will be converted to the address.
 * If some fields are missing they are subsequently reconstructed by this function. E.g. if you
 * specify 'user' and 'domain', then address and raw string will be reconstructed
 *
 * - `name` - name of internet address in UTF8, e.g. for `Vsevolod Stakhov <blah@foo.com>` it returns `Vsevolod Stakhov`
 * - `addr` - address part of the address
 * - `user` - user part (if present) of the address, e.g. `blah`
 * - `domain` - domain part (if present), e.g. `foo.com`
 * @param {integer|string} type if specified has the following meaning: `0` or `any` means try SMTP sender and fallback to MIME if failed, `1` or `smtp` means checking merely SMTP sender and `2` or `mime` means MIME `From:` only
 * @param {table
 * @return {boolean} success or not
 */
LUA_FUNCTION_DEF (task, set_from);
/***
 * @method task:get_user()
 * Returns authenticated user name for this task if specified by an MTA.
 * @return {string} username or nil
 */
LUA_FUNCTION_DEF (task, get_user);
/***
 * @method task:set_user([username])
 * Sets or resets (if username is not specified) authenticated user name for this task.
 * @return {string} the previously set username or nil
 */
LUA_FUNCTION_DEF (task, set_user);
/***
 * @method task:get_from_ip()
 * Returns [ip_addr](ip.md) object of a sender that is provided by MTA
 * @return {rspamd_ip} ip address object
 */
LUA_FUNCTION_DEF (task, get_from_ip);
/***
 * @method task:set_from_ip(str)
 * Set tasks's IP address based on the passed string
 * @param {string} str string representation of ip
 */
LUA_FUNCTION_DEF (task, set_from_ip);
LUA_FUNCTION_DEF (task, get_from_ip_num);
/***
 * @method task:get_client_ip()
 * Returns [ip_addr](ip.md) object of a client connected to rspamd (normally, it is an IP address of MTA)
 * @return {rspamd_ip} ip address object
 */
LUA_FUNCTION_DEF (task, get_client_ip);
/***
 * @method task:get_helo()
 * Returns the value of SMTP helo provided by MTA.
 * @return {string} HELO value
 */
LUA_FUNCTION_DEF (task, get_helo);
LUA_FUNCTION_DEF (task, set_helo);
/***
 * @method task:get_hostname()
 * Returns the value of sender's hostname provided by MTA
 * @return {string} hostname value
 */
LUA_FUNCTION_DEF (task, get_hostname);
LUA_FUNCTION_DEF (task, set_hostname);
/***
 * @method task:get_images()
 * Returns list of all images found in a task as a table of `rspamd_image`.
 * Each image has the following methods:
 *
 * * `get_width` - return width of an image in pixels
 * * `get_height` - return height of an image in pixels
 * * `get_type` - return string representation of image's type (e.g. 'jpeg')
 * * `get_filename` - return string with image's file name
 * * `get_size` - return size in bytes
 * @return {list of rspamd_image} images found in a message
 */
LUA_FUNCTION_DEF (task, get_images);
/***
 * @method task:get_archives()
 * Returns list of all archives found in a task as a table of `rspamd_archive`.
 * Each archive has the following methods available:
 *
 * * `get_files` - return list of strings with filenames inside archive
 * * `get_files_full` - return list of tables with all information about files
 * * `is_encrypted` - return true if an archive is encrypted
 * * `get_type` - return string representation of image's type (e.g. 'zip')
 * * `get_filename` - return string with archive's file name
 * * `get_size` - return size in bytes
 * @return {list of rspamd_archive} archives found in a message
 */
LUA_FUNCTION_DEF (task, get_archives);
/***
 * @method task:get_dkim_results()
 * Returns list of all dkim check results as table of maps. Callee must ensure that
 * dkim checks have been completed by adding dependency on `DKIM_TRACE` symbol.
 * Fields in map:
 *
 * * `result` - string result of check:
 *    - `reject`
 *    - `allow`
 *    - `tempfail`
 *    - `permfail`
 *    - `not found`
 *    - `bad record`
 * * `domain` - dkim domain
 * * `selector` - dkim selector
 * * `bhash` - short version of b tag (8 base64 symbols)
 * * `fail_reason` - reason of failure (if applicable)
 * @return {list of maps} dkim check results
 */
LUA_FUNCTION_DEF (task, get_dkim_results);
/***
 * @method task:get_symbol(name, [shadow_result_name])
 * Searches for a symbol `name` in all metrics results and returns a list of tables
 * one per metric that describes the symbol inserted. Please note that this function
 * is intended to return values for **inserted** symbols, so if this symbol was not
 * inserted it won't be in the function's output. This method is useful for post-filters mainly.
 * The symbols are returned as the list of the following tables:
 *
 * - `metric` - name of metric
 * - `score` - score of a symbol in that metric
 * - `options` - a table of strings representing options of a symbol
 * - `group` - a group of symbol (or 'ungrouped')
 * @param {string} name symbol's name
 * @return {list of tables} list of tables or nil if symbol was not found
 */
LUA_FUNCTION_DEF (task, get_symbol);
/***
 * @method task:get_symbols_all()
 * Returns array of symbols matched in default metric with all metadata
 * @return {table} table of tables formatted as in `task:get_symbol()` except that `metric` is absent and `name` is added
 */
LUA_FUNCTION_DEF (task, get_symbols_all);
/***
 * @method task:get_symbols([shadow_result_name])
 * Returns array of all symbols matched for this task
 * @return {table, table} table of strings with symbols names + table of theirs scores
 */
LUA_FUNCTION_DEF (task, get_symbols);

/***
 * @method task:get_groups([need_private])
 * Returns a map [group -> group_score] for matched group. If `need_private` is
 * unspecified, then the global option `public_groups_only` is used for default.
 * @return {table, number} a map [group -> group_score]
 */
LUA_FUNCTION_DEF (task, get_groups);

/***
 * @method task:get_symbols_numeric()
 * Returns array of all symbols matched for this task
 * @return {table|number, table|number} table of numbers with symbols ids + table of theirs scores
 */
LUA_FUNCTION_DEF (task, get_symbols_numeric);

/***
 * @method task:get_symbols_tokens()
 * Returns array of all symbols as statistical tokens
 * @return {table|number} table of numbers
 */
LUA_FUNCTION_DEF (task, get_symbols_tokens);

/***
 * @method task:process_ann_tokens(symbols, ann_tokens, offset, [min])
 * Processes ann tokens
 * @param {table|string} symbols list of symbols in this profile
 * @param {table|number} ann_tokens list of tokens (including metatokens)
 * @param {integer} offset offset for symbols token (#metatokens)
 * @param {number} min minimum value for symbols found (e.g. for 0 score symbols)
 * @return nothing
 */
LUA_FUNCTION_DEF (task, process_ann_tokens);

/***
 * @method task:has_symbol(name, [shadow_result_name])
 * Fast path to check if a specified symbol is in the task's results
 * @param {string} name symbol's name
 * @return {boolean} `true` if symbol has been found
 */
LUA_FUNCTION_DEF (task, has_symbol);
/***
 * @method task:enable_symbol(name)
 * Enable specified symbol for this particular task
 * @param {string} name symbol's name
 * @return {boolean} `true` if symbol has been found
 */
LUA_FUNCTION_DEF (task, enable_symbol);
/***
 * @method task:disable_symbol(name)
 * Disable specified symbol for this particular task
 * @param {string} name symbol's name
 * @return {boolean} `true` if symbol has been found
 */
LUA_FUNCTION_DEF (task, disable_symbol);
/***
 * @method task:get_date(type[, gmt])
 * Returns timestamp for a connection or for a MIME message. This function can be called with a
 * single table arguments with the following fields:
 *
 * * `format` - a format of date returned:
 * 	- `message` - returns a mime date as integer (unix timestamp)
 * 	- `connect` - returns a unix timestamp of a connection to rspamd
 * * `gmt` - returns date in `GMT` timezone (normal for unix timestamps)
 *
 * By default this function returns connection time in numeric format.
 * @param {string} type date format as described above
 * @param {boolean} gmt gmt flag as described above
 * @return {string/number} date representation according to format
 * @example
rspamd_config.DATE_IN_PAST = function(task)
	local dm = task:get_date{format = 'message', gmt = true}
	local dt = task:get_date{format = 'connect', gmt = true}
	-- A day
	if dt - dm > 86400 then
		return true
	end

	return false
end
 */
LUA_FUNCTION_DEF (task, get_date);
/***
 * @method task:get_message_id()
 * Returns message identifier from the `Message-ID` header.  Angle brackets (`<>`)
 * are stripped off if present.  If a Message-ID header is missing `undef` is
 * returned.
 * @return {string} ID of the message
 */
LUA_FUNCTION_DEF (task, get_message_id);
/***
 * @method task:get_timeval([raw])
 * Returns the timestamp for a task start processing time.
 * @param {boolean} raw if true then two float numbers are returned: task start timestamp and timeout event timestamp
 * @return {table} table with fields as described in `struct timeval` in C
 */
LUA_FUNCTION_DEF (task, get_timeval);
/***
 * @method task:get_scan_time([set])
 * Returns 2 floating point numbers: scan real time and scan virtual time.
 * If `set` is `true`, then the finishing time is also set (enabled by default).
 * This function should be normally called on idempotent phase.
 * @return {number,number} real and virtual times in seconds with floating point
 */
LUA_FUNCTION_DEF (task, get_scan_time);
/***
 * @method task:get_metric_result()
 * Get full result of a metric as a table:
 * - `score`: current score
 * - `action`: current action as a string
 * - `nnegative`: number of negative rules matched
 * - `npositive`: number of positive rules matched
 * - `positive_score`: total score for positive rules
 * - `negative_score`: total score for negative rules
 * - `passthrough`: set to true if message has a passthrough result
 * @return {table} metric result
 */
LUA_FUNCTION_DEF (task, get_metric_result);
/***
 * @method task:get_metric_score(name)
 * Get the current score of metric `name` (must be nil or 'default') . Should be used in idempotent filters only.
 * @param {string} name name of a metric
 * @return {number,number} 2 numbers containing the current score and required score of the metric
 */
LUA_FUNCTION_DEF (task, get_metric_score);
/***
 * @method task:get_metric_action(name)
 * Get the current action of metric `name` (must be nil or 'default'). Should be used in idempotent filters only.
 * @param {string} name name of a metric
 * @return {string} the current action of the metric as a string
 */
LUA_FUNCTION_DEF (task, get_metric_action);
/***
 * @method task:set_metric_score(name, score)
 * Set the current score of metric `name`. Should be used in post-filters only.
 * @param {string} name name of a metric
 * @param {number} score the current score of the metric
 */
LUA_FUNCTION_DEF (task, set_metric_score);
/***
 * @method task:set_metric_subject(subject)
 * Set the subject in the default metric
 * @param {string} subject subject to set
 */
LUA_FUNCTION_DEF (task, set_metric_subject);

/***
 * @method task:learn(is_spam[, classifier)
 * Learn classifier `classifier` with the task. If `is_spam` is true then message
 * is learnt as spam. Otherwise HAM is learnt. By default, this function learns
 * `bayes` classifier.
 * @param {boolean} is_spam learn spam or ham
 * @param {string} classifier classifier's name
 * @return {boolean} `true` if classifier has been learnt successfully
 */
LUA_FUNCTION_DEF (task, learn);
/***
 * @method task:set_settings(obj)
 * Set users settings object for a task. The format of this object is described
 * [here](https://rspamd.com/doc/configuration/settings.html).
 * @param {any} obj any lua object that corresponds to the settings format
 */
LUA_FUNCTION_DEF (task, set_settings);

/***
 * @method task:set_settings_id(id)
 * Set users settings id for a task (must be registered previously)
 * @available 2.0+
 * @param {number} id numeric id
 * @return {boolean} true if settings id has been replaced from the existing one
 */
LUA_FUNCTION_DEF (task, set_settings_id);

/***
 * @method task:get_settings()
 * Gets users settings object for a task. The format of this object is described
 * [here](https://rspamd.com/doc/configuration/settings.html).
 * @return {lua object} lua object generated from UCL
 */
LUA_FUNCTION_DEF (task, get_settings);

/***
 * @method task:lookup_settings(key)
 * Gets users settings object with the specified key for a task.
 * @param {string} key key to lookup
 * @return {lua object} lua object generated from UCL
 */
LUA_FUNCTION_DEF (task, lookup_settings);

/***
 * @method task:get_settings_id()
 * Get numeric hash of settings id if specified for this task. 0 is returned otherwise.
 * @return {number} settings-id hash
 */
LUA_FUNCTION_DEF (task, get_settings_id);

/***
 * @method task:set_milter_reply(obj)
 * Set special reply for milter
 * @param {any} obj any lua object that corresponds to the settings format
 * @example
task:set_milter_reply({
	add_headers = {['X-Lua'] = 'test'},
	-- 1 is the position of header to remove
	remove_headers = {['DKIM-Signature'] = 1},
})
 */
LUA_FUNCTION_DEF (task, set_milter_reply);

/***
 * @method task:process_re(params)
 * Processes the specified regexp and returns number of captures (cached or new)
 * Params is the table with the following fields (mandatory fields are marked with `*`):
 * - `re`* : regular expression object
 * - `type`*: type of regular expression:
 *   + `mime`: mime regexp
 *   + `header`: header regexp
 *   + `rawheader`: raw header expression
 *   + `rawmime`: raw mime regexp
 *   + `body`: raw body regexp
 *   + `url`: url regexp
 * - `header`: for header and rawheader regexp means the name of header
 * - `strong`: case sensitive match for headers
 * @return {number} number of regexp occurrences in the task (limited by 255 so far)
 */
LUA_FUNCTION_DEF (task, process_regexp);

/***
 * @method task:cache_set(key, value)
 * Store some value to the task cache
 * @param {string} key key to use
 * @param {any} value any value (including functions and tables)
 */
LUA_FUNCTION_DEF (task, cache_set);
/***
 * @method task:cache_get(key)
 * Returns cached value or nil if nothing is cached
 * @param {string} key key to use
 * @return {any} cached value
 */
LUA_FUNCTION_DEF (task, cache_get);

/***
 * @method task:get_size()
 * Returns size of the task in bytes (that includes headers + parts size)
 * @return {number} size in bytes
 */
LUA_FUNCTION_DEF (task, get_size);

/***
 * @method task:set_flag(flag_name[, set])
 * Set specific flag for task:
 *
 * - `no_log`: do not log task summary
 * - `no_stat`: do not include task into scanned stats
 * - `pass_all`: check all filters for task
 * - `extended_urls`: output extended info about urls
 * - `skip`: skip task processing
 * - `learn_spam`: learn message as spam
 * - `learn_ham`: learn message as ham
 * - `broken_headers`: header data is broken for a message
 * @param {string} flag to set
 * @param {boolean} set set or clear flag (default is set)
@example
--[[
For messages with undefined queue ID (scanned with rspamc or WebUI)
do not include results into statistics and do not log task summary
(it will not appear in the WebUI history as well).
]]--

-- Callback function to set flags
local function no_log_stat_cb(task)
  if not task:get_queue_id() then
    task:set_flag('no_log')
    task:set_flag('no_stat')
  end
end

rspamd_config:register_symbol({
  name = 'LOCAL_NO_LOG_STAT',
  type = 'postfilter',
  callback = no_log_stat_cb
})
 */
LUA_FUNCTION_DEF (task, set_flag);


/***
 * @method task:has_flag(flag_name)
 * Checks for a specific flag in task:
 *
 * - `no_log`: do not log task summary
 * - `no_stat`: do not include task into scanned stats
 * - `pass_all`: check all filters for task
 * - `extended_urls`: output extended info about urls
 * - `skip`: skip task processing
 * - `learn_spam`: learn message as spam
 * - `learn_ham`: learn message as ham
 * - `broken_headers`: header data is broken for a message
 * @param {string} flag to check
 * @return {boolean} true if flags is set
 */
LUA_FUNCTION_DEF (task, has_flag);


/***
 * @method task:get_flags()
 * Get list of flags for task:
 *
 * - `no_log`: do not log task summary
 * - `no_stat`: do not include task into scanned stats
 * - `pass_all`: check all filters for task
 * - `extended_urls`: output extended info about urls
 * - `skip`: skip task processing
 * - `learn_spam`: learn message as spam
 * - `learn_ham`: learn message as ham
 * - `broken_headers`: header data is broken for a message
 * - `milter`: task is initiated by milter connection
 * @return {array of strings} table with all flags as strings
 */
LUA_FUNCTION_DEF (task, get_flags);

/***
 * @method task:get_digest()
 * Returns message's unique digest (32 hex symbols)
 * @return {string} hex digest
 */
LUA_FUNCTION_DEF (task, get_digest);

/***
 * @method task:store_in_file([mode|table])
 * If task was loaded using file scan, then this method just returns its name,
 * otherwise, a fresh temporary file is created and its name is returned. Default
 * mode is 0600. To convert lua number to the octal mode you can use the following
 * trick: `tonumber("0644", 8)`. The file is automatically removed when task is
 * destroyed.
 *
 * If table argument is specified, the following extra fields are allowed:
 *
 * - `mode`: same as mode argument
 * - `force_new`: always create a new file
 * - `filename`: use specific filename instead of a temporary one
 * - `tmpmask`: use specific tempmask, e.g. '/tmp/file-XXXXX', where XXXX will be replaced by some random letters
 * - `keep`: do not remove file after task is processed
 *
 * @param {number} mode mode for new file
 * @return {string} file name with task content
 */
LUA_FUNCTION_DEF (task, store_in_file);

/***
 * @method task:get_protocol_reply([flags])
 * This method being called from a **postfilter** will return reply for a message
 * as it is returned to a client. This method returns the Lua table corresponding
 * to the UCL object. Flags is a table that specify which information should be
 * there in a reply:
 *
 * - `basic`: basic info, such as message-id
 * - `metrics`: metrics and symbols
 * - `messages`: messages
 * - `dkim`: dkim signature
 * - `milter`: milter control block
 * - `extra`: extra data, such as profiling
 * - `urls`: list of all urls in a message
 *
 * @param {table} flags table of flags (default is all flags but `urls`)
 * @return {table} ucl object corresponding to the reply
 */
LUA_FUNCTION_DEF (task, get_protocol_reply);

/***
 * @method task:headers_foreach(callback, [params])
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
LUA_FUNCTION_DEF (task, headers_foreach);

/***
 * @method task:disable_action(action)
 * Disables some action for this task (e.g. 'greylist')
 *
 * @param {string} action action to disable
 * @return {boolean} true if an action was enabled and is disabled after the method call
 */
LUA_FUNCTION_DEF (task, disable_action);

/***
 * @method task:get_newlines_type()
 * Returns the most frequent newlines type met in a task
 *
 * @return {string} "cr" for \r, "lf" for \n, "crlf" for \r\n
 */
LUA_FUNCTION_DEF (task, get_newlines_type);

/***
 * @method task:get_stat_tokens()
 * Returns list of tables the statistical tokens:
 * - `data`: 64 bit number encoded as a string
 * - `t1`: the first token (if any)
 * - `t2`: the second token (if any)
 * - `win`: window index
 * - `flag`: table of strings:
 *    - `text`: text token
 *    - `meta`: meta token
 *    - `lua`: lua meta token
 *    - `exception`: exception
 *    - `subject`: subject token
 *    - `unigram`: unigram token
 *
 * @return {table of tables}
 */
LUA_FUNCTION_DEF (task, get_stat_tokens);

/***
 * @method task:lookup_words(map, function({o, n, s, f}) ... end)
 * Matches words in a task (including meta words) against some map (set, regexp and so on)
 * and call the specified function with a table containing 4 values:
 *   - [1] - stemmed word
 *   - [2] - normalised word
 *   - [3] - raw word
 *   - [4] - flags (table of strings)
 */
LUA_FUNCTION_DEF (task, lookup_words);

/**
 * @method task:topointer()
 *
 * Returns raw C pointer (lightuserdata) associated with task. This might be
 * broken with luajit and GC64, use with caution.
 */
LUA_FUNCTION_DEF (task, topointer);

/**
 * @method task:add_named_result(name, symbol_control_function)
 *
 * Adds a new named result for this task. symbol_control_function is a callback
 * called with 3 parameters:
 * `function(task, symbol, result_name)` and it should return boolean that
 * specifies if this symbol should be added to this named result.
 * @param {string} name for this result
 * @param {function} symbol_control_function predicate for symbols
 */
LUA_FUNCTION_DEF (task, add_named_result);

/**
 * @method task:get_all_named_results()
 *
 * Returns all named results registered for the task as a table of strings
 * @return {table|string} all named results starting from `default`
 */
LUA_FUNCTION_DEF (task, get_all_named_results);

/***
 * @method task:get_dns_req()
 * Get number of dns requests being sent in the task
 * @return {number} number of DNS requests
 */
LUA_FUNCTION_DEF (task, get_dns_req);

static const struct luaL_reg tasklib_f[] = {
	LUA_INTERFACE_DEF (task, create),
	LUA_INTERFACE_DEF (task, load_from_file),
	LUA_INTERFACE_DEF (task, load_from_string),
	{NULL, NULL}
};

static const struct luaL_reg tasklib_m[] = {
	LUA_INTERFACE_DEF (task, get_message),
	LUA_INTERFACE_DEF (task, set_message),
	LUA_INTERFACE_DEF (task, destroy),
	LUA_INTERFACE_DEF (task, process_message),
	LUA_INTERFACE_DEF (task, set_cfg),
	LUA_INTERFACE_DEF (task, get_cfg),
	LUA_INTERFACE_DEF (task, get_mempool),
	LUA_INTERFACE_DEF (task, get_session),
	LUA_INTERFACE_DEF (task, set_session),
	LUA_INTERFACE_DEF (task, get_ev_base),
	LUA_INTERFACE_DEF (task, get_worker),
	LUA_INTERFACE_DEF (task, insert_result),
	LUA_INTERFACE_DEF (task, insert_result_named),
	LUA_INTERFACE_DEF (task, adjust_result),
	LUA_INTERFACE_DEF (task, remove_result),
	LUA_INTERFACE_DEF (task, set_pre_result),
	LUA_INTERFACE_DEF (task, has_pre_result),
	LUA_INTERFACE_DEF (task, append_message),
	LUA_INTERFACE_DEF (task, has_urls),
	LUA_INTERFACE_DEF (task, get_urls),
	LUA_INTERFACE_DEF (task, get_urls_filtered),
	LUA_INTERFACE_DEF (task, inject_url),
	LUA_INTERFACE_DEF (task, get_content),
	LUA_INTERFACE_DEF (task, get_filename),
	LUA_INTERFACE_DEF (task, get_rawbody),
	LUA_INTERFACE_DEF (task, get_emails),
	LUA_INTERFACE_DEF (task, get_text_parts),
	LUA_INTERFACE_DEF (task, get_parts),
	LUA_INTERFACE_DEF (task, get_request_header),
	LUA_INTERFACE_DEF (task, set_request_header),
	LUA_INTERFACE_DEF (task, get_header),
	LUA_INTERFACE_DEF (task, has_header),
	LUA_INTERFACE_DEF (task, get_header_raw),
	LUA_INTERFACE_DEF (task, get_header_full),
	LUA_INTERFACE_DEF (task, get_header_count),
	LUA_INTERFACE_DEF (task, get_raw_headers),
	LUA_INTERFACE_DEF (task, get_headers),
	LUA_INTERFACE_DEF (task, modify_header),
	LUA_INTERFACE_DEF (task, get_received_headers),
	LUA_INTERFACE_DEF (task, get_queue_id),
	LUA_INTERFACE_DEF (task, get_uid),
	LUA_INTERFACE_DEF (task, get_resolver),
	LUA_INTERFACE_DEF (task, set_resolver),
	LUA_INTERFACE_DEF (task, inc_dns_req),
	LUA_INTERFACE_DEF (task, get_dns_req),
	LUA_INTERFACE_DEF (task, has_recipients),
	LUA_INTERFACE_DEF (task, get_recipients),
	LUA_INTERFACE_DEF (task, set_recipients),
	LUA_INTERFACE_DEF (task, get_principal_recipient),
	LUA_INTERFACE_DEF (task, get_reply_sender),
	LUA_INTERFACE_DEF (task, has_from),
	LUA_INTERFACE_DEF (task, get_from),
	LUA_INTERFACE_DEF (task, set_from),
	LUA_INTERFACE_DEF (task, get_user),
	LUA_INTERFACE_DEF (task, set_user),
	{"get_addr", lua_task_get_from_ip},
	{"get_ip", lua_task_get_from_ip},
	{"get_from_addr", lua_task_get_from_ip},
	LUA_INTERFACE_DEF (task, get_from_ip),
	LUA_INTERFACE_DEF (task, set_from_ip),
	LUA_INTERFACE_DEF (task, get_from_ip_num),
	LUA_INTERFACE_DEF (task, get_client_ip),
	LUA_INTERFACE_DEF (task, get_subject),
	LUA_INTERFACE_DEF (task, get_helo),
	LUA_INTERFACE_DEF (task, set_helo),
	LUA_INTERFACE_DEF (task, get_hostname),
	LUA_INTERFACE_DEF (task, set_hostname),
	LUA_INTERFACE_DEF (task, get_images),
	LUA_INTERFACE_DEF (task, get_archives),
	LUA_INTERFACE_DEF (task, get_dkim_results),
	LUA_INTERFACE_DEF (task, get_symbol),
	LUA_INTERFACE_DEF (task, get_symbols),
	LUA_INTERFACE_DEF (task, get_symbols_all),
	LUA_INTERFACE_DEF (task, get_symbols_numeric),
	LUA_INTERFACE_DEF (task, get_symbols_tokens),
	LUA_INTERFACE_DEF (task, get_groups),
	LUA_INTERFACE_DEF (task, process_ann_tokens),
	LUA_INTERFACE_DEF (task, has_symbol),
	LUA_INTERFACE_DEF (task, enable_symbol),
	LUA_INTERFACE_DEF (task, disable_symbol),
	LUA_INTERFACE_DEF (task, get_date),
	LUA_INTERFACE_DEF (task, get_message_id),
	LUA_INTERFACE_DEF (task, get_timeval),
	LUA_INTERFACE_DEF (task, get_scan_time),
	LUA_INTERFACE_DEF (task, get_metric_result),
	LUA_INTERFACE_DEF (task, get_metric_score),
	LUA_INTERFACE_DEF (task, get_metric_action),
	LUA_INTERFACE_DEF (task, set_metric_score),
	LUA_INTERFACE_DEF (task, set_metric_subject),
	LUA_INTERFACE_DEF (task, learn),
	LUA_INTERFACE_DEF (task, set_settings),
	LUA_INTERFACE_DEF (task, get_settings),
	LUA_INTERFACE_DEF (task, lookup_settings),
	LUA_INTERFACE_DEF (task, get_settings_id),
	LUA_INTERFACE_DEF (task, set_settings_id),
	LUA_INTERFACE_DEF (task, cache_get),
	LUA_INTERFACE_DEF (task, cache_set),
	LUA_INTERFACE_DEF (task, process_regexp),
	LUA_INTERFACE_DEF (task, get_size),
	LUA_INTERFACE_DEF (task, set_flag),
	LUA_INTERFACE_DEF (task, get_flags),
	LUA_INTERFACE_DEF (task, has_flag),
	{"set_rmilter_reply", lua_task_set_milter_reply},
	LUA_INTERFACE_DEF (task, set_milter_reply),
	LUA_INTERFACE_DEF (task, get_digest),
	LUA_INTERFACE_DEF (task, store_in_file),
	LUA_INTERFACE_DEF (task, get_protocol_reply),
	LUA_INTERFACE_DEF (task, headers_foreach),
	LUA_INTERFACE_DEF (task, disable_action),
	LUA_INTERFACE_DEF (task, get_newlines_type),
	LUA_INTERFACE_DEF (task, get_stat_tokens),
	LUA_INTERFACE_DEF (task, get_meta_words),
	LUA_INTERFACE_DEF (task, lookup_words),
	LUA_INTERFACE_DEF (task, add_named_result),
	LUA_INTERFACE_DEF (task, get_all_named_results),
	LUA_INTERFACE_DEF (task, topointer),
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};

/* Image methods */
LUA_FUNCTION_DEF (image, get_width);
LUA_FUNCTION_DEF (image, get_height);
LUA_FUNCTION_DEF (image, get_type);
LUA_FUNCTION_DEF (image, get_filename);
LUA_FUNCTION_DEF (image, get_size);

static const struct luaL_reg imagelib_m[] = {
	LUA_INTERFACE_DEF (image, get_width),
	LUA_INTERFACE_DEF (image, get_height),
	LUA_INTERFACE_DEF (image, get_type),
	LUA_INTERFACE_DEF (image, get_filename),
	LUA_INTERFACE_DEF (image, get_size),
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};

/* Archive methods */
LUA_FUNCTION_DEF (archive, get_type);
LUA_FUNCTION_DEF (archive, get_files);
LUA_FUNCTION_DEF (archive, get_files_full);
LUA_FUNCTION_DEF (archive, is_encrypted);
LUA_FUNCTION_DEF (archive, is_unreadable);
LUA_FUNCTION_DEF (archive, get_filename);
LUA_FUNCTION_DEF (archive, get_size);

static const struct luaL_reg archivelib_m[] = {
	LUA_INTERFACE_DEF (archive, get_type),
	LUA_INTERFACE_DEF (archive, get_files),
	LUA_INTERFACE_DEF (archive, get_files_full),
	LUA_INTERFACE_DEF (archive, is_encrypted),
	LUA_INTERFACE_DEF (archive, is_unreadable),
	LUA_INTERFACE_DEF (archive, get_filename),
	LUA_INTERFACE_DEF (archive, get_size),
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};

/* Utility functions */
struct rspamd_task *
lua_check_task (lua_State * L, gint pos)
{
	void *ud = rspamd_lua_check_udata (L, pos, "rspamd{task}");
	luaL_argcheck (L, ud != NULL, pos, "'task' expected");
	return ud ? *((struct rspamd_task **)ud) : NULL;
}

struct rspamd_task *
lua_check_task_maybe (lua_State * L, gint pos)
{
	void *ud = rspamd_lua_check_udata_maybe (L, pos, "rspamd{task}");

	return ud ? *((struct rspamd_task **)ud) : NULL;
}

static struct rspamd_image *
lua_check_image (lua_State * L)
{
	void *ud = rspamd_lua_check_udata (L, 1, "rspamd{image}");
	luaL_argcheck (L, ud != NULL, 1, "'image' expected");
	return ud ? *((struct rspamd_image **)ud) : NULL;
}

static struct rspamd_archive *
lua_check_archive (lua_State * L)
{
	void *ud = rspamd_lua_check_udata (L, 1, "rspamd{archive}");
	luaL_argcheck (L, ud != NULL, 1, "'archive' expected");
	return ud ? *((struct rspamd_archive **)ud) : NULL;
}

static void
lua_task_set_cached (lua_State *L, struct rspamd_task *task, const gchar *key,
		gint pos)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_cached_entry *entry;

	lua_pushvalue (L, pos);

	entry = g_hash_table_lookup (task->lua_cache, key);

	if (G_UNLIKELY (entry != NULL)) {
		/* Unref previous value */
		luaL_unref (L, LUA_REGISTRYINDEX, entry->ref);
	}
	else {
		entry = rspamd_mempool_alloc (task->task_pool, sizeof (*entry));
		g_hash_table_insert (task->lua_cache,
				rspamd_mempool_strdup (task->task_pool, key), entry);
	}

	entry->ref = luaL_ref (L, LUA_REGISTRYINDEX);

	if (task->message) {
		entry->id = GPOINTER_TO_UINT (task->message);
	}
}


static gboolean
lua_task_get_cached (lua_State *L, struct rspamd_task *task, const gchar *key)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_cached_entry *entry;

	entry = g_hash_table_lookup (task->lua_cache, key);

	if (entry != NULL && (task->message &&
						  entry->id == GPOINTER_TO_UINT (task->message))) {
		lua_rawgeti (L, LUA_REGISTRYINDEX, entry->ref);

		return TRUE;
	}

	return FALSE;
}

/* Task methods */
static int
lua_task_process_message (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	gboolean enforce = FALSE;

	if (task != NULL) {
		if (task->msg.len > 0) {
			if (lua_isboolean (L, 2)) {
				enforce = lua_toboolean (L, 2);
			}

			if (rspamd_message_parse (task)) {
				if (enforce ||
					(!(task->flags & RSPAMD_TASK_FLAG_SKIP_PROCESS) &&
					!(task->processed_stages & RSPAMD_TASK_STAGE_PROCESS_MESSAGE))) {

					lua_pushboolean (L, TRUE);
					rspamd_message_process (task);
					task->processed_stages |= RSPAMD_TASK_STAGE_PROCESS_MESSAGE;
				}
				else {
					lua_pushboolean (L, FALSE);
				}
			}
			else {
				lua_pushboolean (L, FALSE);
			}
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

static int
lua_task_get_cfg (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	struct rspamd_config **pcfg;

	if (task) {
		pcfg = lua_newuserdata (L, sizeof (gpointer));
		rspamd_lua_setclass (L, "rspamd{config}", -1);
		*pcfg = task->cfg;
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static int
lua_task_set_cfg (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	void *ud = rspamd_lua_check_udata (L, 2, "rspamd{config}");

	if (task) {
		luaL_argcheck (L, ud != NULL, 1, "'config' expected");
		task->cfg = ud ? *((struct rspamd_config **)ud) : NULL;
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 0;
}

static int
lua_task_destroy (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);

	if (task != NULL) {
		rspamd_task_free (task);
	}

	return 0;
}

static int
lua_task_get_message (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_text *t;
	struct rspamd_task *task = lua_check_task (L, 1);

	if (task) {
		t = lua_newuserdata (L, sizeof (*t));
		rspamd_lua_setclass (L, "rspamd{text}", -1);
		t->flags = 0;
		t->start = task->msg.begin;
		t->len = task->msg.len;
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static int
lua_task_set_message (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_lua_text *t;
	struct rspamd_task *task = lua_check_task (L, 1);
	gboolean message_set = FALSE;

	if (task) {
		gsize final_len = 0;
		gchar *buf = NULL;

		if (lua_type (L, 2) == LUA_TTABLE) {
			/* Piecewise construct */
			guint vec_len = rspamd_lua_table_size (L, 2);


			for (guint i = 0; i < vec_len; i ++) {
				lua_rawgeti (L, 2, i + 1);

				if (lua_type (L, -1) == LUA_TSTRING) {
					gsize l;

					(void)lua_tolstring (L, -1, &l);
					final_len += l;
				}
				else {
					t = lua_check_text (L, -1);

					if (t) {
						final_len += t->len;
					}
				}

				lua_pop (L, 1);
			}

			if (final_len > 0) {
				gchar *pos;

				buf = rspamd_mempool_alloc (task->task_pool, final_len);
				pos = buf;

				for (guint i = 0; i < vec_len; i ++) {
					lua_rawgeti (L, 2, i + 1);

					if (lua_type (L, -1) == LUA_TSTRING) {
						gsize l;
						const gchar *s;

						s = lua_tolstring (L, -1, &l);
						memcpy (pos, s, l);
						pos += l;
					}
					else {
						t = lua_check_text (L, -1);

						if (t) {
							memcpy (pos, t->start, t->len);
							pos += t->len;
						}
					}

					lua_pop (L, 1);
				}

				task->flags |= RSPAMD_TASK_FLAG_MESSAGE_REWRITE;
				task->msg.begin = buf;
				task->msg.len = final_len;
				message_set = TRUE;
			}

		}
		else {
			if (lua_type (L, 2) == LUA_TSTRING) {
				const gchar *s;

				s = lua_tolstring (L, -1, &final_len);
				buf = rspamd_mempool_alloc (task->task_pool, final_len);
				memcpy (buf, s, final_len);
			}
			else {
				t = lua_check_text (L, -1);

				if (t) {
					final_len = t->len;
					buf = rspamd_mempool_alloc (task->task_pool, final_len);
					memcpy (buf, t->start, final_len);
				}
			}

			if (buf) {
				task->msg.begin = buf;
				task->msg.len = final_len;
				task->flags |= RSPAMD_TASK_FLAG_MESSAGE_REWRITE;
				message_set = TRUE;
			}
		}

		if (message_set) {
			if (rspamd_message_parse (task)) {
				rspamd_message_process (task);
				lua_pushboolean (L, TRUE);
				lua_pushinteger (L, final_len);

				return 2;
			}
			else {
				lua_pushboolean (L, FALSE);
			}
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

static void
lua_task_unmap_dtor (gpointer p)
{
	struct rspamd_task *task = (struct rspamd_task *)p;

	if (task->msg.begin) {
		munmap ((gpointer)task->msg.begin, task->msg.len);
	}
}

static void
lua_task_free_dtor (gpointer p)
{
	g_free (p);
}

static gint
lua_task_load_from_file (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = NULL, **ptask;
	const gchar *fname = luaL_checkstring (L, 1), *err = NULL;
	struct rspamd_config *cfg = NULL;
	gboolean res = FALSE;
	gpointer map;
	gsize sz;

	if (fname) {

		if (lua_type (L, 2) == LUA_TUSERDATA) {
			gpointer p;
			p = rspamd_lua_check_udata_maybe (L, 2, "rspamd{config}");

			if (p) {
				cfg = *(struct rspamd_config **)p;
			}
		}

		if (strcmp (fname, "-") == 0) {
			/* Read from stdin */
			gint fd = STDIN_FILENO;
			GString *data = g_string_sized_new (BUFSIZ);
			gchar buf[BUFSIZ];
			gssize r;

			for (;;) {
				r = read (fd, buf, sizeof (buf));

				if (r == -1) {
					err = strerror (errno);
					break;
				}
				else if (r == 0) {
					break;
				}
				else {
					g_string_append_len (data, buf, r);
				}
			}

			task = rspamd_task_new (NULL, cfg, NULL, NULL, NULL, FALSE);
			task->msg.begin = data->str;
			task->msg.len = data->len;
			rspamd_mempool_add_destructor (task->task_pool,
					lua_task_free_dtor, data->str);
			res = TRUE;
			g_string_free (data, FALSE); /* Buffer is still valid */
		}
		else {
			map = rspamd_file_xmap (fname, PROT_READ, &sz, TRUE);

			if (!map) {
				err = strerror (errno);
			} else {
				task = rspamd_task_new (NULL, cfg, NULL, NULL, NULL, FALSE);
				task->msg.begin = map;
				task->msg.len = sz;
				rspamd_mempool_add_destructor (task->task_pool,
						lua_task_unmap_dtor, task);
				res = TRUE;
			}
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	lua_pushboolean (L, res);

	if (res) {
		ptask = lua_newuserdata (L, sizeof (*ptask));
		*ptask = task;
		rspamd_lua_setclass (L, "rspamd{task}", -1);
	}
	else {
		if (err) {
			lua_pushstring (L, err);
		}
		else {
			lua_pushnil (L);
		}
	}

	return 2;
}

static gint
lua_task_load_from_string (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = NULL, **ptask;
	const gchar *str_message;
	gsize message_len;
	struct rspamd_config *cfg = NULL;

	str_message = luaL_checklstring (L, 1, &message_len);

	if (str_message) {

		if (lua_type (L, 2) == LUA_TUSERDATA) {
			gpointer p;
			p = rspamd_lua_check_udata_maybe (L, 2, "rspamd{config}");

			if (p) {
				cfg = *(struct rspamd_config **)p;
			}
		}

		task = rspamd_task_new (NULL, cfg, NULL, NULL, NULL, FALSE);
		task->msg.begin = g_malloc (message_len);
		memcpy ((gchar *)task->msg.begin, str_message, message_len);
		task->msg.len  = message_len;
		rspamd_mempool_add_destructor (task->task_pool, lua_task_free_dtor,
				(gpointer)task->msg.begin);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	lua_pushboolean (L, true);

	ptask = lua_newuserdata (L, sizeof (*ptask));
	*ptask = task;
	rspamd_lua_setclass (L, "rspamd{task}", -1);

	return 2;
}

static gint
lua_task_create (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = NULL, **ptask;
	struct rspamd_config *cfg = NULL;
	struct ev_loop *ev_base = NULL;

	if (lua_type (L, 1) == LUA_TUSERDATA) {
		gpointer p;
		p = rspamd_lua_check_udata_maybe (L, 2, "rspamd{config}");

		if (p) {
			cfg = *(struct rspamd_config **)p;
		}
	}

	if (lua_type (L, 2) == LUA_TUSERDATA) {
		gpointer p;
		p = rspamd_lua_check_udata_maybe (L, 2, "rspamd{ev_base}");

		if (p) {
			ev_base = *(struct ev_loop **)p;
		}
	}

	task = rspamd_task_new (NULL, cfg, NULL, NULL, ev_base, FALSE);
	task->flags |= RSPAMD_TASK_FLAG_EMPTY;

	ptask = lua_newuserdata (L, sizeof (*ptask));
	*ptask = task;
	rspamd_lua_setclass (L, "rspamd{task}", -1);

	return 1;
}

static int
lua_task_get_mempool (lua_State * L)
{
	LUA_TRACE_POINT;
	rspamd_mempool_t **ppool;
	struct rspamd_task *task = lua_check_task (L, 1);

	if (task != NULL) {
		ppool = lua_newuserdata (L, sizeof (rspamd_mempool_t *));
		rspamd_lua_setclass (L, "rspamd{mempool}", -1);
		*ppool = task->task_pool;
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static int
lua_task_get_session (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_async_session **psession;
	struct rspamd_task *task = lua_check_task (L, 1);

	if (task != NULL) {
		psession = lua_newuserdata (L, sizeof (void *));
		rspamd_lua_setclass (L, "rspamd{session}", -1);
		*psession = task->s;
	}
	else {
		return luaL_error (L, "invalid arguments");
	}
	return 1;
}

static int
lua_task_set_session (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_async_session *session = lua_check_session (L, 2);
	struct rspamd_task *task = lua_check_task (L, 1);

	if (task != NULL && session != NULL) {
		task->s = session;
	}
	else {
		return luaL_error (L, "invalid arguments");
	}
	return 1;
}

static int
lua_task_get_ev_base (lua_State * L)
{
	LUA_TRACE_POINT;
	struct ev_loop **pbase;
	struct rspamd_task *task = lua_check_task (L, 1);

	if (task != NULL) {
		pbase = lua_newuserdata (L, sizeof (struct ev_loop *));
		rspamd_lua_setclass (L, "rspamd{ev_base}", -1);
		*pbase = task->event_loop;
	}
	else {
		return luaL_error (L, "invalid arguments");
	}
	return 1;
}

static int
lua_task_get_worker (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_worker **pworker;
	struct rspamd_task *task = lua_check_task (L, 1);

	if (task != NULL) {
		if (task->worker) {
			pworker = lua_newuserdata (L, sizeof (struct rspamd_worker *));
			rspamd_lua_setclass (L, "rspamd{worker}", -1);
			*pworker = task->worker;
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
lua_task_insert_result_common (lua_State * L, struct rspamd_scan_result *result,
		gint common_args_pos)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	const gchar *symbol_name;
	double weight;
	struct rspamd_symbol_result *s;
	enum rspamd_symbol_insert_flags flags = RSPAMD_SYMBOL_INSERT_DEFAULT;
	gint i, top, args_start;

	if (task != NULL) {
		if (lua_isboolean (L, common_args_pos)) {
			args_start = common_args_pos + 1;

			if (lua_toboolean (L, common_args_pos)) {
				flags |= RSPAMD_SYMBOL_INSERT_ENFORCE;
			}
		}
		else {
			args_start = common_args_pos;
		}

		symbol_name = rspamd_mempool_strdup (task->task_pool,
				luaL_checkstring (L, args_start));
		weight = luaL_checknumber (L, args_start + 1);
		top = lua_gettop (L);
		s = rspamd_task_insert_result_full (task, symbol_name, weight,
				NULL, flags, result);

		/* Get additional options */
		if (s) {
			if (s->sym == NULL) {
				/* Unknown symbol, print traceback */
				lua_pushfstring (L, "unknown symbol %s", symbol_name);
				rspamd_lua_traceback (L);

				msg_info_task ("symbol insertion issue: %s", lua_tostring (L, -1));

				lua_pop (L, 1); /* Traceback string */
			}
			for (i = args_start + 2; i <= top; i++) {
				gint ltype = lua_type (L, i);

				if (ltype == LUA_TSTRING) {
					gsize optlen;
					const char *opt = lua_tolstring (L, i, &optlen);

					rspamd_task_add_result_option (task, s, opt, optlen);
				}
				else if (ltype == LUA_TUSERDATA) {
					struct rspamd_lua_text *t = lua_check_text (L, i);

					if (t) {
						rspamd_task_add_result_option (task, s, t->start,
								t->len);
					}
				}
				else if (ltype == LUA_TTABLE) {
					gsize objlen = rspamd_lua_table_size (L, i);

					for (guint j = 1; j <= objlen; j ++) {
						lua_rawgeti (L, i, j);

						if (lua_type (L, -1) == LUA_TSTRING) {
							gsize optlen;
							const char *opt = lua_tolstring (L, -1, &optlen);

							rspamd_task_add_result_option (task, s, opt, optlen);
						}
						else if (lua_type (L, -1) == LUA_TUSERDATA) {
							struct rspamd_lua_text *t = lua_check_text (L, -1);

							if (t) {
								rspamd_task_add_result_option (task, s, t->start,
										t->len);
							}
							else {
								return luaL_error (L, "not rspamd_text option in a table "
													  "when adding symbol  %s: %s type",
										s->name);
							}
						}
						else {
							const gchar *tname = lua_typename (L, lua_type (L, -1));
							lua_pop (L, 2);

							return luaL_error (L, "not a string option in a table "
												  "when adding symbol  %s: %s type",
									s->name, tname);
						}

						lua_pop (L, 1);
					}
				}
				else if (ltype == LUA_TNIL) {
					/* We have received a NULL option, it is not good but not a fatal error */
					msg_info_task ("nil option when adding symbol %s at pos %d",
							s->name, i);
					continue;
				}
				else {
					const gchar *tname = lua_typename (L, ltype);

					return luaL_error (L, "not a string/table option "
										  "when adding symbol %s: %s type",
							s->name, tname);
				}
			}
		}
		else if (task->settings == NULL && task->settings_elt == NULL) {
			lua_pushfstring (L, "insertion failed for %s", symbol_name);
			rspamd_lua_traceback (L);

			msg_info_task ("symbol insertion issue: %s", lua_tostring (L, -1));

			lua_pop (L, 2); /* Traceback string + error string */
		}
		else {
			/* Usually denied by settings */

		}

	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 0;
}

static gint
lua_task_insert_result (lua_State * L)
{
	return lua_task_insert_result_common (L, NULL, 2);
}

static gint
lua_task_insert_result_named (lua_State * L)
{
	struct rspamd_task *task = lua_check_task (L, 1);
	const gchar *named_result = luaL_checkstring (L, 2);
	struct rspamd_scan_result *res;

	if (task && named_result) {
		res = rspamd_find_metric_result (task, named_result);

		if (res == NULL) {
			return luaL_error (L, "invalid arguments: bad named result: %s",
					named_result);
		}

		return lua_task_insert_result_common (L, res, 3);
	}

	return luaL_error (L, "invalid arguments");
}

static gint
lua_task_adjust_result (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	const gchar *symbol_name;
	struct rspamd_scan_result *metric_res;
	struct rspamd_symbol_result *s = NULL;
	double weight;
	gint i, top;

	if (task != NULL) {

		symbol_name = luaL_checkstring (L, 2);
		weight = luaL_checknumber (L, 3);
		top = lua_gettop (L);
		metric_res = task->result;

		if (metric_res) {
			s = rspamd_task_find_symbol_result (task, symbol_name, NULL);
		}
		else {
			return luaL_error (L, "no metric result");
		}

		if (s) {
			if (!isnan (weight)) {
				metric_res->score -= s->score;
				s->score = weight;
				metric_res->score += s->score;
			}
		}
		else {
			return luaL_error (L, "symbol not found: %s", symbol_name);
		}

		/* Get additional options */
		if (s) {
			for (i = 4; i <= top; i++) {
				if (lua_type (L, i) == LUA_TSTRING) {
					gsize optlen;
					const char *opt = lua_tolstring (L, i, &optlen);

					rspamd_task_add_result_option (task, s, opt, optlen);
				}
				else if (lua_type (L, i) == LUA_TUSERDATA) {
					struct rspamd_lua_text *t = lua_check_text (L, i);

					if (t) {
						rspamd_task_add_result_option (task, s, t->start,
								t->len);
					}
				}
				else if (lua_type (L, i) == LUA_TTABLE) {
					gsize objlen = rspamd_lua_table_size (L, i);

					for (guint j = 1; j <= objlen; j ++) {
						lua_rawgeti (L, i, j);

						if (lua_type (L, -1) == LUA_TSTRING) {
							gsize optlen;
							const char *opt = lua_tolstring (L, -1, &optlen);

							rspamd_task_add_result_option (task, s, opt, optlen);
						}
						else if (lua_type (L, -1) == LUA_TUSERDATA) {
							struct rspamd_lua_text *t = lua_check_text (L, -1);

							if (t) {
								rspamd_task_add_result_option (task, s, t->start,
										t->len);
							}
						}

						lua_pop (L, 1);
					}
				}
			}
		}

	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 0;
}

static gint
lua_task_remove_result (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	const gchar *symbol_name = luaL_checkstring (L, 2);
	struct rspamd_scan_result *metric_res;
	const gchar *named_result = luaL_optstring (L, 3, NULL);

	if (task != NULL) {
		metric_res = rspamd_find_metric_result (task, named_result);

		if (metric_res == NULL) {
			return luaL_error (L, "invalid arguments: bad named result: %s",
					named_result);
		}

		lua_pushboolean (L, (rspamd_task_remove_symbol_result (task, symbol_name,
				metric_res)) != NULL);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_task_set_pre_result (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	const gchar *message = NULL, *module = NULL, *fl_str = NULL, *act_str = NULL,
		*res_name = NULL;
	gdouble score = NAN;
	struct rspamd_action *action;
	guint priority = RSPAMD_PASSTHROUGH_NORMAL, flags = 0;

	if (task != NULL) {

		if (RSPAMD_TASK_IS_SKIPPED (task)) {
			/* Do not set pre-result for a skipped task */
			return 0;
		}

		if (lua_type (L, 2) == LUA_TTABLE) {
			GError *err = NULL;

			if (!rspamd_lua_parse_table_arguments (L, 2, &err,
					RSPAMD_LUA_PARSE_ARGUMENTS_DEFAULT,
					"*action=S;message=S;module=S;score=D;priority=i;flags=S;result=S",
					&act_str, &message, &module, &score, &priority, &fl_str, &res_name)) {
				gint ret = luaL_error (L, "invald arguments: %s", err->message);
				g_error_free (err);

				return ret;
			}
		}
		else {
			if (lua_type (L, 2) == LUA_TSTRING) {
				act_str = lua_tostring (L, 2);
			}
			else {
				return luaL_error (L, "invalid arguments");
			}

			if (lua_type (L, 3) == LUA_TSTRING) {
				message = lua_tostring (L, 3);
			}

			if (lua_type (L, 4) == LUA_TSTRING) {
				module = lua_tostring (L, 4);
			}

			if (lua_type (L, 5) == LUA_TNUMBER) {
				score = lua_tonumber (L, 5);
			}

			if (lua_type (L, 6) == LUA_TNUMBER) {
				priority = lua_tonumber (L, 6);
			}

			if (lua_type (L, 7) == LUA_TSTRING) {
				fl_str = lua_tostring (L, 7);
			}
		}

		gint internal_type;

		if (strcmp (act_str, "accept") == 0) {
			/* Compatibility! */
			act_str = "no action";
		}
		else if (rspamd_action_from_str (act_str, &internal_type)) {
			/* Compatibility! */
			act_str = rspamd_action_to_str (internal_type);
		}

		action = rspamd_config_get_action (task->cfg, act_str);

		if (action == NULL) {
			struct rspamd_action *tmp;

			HASH_ITER (hh, task->cfg->actions, action, tmp) {
				msg_err_task ("known defined action: %s = %f",
						action->name, action->threshold);
			}

			return luaL_error (L, "unknown action %s", act_str);
		}

		if (module == NULL) {
			module = "Unknown lua";
		}

		if (message == NULL) {
			message = "unknown reason";
			flags |= RSPAMD_PASSTHROUGH_NO_SMTP_MESSAGE;
		}

		if (fl_str != NULL) {
			if (strstr (fl_str, "least") != NULL) {
				flags |= RSPAMD_PASSTHROUGH_LEAST;
			}
			else if (strstr (fl_str, "no_smtp_message") != NULL) {
				flags |= RSPAMD_PASSTHROUGH_NO_SMTP_MESSAGE;
			}
			else if (strstr (fl_str, "process_all") != NULL) {
				flags |= RSPAMD_PASSTHROUGH_PROCESS_ALL;
			}
		}


		rspamd_add_passthrough_result (task,
				action,
				priority,
				score,
				rspamd_mempool_strdup (task->task_pool, message),
				rspamd_mempool_strdup (task->task_pool, module),
				flags,
				rspamd_find_metric_result (task, res_name));

		/* Don't classify or filter message if pre-filter sets results */

		if (res_name == NULL && !(flags & (RSPAMD_PASSTHROUGH_LEAST|RSPAMD_PASSTHROUGH_PROCESS_ALL))) {
			task->processed_stages |= (RSPAMD_TASK_STAGE_CLASSIFIERS |
									   RSPAMD_TASK_STAGE_CLASSIFIERS_PRE |
									   RSPAMD_TASK_STAGE_CLASSIFIERS_POST);
			rspamd_symcache_disable_all_symbols (task, task->cfg->cache,
					SYMBOL_TYPE_IDEMPOTENT | SYMBOL_TYPE_IGNORE_PASSTHROUGH);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 0;
}

static gint
lua_task_has_pre_result (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	gint nret = 1;

	if (task) {
		if (task->result->passthrough_result) {
			struct rspamd_passthrough_result *pr = task->result->passthrough_result;

			lua_pushboolean (L, true);
			nret = 4;
			/* bool, action, message, module */

			if (pr->action) {
				lua_pushstring(L, rspamd_action_to_str(pr->action->action_type));
			}
			else {
				lua_pushnil(L);
			}

			if (pr->message) {
				lua_pushstring(L, pr->message);
			}
			else {
				lua_pushnil(L);
			}
			if (pr->module) {
				lua_pushstring(L, pr->module);
			}
			else {
				lua_pushnil(L);
			}
		}
		else {
			lua_pushboolean (L, false);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return nret;
}

static gint
lua_task_append_message (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	const gchar *category;

	if (task != NULL) {
		if (lua_type (L, 3) == LUA_TSTRING) {
			category = luaL_checkstring (L, 3);
		}
		else {
			category = "unknown";
		}

		ucl_object_insert_key (task->messages,
				ucl_object_lua_import (L, 2),
				category, 0,
				true);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 0;
}



static gint
lua_task_get_urls (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	struct lua_tree_cb_data cb;
	struct rspamd_url *u;
	static const gint default_protocols_mask = PROTOCOL_HTTP|PROTOCOL_HTTPS|
											   PROTOCOL_FILE|PROTOCOL_FTP;
	gsize sz, max_urls = 0;

	if (task) {
		if (task->cfg) {
			max_urls = task->cfg->max_lua_urls;
		}

		if (task->message == NULL) {
			lua_newtable (L);

			return 1;
		}

		/* Exclude RSPAMD_URL_FLAG_CONTENT to preserve backward compatibility */
		if (!lua_url_cbdata_fill (L, 2, &cb, default_protocols_mask,
				~(RSPAMD_URL_FLAG_CONTENT|RSPAMD_URL_FLAG_IMAGE),
				max_urls)) {
			return luaL_error (L, "invalid arguments");
		}

		sz = kh_size (MESSAGE_FIELD (task, urls));
		sz = lua_url_adjust_skip_prob (task->task_timestamp,
				MESSAGE_FIELD (task, digest), &cb, sz);

		lua_createtable (L, sz, 0);

		if (cb.sort) {
			struct rspamd_url **urls_sorted;
			gint i = 0;

			urls_sorted = g_new0 (struct rspamd_url *, sz);

			kh_foreach_key (MESSAGE_FIELD(task, urls), u, {
				if (i < sz) {
					urls_sorted[i] = u;
					i ++;
				}
			});

			qsort (urls_sorted, i, sizeof (struct rspamd_url *), rspamd_url_cmp_qsort);

			for (int j = 0; j < i; j ++) {
				lua_tree_url_callback (urls_sorted[j], urls_sorted[j], &cb);
			}

			g_free (urls_sorted);
		}
		else {
			kh_foreach_key (MESSAGE_FIELD(task, urls), u, {
				lua_tree_url_callback(u, u, &cb);
			});
		}

		lua_url_cbdata_dtor (&cb);
	}
	else {
		return luaL_error (L, "invalid arguments, no task");
	}

	return 1;
}

static gint
lua_task_get_urls_filtered (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	struct lua_tree_cb_data cb;
	struct rspamd_url *u;
	static const gint default_protocols_mask = PROTOCOL_HTTP|PROTOCOL_HTTPS|
											   PROTOCOL_FILE|PROTOCOL_FTP;
	gsize sz, max_urls = 0;

	if (task) {
		if (task->cfg) {
			max_urls = task->cfg->max_lua_urls;
		}

		if (task->message == NULL) {
			lua_newtable (L);

			return 1;
		}

		if (!lua_url_cbdata_fill_exclude_include (L, 2, &cb, default_protocols_mask, max_urls)) {
			return luaL_error (L, "invalid arguments");
		}

		sz = kh_size (MESSAGE_FIELD (task, urls));
		sz = lua_url_adjust_skip_prob (task->task_timestamp,
				MESSAGE_FIELD (task, digest), &cb, sz);

		lua_createtable (L, sz, 0);

		if (cb.sort) {
			struct rspamd_url **urls_sorted;
			gint i = 0;

			urls_sorted = g_new0 (struct rspamd_url *, sz);

			kh_foreach_key (MESSAGE_FIELD(task, urls), u, {
				if (i < sz) {
					urls_sorted[i] = u;
					i ++;
				}
			});

			qsort (urls_sorted, i, sizeof (struct rspamd_url *), rspamd_url_cmp_qsort);

			for (int j = 0; j < i; j ++) {
				lua_tree_url_callback (urls_sorted[j], urls_sorted[j], &cb);
			}

			g_free (urls_sorted);
		}
		else {
			kh_foreach_key (MESSAGE_FIELD(task, urls), u, {
				lua_tree_url_callback(u, u, &cb);
			});
		}

		lua_url_cbdata_dtor (&cb);
	}
	else {
		return luaL_error (L, "invalid arguments, no task");
	}

	return 1;
}

static gint
lua_task_has_urls (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	gboolean ret = FALSE;
	gsize sz = 0;

	if (task) {
		if (task->message) {
			if (lua_gettop (L) >= 2) {
				lua_toboolean (L, 2);
			}

			if (kh_size (MESSAGE_FIELD (task, urls)) > 0) {
				sz += kh_size (MESSAGE_FIELD (task, urls));
				ret = TRUE;
			}
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	lua_pushboolean (L, ret);
	lua_pushinteger (L, sz);

	return 2;
}

static gint
lua_task_inject_url (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	struct rspamd_lua_url *url = lua_check_url (L, 2);
	struct rspamd_mime_part *mpart = NULL;

	if (lua_isuserdata (L, 3)) {
		/* We also have a mime part there */
		mpart = *((struct rspamd_mime_part **)rspamd_lua_check_udata_maybe (L,
				3, "rspamd{mimepart}"));
	}

	if (task && task->message && url && url->url) {
		if (rspamd_url_set_add_or_increase(MESSAGE_FIELD (task, urls), url->url, false)) {
			if (mpart && mpart->urls) {
				/* Also add url to the mime part */
				g_ptr_array_add (mpart->urls, url->url);
			}
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 0;
}

static gint
lua_task_get_content (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	struct rspamd_lua_text *t;

	if (task) {
		t = lua_newuserdata (L, sizeof (*t));
		rspamd_lua_setclass (L, "rspamd{text}", -1);
		t->len = task->msg.len;
		t->start = task->msg.begin;
		t->flags = 0;
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_task_get_filename (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);

	if (task) {
		if (task->msg.fpath) {
			lua_pushstring (L, task->msg.fpath);
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
lua_task_get_rawbody (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	struct rspamd_lua_text *t;

	if (task) {
		if (task->message != NULL) {
			t = lua_newuserdata (L, sizeof (*t));
			rspamd_lua_setclass (L, "rspamd{text}", -1);

			if (MESSAGE_FIELD (task, raw_headers_content).len > 0) {
				g_assert (MESSAGE_FIELD (task, raw_headers_content).len <= task->msg.len);
				t->start = task->msg.begin + MESSAGE_FIELD (task, raw_headers_content).len;
				t->len = task->msg.len - MESSAGE_FIELD (task, raw_headers_content).len;
			}
			else {
				t->len = task->msg.len;
				t->start = task->msg.begin;
			}

			t->flags = 0;
		}
		else {
			/* Push body it it is there */
			if (task->msg.len > 0 && task->msg.begin != NULL) {
				lua_new_text (L, task->msg.begin, task->msg.len, FALSE);
			}
			else {
				lua_pushnil (L);
			}
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_task_get_emails (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	struct lua_tree_cb_data cb;
	struct rspamd_url *u;
	gsize max_urls = 0, sz;

	if (task) {
		if (task->message) {
			if (task->cfg) {
				max_urls = task->cfg->max_lua_urls;
			}

			if (!lua_url_cbdata_fill (L, 2, &cb, PROTOCOL_MAILTO,
					~(RSPAMD_URL_FLAG_CONTENT|RSPAMD_URL_FLAG_IMAGE),
					max_urls)) {
				return luaL_error (L, "invalid arguments");
			}

			sz = kh_size (MESSAGE_FIELD (task, urls));
			sz = lua_url_adjust_skip_prob (task->task_timestamp,
					MESSAGE_FIELD (task, digest), &cb, sz);

			lua_createtable (L, sz, 0);

			kh_foreach_key (MESSAGE_FIELD (task, urls), u, {
				lua_tree_url_callback (u, u, &cb);
			});

			lua_url_cbdata_dtor (&cb);
		}
		else {
			lua_newtable (L);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_task_get_text_parts (lua_State * L)
{
	LUA_TRACE_POINT;
	guint i;
	struct rspamd_task *task = lua_check_task (L, 1);
	struct rspamd_mime_text_part *part, **ppart;

	if (task != NULL) {

		if (task->message) {
			if (!lua_task_get_cached (L, task, "text_parts")) {
				lua_createtable (L, MESSAGE_FIELD (task, text_parts)->len, 0);

				PTR_ARRAY_FOREACH (MESSAGE_FIELD (task, text_parts), i, part) {
					ppart = lua_newuserdata (L, sizeof (struct rspamd_mime_text_part *));
					*ppart = part;
					rspamd_lua_setclass (L, "rspamd{textpart}", -1);
					/* Make it array */
					lua_rawseti (L, -2, i + 1);
				}

				lua_task_set_cached (L, task, "text_parts", -1);
			}
		}
		else {
			lua_newtable (L);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_task_get_parts (lua_State * L)
{
	LUA_TRACE_POINT;
	guint i;
	struct rspamd_task *task = lua_check_task (L, 1);
	struct rspamd_mime_part *part, **ppart;

	if (task != NULL) {
		if (task->message) {
			lua_createtable (L, MESSAGE_FIELD (task, parts)->len, 0);

			PTR_ARRAY_FOREACH (MESSAGE_FIELD (task, parts), i, part) {
				ppart = lua_newuserdata (L, sizeof (struct rspamd_mime_part *));
				*ppart = part;
				rspamd_lua_setclass (L, "rspamd{mimepart}", -1);
				/* Make it array */
				lua_rawseti (L, -2, i + 1);
			}
		}
		else {
			lua_newtable (L);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_task_get_request_header (lua_State *L)
{
	LUA_TRACE_POINT;
	rspamd_ftok_t *hdr;
	struct rspamd_task *task = lua_check_task (L, 1);
	const gchar *s;
	struct rspamd_lua_text *t;

	s = luaL_checkstring (L, 2);

	if (s && task) {
		hdr = rspamd_task_get_request_header (task, s);

		if (hdr) {
			t = lua_newuserdata (L, sizeof (*t));
			rspamd_lua_setclass (L, "rspamd{text}", -1);
			t->start = hdr->begin;
			t->len = hdr->len;
			t->flags = 0;

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
lua_task_set_request_header (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	const gchar *s, *v = NULL;
	rspamd_fstring_t *buf;
	struct rspamd_lua_text *t;
	rspamd_ftok_t *hdr, *new_name;
	gsize len, vlen = 0;

	s = luaL_checklstring (L, 2, &len);

	if (s && task) {
		if (lua_type (L, 3) == LUA_TSTRING) {
			v = luaL_checklstring (L, 3, &vlen);
		}
		else if (lua_type (L, 3) == LUA_TUSERDATA) {
			t = lua_check_text (L, 3);

			if (t != NULL) {
				v = t->start;
				vlen = t->len;
			}
		}

		if (v != NULL) {
			buf = rspamd_fstring_new_init (v, vlen);
			hdr = rspamd_ftok_map (buf);
			buf = rspamd_fstring_new_init (s, len);
			new_name = rspamd_ftok_map (buf);

			rspamd_task_add_request_header (task, new_name, hdr);
		}

	}
	else {
		return luaL_error (L, "invalid arguments");
	}


	return 0;
}



gint
rspamd_lua_push_header (lua_State *L, struct rspamd_mime_header *rh,
						enum rspamd_lua_task_header_type how)
{
	LUA_TRACE_POINT;
	switch (how) {
	case RSPAMD_TASK_HEADER_PUSH_FULL:
		/* Create new associated table for a header */
		lua_createtable (L, 0, 7);
		rspamd_lua_table_set (L, "name",	 rh->name);

		if (rh->value) {
			rspamd_lua_table_set (L, "value", rh->value);
		}

		if (rh->raw_len > 0) {
			lua_pushstring (L, "raw");
			lua_pushlstring (L, rh->raw_value, rh->raw_len);
			lua_settable (L, -3);
		}

		if (rh->decoded) {
			rspamd_lua_table_set (L, "decoded", rh->decoded);
		}

		lua_pushstring (L, "tab_separated");
		lua_pushboolean (L, rh->flags & RSPAMD_HEADER_TAB_SEPARATED);
		lua_settable (L, -3);
		lua_pushstring (L, "empty_separator");
		lua_pushboolean (L, rh->flags & RSPAMD_HEADER_EMPTY_SEPARATOR);
		lua_settable (L, -3);
		rspamd_lua_table_set (L, "separator", rh->separator);
		lua_pushstring (L, "order");
		lua_pushinteger (L, rh->order);
		lua_settable (L, -3);
		break;
	case RSPAMD_TASK_HEADER_PUSH_RAW:
		if (rh->value) {
			lua_pushstring (L, rh->value);
		}
		else {
			lua_pushnil (L);
		}
		break;
	case RSPAMD_TASK_HEADER_PUSH_SIMPLE:
		if (rh->decoded) {
			lua_pushstring (L, rh->decoded);
		}
		else {
			lua_pushnil (L);
		}
		break;
	case RSPAMD_TASK_HEADER_PUSH_COUNT:
	default:
		g_assert_not_reached ();
		break;
	}

	return 1;
}

gint
rspamd_lua_push_header_array (lua_State *L,
							  const gchar *name,
							  struct rspamd_mime_header *rh,
							  enum rspamd_lua_task_header_type how,
							  gboolean strong)
{
	LUA_TRACE_POINT;
	struct rspamd_mime_header *cur;
	guint i;
	gint nret = 1;

	if (rh == NULL) {
		if (how == RSPAMD_TASK_HEADER_PUSH_HAS) {
			lua_pushboolean (L, false);
			nret = 1;
		}
		else if (how == RSPAMD_TASK_HEADER_PUSH_COUNT) {
			lua_pushnumber (L, 0);
		}
		else {
			lua_pushnil (L);
		}

		return nret;
	}

	if (how == RSPAMD_TASK_HEADER_PUSH_FULL) {
		lua_createtable (L, 0, 0);
		i = 0;

		DL_FOREACH (rh, cur) {
			if (!strong || strcmp (name, cur->name) == 0) {
				rspamd_lua_push_header (L, cur, how);
				lua_rawseti (L, -2, ++i);
			}
		}
	}
	else if (how == RSPAMD_TASK_HEADER_PUSH_COUNT) {
		i = 0;

		DL_FOREACH (rh, cur) {
			if (!strong || strcmp (name, cur->name) == 0) {
				i++;
			}
		}

		lua_pushinteger (L, i);
	}
	else if (how == RSPAMD_TASK_HEADER_PUSH_HAS) {
		nret = 1;
		bool found = false;

		if (strong) {
			/* We still have to check all headers in the chain */
			DL_FOREACH (rh, cur) {
				if (strcmp (name, cur->name) == 0) {
					found = true;
					break;
				}
			}
		}
		else {
			found = true;
		}

		lua_pushboolean (L, found);
	}
	else {
		DL_FOREACH (rh, cur) {
			if (!strong || strcmp (name, cur->name) == 0) {
				return rspamd_lua_push_header (L, cur, how);
			}
		}

		/* Not found with this case */
		lua_pushnil (L);
	}

	return nret;
}

static gint
lua_task_get_header_common (lua_State *L, enum rspamd_lua_task_header_type how)
{
	LUA_TRACE_POINT;
	gboolean strong = FALSE, need_modified = FALSE;
	struct rspamd_task *task = lua_check_task (L, 1);
	struct rspamd_mime_header *rh;
	const gchar *name;

	name = luaL_checkstring (L, 2);

	if (name && task) {
		if (lua_gettop (L) >= 3) {
			strong = lua_toboolean (L, 3);
			if (lua_isboolean (L, 4)) {
				need_modified = lua_toboolean (L, 4);
			}
		}


		rh = rspamd_message_get_header_array (task, name, need_modified);

		return rspamd_lua_push_header_array (L, name, rh, how, strong);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}
}

static gint
lua_task_get_header_full (lua_State * L)
{
	return lua_task_get_header_common (L, RSPAMD_TASK_HEADER_PUSH_FULL);
}

static gint
lua_task_get_header (lua_State * L)
{
	return lua_task_get_header_common (L, RSPAMD_TASK_HEADER_PUSH_SIMPLE);
}

static gint
lua_task_get_header_raw (lua_State * L)
{
	return lua_task_get_header_common (L, RSPAMD_TASK_HEADER_PUSH_RAW);
}

static gint
lua_task_get_header_count (lua_State * L)
{
	return lua_task_get_header_common (L, RSPAMD_TASK_HEADER_PUSH_COUNT);
}

static gint
lua_task_has_header (lua_State * L)
{
	return lua_task_get_header_common (L, RSPAMD_TASK_HEADER_PUSH_HAS);
}

static gint
lua_task_get_headers (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	bool need_modified = lua_isnoneornil(L, 2) ? false : lua_toboolean(L, 2);

	if (task && task->message) {
		struct rspamd_mime_header *cur;
		int i = 1;

		lua_createtable (L, rspamd_mime_headers_count(MESSAGE_FIELD(task, raw_headers)), 0);
		LL_FOREACH2(MESSAGE_FIELD(task, headers_order), cur, ord_next) {
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
lua_task_get_raw_headers (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	struct rspamd_lua_text *t;

	if (task && task->message) {
		t = lua_newuserdata (L, sizeof (*t));
		rspamd_lua_setclass (L, "rspamd{text}", -1);
		t->start = MESSAGE_FIELD (task, raw_headers_content).begin;
		t->len = MESSAGE_FIELD (task, raw_headers_content).len;
		t->flags = 0;
	}
	else {
		return luaL_error (L, "invalid arguments");
	}


	return 1;
}

static gint
lua_task_get_received_headers (lua_State * L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);

	if (task) {
		if (!task->message) {
			/* No message - no received */
			lua_newtable (L);
			return 1;
		}

		if (!lua_task_get_cached (L, task, "received")) {

			if (rspamd_received_export_to_lua(task, L)) {
				lua_task_set_cached (L, task, "received", -1);
			}
			else {
				/* no received, preserve compatibility */
				lua_newtable (L);
				return 1;
			}
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_task_get_queue_id (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);

	if (task) {
		if (task->queue_id != NULL && strcmp (task->queue_id, "undef") != 0) {
			lua_pushstring (L, task->queue_id);
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
lua_task_get_uid (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);

	if (task) {
		lua_pushstring (L, task->task_pool->tag.uid);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_task_get_resolver (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	struct rspamd_dns_resolver **presolver;

	if (task != NULL && task->resolver != NULL) {
		presolver = lua_newuserdata (L, sizeof (void *));
		rspamd_lua_setclass (L, "rspamd{resolver}", -1);
		*presolver = task->resolver;
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_task_set_resolver (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	struct rspamd_dns_resolver *resolver = lua_check_dns_resolver (L, 2);

	if (task != NULL && resolver != NULL) {
		task->resolver = resolver;
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 0;
}

static gint
lua_task_inc_dns_req (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	static guint warning_shown = 0;

	if (warning_shown < 100) {
		warning_shown ++;
		msg_warn_task_check ("task:inc_dns_req is deprecated and should not be used");
	}

	if (task != NULL) {
		/* Deprecation: already done in rspamd_dns_resolver_request */
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 0;
}

static gint
lua_task_get_dns_req (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);

	if (task != NULL) {
		lua_pushinteger (L, task->dns_requests);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

enum rspamd_address_type {
	RSPAMD_ADDRESS_ANY = 0u,
	RSPAMD_ADDRESS_SMTP = 1,
	RSPAMD_ADDRESS_MIME = 2,
	RSPAMD_ADDRESS_MASK = 0x3FF,
	RSPAMD_ADDRESS_RAW = (1u << 10),
	RSPAMD_ADDRESS_ORIGINAL = (1u << 11),
	RSPAMD_ADDRESS_MAX = RSPAMD_ADDRESS_MASK,
};

/*
 * Convert element at the specified position to the type
 * for get_from/get_recipients
 */
static enum rspamd_address_type
lua_task_str_to_get_type (lua_State *L, struct rspamd_task *task, gint pos)
{
	const gchar *type = NULL;
	gint ret = RSPAMD_ADDRESS_ANY;
	guint64 h;
	gsize sz;

	/* Get what value */

	if (lua_type (L, pos) == LUA_TNUMBER) {
		ret = lua_tonumber (L, pos);

		if (ret >= RSPAMD_ADDRESS_ANY && ret < RSPAMD_ADDRESS_MAX) {
			return ret;
		}

		return RSPAMD_ADDRESS_ANY;
	}
	else if (lua_type (L, pos) == LUA_TSTRING) {
		type = lua_tolstring (L, pos, &sz);

		if (type && sz > 0) {
			h = rspamd_cryptobox_fast_hash_specific (RSPAMD_CRYPTOBOX_XXHASH64,
					type, sz, 0xdeadbabe);

			switch (h) {
			case 0xDA081341FB600389ULL: /* mime */
				ret = RSPAMD_ADDRESS_MIME;
				break;
			case 0xEEC8A7832F8C43ACULL: /* any */
				ret = RSPAMD_ADDRESS_ANY;
				break;
			case 0x472274D5193B2A80ULL: /* smtp */
			case 0xEFE0F586CC9F14A9ULL: /* envelope */
				ret = RSPAMD_ADDRESS_SMTP;
				break;
			default:
				msg_err_task ("invalid email type: %*s", (gint)sz, type);
				break;
			}
		}
	}
	else if (lua_type (L, pos) == LUA_TTABLE) {
		for (lua_pushnil (L); lua_next (L, pos); lua_pop (L, 1)) {
			type = lua_tolstring (L, -1, &sz);

			if (type && sz > 0) {
				h = rspamd_cryptobox_fast_hash_specific (RSPAMD_CRYPTOBOX_XXHASH64,
						type, sz, 0xdeadbabe);

				switch (h) {
				case 0xDA081341FB600389ULL: /* mime */
					ret |= RSPAMD_ADDRESS_MIME;
					break;
				case 0xEEC8A7832F8C43ACULL: /* any */
					ret |= RSPAMD_ADDRESS_ANY;
					break;
				case 0x472274D5193B2A80ULL: /* smtp */
				case 0xEFE0F586CC9F14A9ULL: /* envelope */
					ret |= RSPAMD_ADDRESS_SMTP;
					break;
				case 0xAF4DE083D9AD0132: /* raw */
					ret |= RSPAMD_ADDRESS_RAW;
					break;
				case 0xC7AB6C7B7B0F5A8A: /* orig */
				case 0x1778AE905589E431: /* original */
					ret |= RSPAMD_ADDRESS_ORIGINAL;
					break;
				default:
					msg_err_task ("invalid email type: %*s", (gint)sz, type);
					break;
				}
			}
		}
	}

	return ret;
}

#define EMAIL_CHECK_FLAG(fl, str) do { \
	if (addr->flags & (fl)) { \
		lua_pushstring (L, (str)); \
		lua_pushboolean (L, true); \
		lua_settable (L, -3); \
	} \
} while(0)

static void
lua_push_email_address (lua_State *L, struct rspamd_email_address *addr)
{
	if (addr) {
		lua_createtable (L, 0, 5);

		if (addr->raw_len > 0) {
			lua_pushstring (L, "raw");
			lua_pushlstring (L, addr->raw, addr->raw_len);
			lua_settable (L, -3);
		}
		else {
			lua_pushstring (L, "raw");
			lua_pushstring (L, "");
			lua_settable (L, -3);
		}
		if (addr->addr_len > 0) {
			lua_pushstring (L, "addr");
			lua_pushlstring (L, addr->addr, addr->addr_len);
			lua_settable (L, -3);
		}
		else {
			lua_pushstring (L, "addr");
			lua_pushstring (L, "");
			lua_settable (L, -3);
		}
		if (addr->domain_len > 0) {
			lua_pushstring (L, "domain");
			lua_pushlstring (L, addr->domain, addr->domain_len);
			lua_settable (L, -3);
		}
		else {
			lua_pushstring (L, "domain");
			lua_pushstring (L, "");
			lua_settable (L, -3);
		}
		if (addr->user_len > 0) {
			lua_pushstring (L, "user");
			lua_pushlstring (L, addr->user, addr->user_len);
			lua_settable (L, -3);
		}
		else {
			lua_pushstring (L, "user");
			lua_pushstring (L, "");
			lua_settable (L, -3);
		}

		if (addr->name) {
			lua_pushstring (L, "name");
			lua_pushstring (L, addr->name);
			lua_settable (L, -3);
		}
		else {
			lua_pushstring (L, "name");
			lua_pushstring (L, "");
			lua_settable (L, -3);
		}

		lua_pushstring (L, "flags");
		lua_createtable (L, 0, 7);

		EMAIL_CHECK_FLAG (RSPAMD_EMAIL_ADDR_VALID, "valid");
		EMAIL_CHECK_FLAG (RSPAMD_EMAIL_ADDR_IP, "ip");
		EMAIL_CHECK_FLAG (RSPAMD_EMAIL_ADDR_BRACED, "braced");
		EMAIL_CHECK_FLAG (RSPAMD_EMAIL_ADDR_QUOTED, "quoted");
		EMAIL_CHECK_FLAG (RSPAMD_EMAIL_ADDR_EMPTY, "empty");
		EMAIL_CHECK_FLAG (RSPAMD_EMAIL_ADDR_HAS_BACKSLASH, "backslash");
		EMAIL_CHECK_FLAG (RSPAMD_EMAIL_ADDR_HAS_8BIT, "8bit");

		lua_settable (L, -3);
	}
}

void
lua_push_emails_address_list (lua_State *L, GPtrArray *addrs, int flags)
{
	struct rspamd_email_address *addr;
	guint i, pos = 1;

	lua_createtable (L, addrs->len, 0);

	for (i = 0; i < addrs->len; i ++) {
		addr = g_ptr_array_index (addrs, i);


		if (addr->flags & RSPAMD_EMAIL_ADDR_ORIGINAL) {
			if (flags & RSPAMD_ADDRESS_ORIGINAL) {
				lua_push_email_address (L, addr);
				lua_rawseti (L, -2, pos);
				pos++;
			}
		}
		else {
			lua_push_email_address (L, addr);
			lua_rawseti (L, -2, pos);
			pos++;
		}
	}
}

static gboolean
lua_import_email_address (lua_State *L, struct rspamd_task *task,
		gint pos,
		struct rspamd_email_address **paddr)
{
	struct rspamd_email_address *addr;
	const gchar *p;
	gchar *dst;
	gsize len;

	g_assert (paddr != NULL);

	if (!lua_istable (L, pos)) {
		return FALSE;
	}

	addr = g_malloc0 (sizeof (*addr));

	lua_pushstring (L, "name");
	lua_gettable (L, pos);

	if (lua_type (L, -1) == LUA_TSTRING) {
		p = lua_tolstring (L, -1, &len);
		dst = rspamd_mempool_alloc (task->task_pool, len + 1);
		rspamd_strlcpy (dst, p, len + 1);
		addr->name = dst;
	}

	lua_pop (L, 1);

	lua_pushstring (L, "user");
	lua_gettable (L, pos);

	if (lua_type (L, -1) == LUA_TSTRING) {
		p = lua_tolstring (L, -1, &len);
		addr->user = (const gchar *)rspamd_mempool_alloc (task->task_pool, len);
		memcpy ((gchar *)addr->user, p, len);
		addr->user_len = len;
	}

	lua_pop (L, 1);

	lua_pushstring (L, "domain");
	lua_gettable (L, pos);

	if (lua_type (L, -1) == LUA_TSTRING) {
		p = lua_tolstring (L, -1, &len);
		addr->domain = (const gchar *)rspamd_mempool_alloc (task->task_pool, len);
		memcpy ((gchar *)addr->domain, p, len);
		addr->domain_len = len;
	}

	lua_pop (L, 1);

	lua_pushstring (L, "addr");
	lua_gettable (L, pos);

	if (lua_type (L, -1) == LUA_TSTRING) {
		p = lua_tolstring (L, -1, &len);
		addr->addr = (const gchar *)rspamd_mempool_alloc (task->task_pool, len);
		memcpy ((gchar *)addr->addr, p, len);
		addr->addr_len = len;
	}
	else {
		/* Construct addr */
		len = addr->domain_len + addr->user_len + 1;
		addr->addr = (const gchar *)rspamd_mempool_alloc (task->task_pool, len);
		addr->addr_len = rspamd_snprintf ((gchar *)addr->addr, len, "%*s@%*s",
					(int)addr->user_len, addr->user,
					(int)addr->domain_len, addr->domain);
	}

	lua_pop (L, 1);

	lua_pushstring (L, "raw");
	lua_gettable (L, pos);

	if (lua_type (L, -1) == LUA_TSTRING) {
		gchar *cpy;
		p = lua_tolstring (L, -1, &len);
		cpy = rspamd_mempool_alloc (task->task_pool, len + 1);
		memcpy (cpy, p, len);
		cpy[len] = '\0';
		addr->raw_len = len;
		addr->raw = cpy;
	}
	else {
		/* Construct raw addr */
		len = addr->addr_len + 3;

		if (addr->name) {
			len += strlen (addr->name) + 1;
			dst = rspamd_mempool_alloc (task->task_pool, len + 1);

			addr->raw_len = rspamd_snprintf (dst, len, "%s <%*s>",
					addr->name,
					(int)addr->addr_len, addr->addr);

		}
		else {
			dst = rspamd_mempool_alloc (task->task_pool, len + 1);

			addr->raw_len = rspamd_snprintf (dst, len, "<%*s@%*s>",
					(int)addr->user_len, addr->user,
					(int)addr->domain_len, addr->domain);
		}

		addr->raw = dst;
	}

	lua_pop (L, 1);
	addr->flags = RSPAMD_EMAIL_ADDR_VALID;

	*paddr = addr;

	return TRUE;
}

static gint
lua_task_get_recipients (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	GPtrArray *ptrs = NULL;
	gint what = 0;

	if (task) {
		if (lua_gettop (L) == 2) {
			/* Get what value */
			what = lua_task_str_to_get_type (L, task, 2);
		}

		switch (what & RSPAMD_ADDRESS_MASK) {
		case RSPAMD_ADDRESS_SMTP:
			/* Here we check merely envelope rcpt */
			ptrs = task->rcpt_envelope;
			break;
		case RSPAMD_ADDRESS_MIME:
			/* Here we check merely mime rcpt */
			ptrs = MESSAGE_FIELD_CHECK (task, rcpt_mime);
			break;
		case RSPAMD_ADDRESS_ANY:
		default:
			if (task->rcpt_envelope) {
				ptrs = task->rcpt_envelope;
			}
			else {
				ptrs = MESSAGE_FIELD_CHECK (task, rcpt_mime);
			}
			break;
		}
		if (ptrs) {
			lua_push_emails_address_list (L, ptrs, what & ~RSPAMD_ADDRESS_MASK);
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
lua_task_set_recipients (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	GPtrArray *ptrs = NULL;
	struct rspamd_email_address *addr = NULL;
	gint what = 0, pos = 3;
	const gchar *how = "add";
	gboolean need_update_digest = FALSE;

	if (task && lua_gettop (L) >= 3) {

		/* Get what value */
		what = lua_task_str_to_get_type (L, task, 2);

		if (lua_isstring (L, 4)) {
			how = lua_tostring (L, 4);
		}

		switch (what) {
		case RSPAMD_ADDRESS_SMTP:
			/* Here we check merely envelope rcpt */
			ptrs = task->rcpt_envelope;
			break;
		case RSPAMD_ADDRESS_MIME:
			/* Here we check merely mime rcpt */
			ptrs = MESSAGE_FIELD_CHECK (task, rcpt_mime);
			need_update_digest = TRUE;
			break;
		case RSPAMD_ADDRESS_ANY:
		default:
			if (task->rcpt_envelope) {
				ptrs = task->rcpt_envelope;
			}
			else {
				ptrs = MESSAGE_FIELD_CHECK (task, rcpt_mime);
				need_update_digest = TRUE;
			}
			break;
		}
		if (ptrs) {
			guint i, flags_existing = RSPAMD_EMAIL_ADDR_ORIGINAL, flags_add = 0;
			struct rspamd_email_address *tmp;

			if (strcmp (how, "alias") == 0) {
				flags_add |= RSPAMD_EMAIL_ADDR_ALIASED;
			}
			else if (strcmp (how, "rewrite") == 0) {
				/* Clear old addresses */
				PTR_ARRAY_FOREACH (ptrs, i, tmp) {
					rspamd_email_address_free (addr);
				}

				g_ptr_array_set_size (ptrs, 0);
			}

			PTR_ARRAY_FOREACH (ptrs, i, tmp) {
				tmp->flags |= flags_existing;
			}

			lua_pushvalue (L, pos);

			for (lua_pushnil (L); lua_next (L, -2); lua_pop (L, 1)) {
				if (lua_import_email_address (L, task, lua_gettop (L), &addr)) {

					if (need_update_digest) {
						rspamd_message_update_digest (task->message,
								addr->addr, addr->addr_len);
					}

					addr->flags |= flags_add;
					g_ptr_array_add (ptrs, addr);
				}
			}

			lua_pop (L, 1);
			lua_pushboolean (L, true);
		}
		else {
			lua_pushboolean (L, false);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}


#define CHECK_EMAIL_ADDR(addr) do { \
	if (addr == NULL) { \
		ret = 0; \
	} \
	else { \
		ret = addr->flags & RSPAMD_EMAIL_ADDR_VALID; \
	} \
} while (0)

#define CHECK_EMAIL_ADDR_LIST(addr) do { \
	if (addr == NULL) { \
		ret = 0; \
	} \
	else { \
		ret = addr->len > 0; \
		nrcpt = addr->len; \
	} \
} while (0)

static gint
lua_task_has_from (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	gint what = 0, nrcpt = 0;
	gboolean ret = FALSE;

	if (task) {
		if (lua_gettop (L) == 2) {
			/* Get what value */
			what = lua_task_str_to_get_type (L, task, 2);
		}

		switch (what & RSPAMD_ADDRESS_MASK) {
		case RSPAMD_ADDRESS_SMTP:
			/* Here we check merely envelope rcpt */
			CHECK_EMAIL_ADDR (task->from_envelope);
			break;
		case RSPAMD_ADDRESS_MIME:
			/* Here we check merely mime rcpt */
			CHECK_EMAIL_ADDR_LIST (MESSAGE_FIELD_CHECK (task, from_mime));
			break;
		case RSPAMD_ADDRESS_ANY:
		default:
			CHECK_EMAIL_ADDR (task->from_envelope);

			if (!ret) {
				CHECK_EMAIL_ADDR_LIST (MESSAGE_FIELD_CHECK (task, from_mime));
			}
			break;
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	lua_pushboolean (L, ret);
	(void)nrcpt; /* Silence warning */

	return 1;
}

static gint
lua_task_has_recipients (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	gint what = 0, nrcpt = 0;
	gboolean ret = FALSE;

	if (task) {
		if (lua_gettop (L) == 2) {
			/* Get what value */
			what = lua_task_str_to_get_type (L, task, 2);
		}

		switch (what & RSPAMD_ADDRESS_MASK) {
		case RSPAMD_ADDRESS_SMTP:
			/* Here we check merely envelope rcpt */
			CHECK_EMAIL_ADDR_LIST (task->rcpt_envelope);
			break;
		case RSPAMD_ADDRESS_MIME:
			/* Here we check merely mime rcpt */
			CHECK_EMAIL_ADDR_LIST (MESSAGE_FIELD_CHECK (task, rcpt_mime));
			break;
		case RSPAMD_ADDRESS_ANY:
		default:
			CHECK_EMAIL_ADDR_LIST (task->rcpt_envelope);

			if (!ret) {
				CHECK_EMAIL_ADDR_LIST (MESSAGE_FIELD_CHECK (task, rcpt_mime));
			}
			break;
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	lua_pushboolean (L, ret);

	if (ret) {
		lua_pushinteger (L, nrcpt);
		return 2;
	}

	return 1;
}

static gint
lua_task_get_from (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	GPtrArray *addrs = NULL;
	struct rspamd_email_address *addr = NULL;
	gint what = 0;

	if (task) {
		if (lua_gettop (L) == 2) {
			/* Get what value */
			what = lua_task_str_to_get_type (L, task, 2);
		}

		switch (what & RSPAMD_ADDRESS_MASK) {
		case RSPAMD_ADDRESS_SMTP:
			/* Here we check merely envelope rcpt */
			addr = task->from_envelope;
			break;
		case RSPAMD_ADDRESS_MIME:
			/* Here we check merely mime rcpt */
			addrs = MESSAGE_FIELD_CHECK (task, from_mime);
			break;
		case RSPAMD_ADDRESS_ANY:
		default:
			if (task->from_envelope) {
				addr = task->from_envelope;
			}
			else {
				addrs = MESSAGE_FIELD_CHECK (task, from_mime);
			}
			break;
		}

		if (addrs && addrs->len > 0) {
			lua_push_emails_address_list (L, addrs, what & ~RSPAMD_ADDRESS_MASK);
		}
		else if (addr) {
			/* Create table to preserve compatibility */
			if (addr->addr) {
				lua_createtable (L, 1, 0);
				if (what & RSPAMD_ADDRESS_ORIGINAL) {
					if (task->from_envelope_orig) {
						lua_push_email_address (L, task->from_envelope_orig);
					}
					else {
						lua_push_email_address (L, addr);
					}
				}
				else {
					lua_push_email_address (L, addr);
				}

				lua_rawseti (L, -2, 1);
			}
			else {
				lua_pushnil (L);
			}
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
lua_task_set_from (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	const gchar *how = "rewrite";
	GPtrArray *addrs = NULL;
	struct rspamd_email_address **paddr = NULL, *addr;
	gboolean need_update_digest = FALSE;
	gint what = 0;

	if (task && lua_gettop (L) >= 3) {
		what = lua_task_str_to_get_type (L, task, 2);

		if (lua_isstring (L, 4)) {
			how = lua_tostring (L, 4);
		}

		switch (what & RSPAMD_ADDRESS_MASK) {
		case RSPAMD_ADDRESS_SMTP:
			/* Here we check merely envelope rcpt */
			paddr = &task->from_envelope;
			break;
		case RSPAMD_ADDRESS_MIME:
			/* Here we check merely mime rcpt */
			addrs = MESSAGE_FIELD_CHECK (task, from_mime);
			need_update_digest = TRUE;
			break;
		case RSPAMD_ADDRESS_ANY:
		default:
			if (task->from_envelope) {
				paddr = &task->from_envelope;
			}
			else {
				addrs = MESSAGE_FIELD_CHECK (task, from_mime);
				need_update_digest = TRUE;
			}
			break;
		}

		if (addrs) {
			if (lua_import_email_address (L, task, 3, &addr)) {
				guint i, flags_add = RSPAMD_EMAIL_ADDR_ORIGINAL;
				struct rspamd_email_address *tmp;

				if (strcmp (how, "alias") == 0) {
					flags_add |= RSPAMD_EMAIL_ADDR_ALIASED;
				}

				PTR_ARRAY_FOREACH (addrs, i, tmp) {
					tmp->flags |= flags_add;
				}

				if (need_update_digest) {
					rspamd_message_update_digest (task->message,
							addr->addr, addr->addr_len);
				}

				g_ptr_array_add (addrs, addr);
				lua_pushboolean (L, true);
			}
			else {
				lua_pushboolean (L, false);
			}
		}
		else if (paddr) {
			/* SMTP from case */
			if (lua_import_email_address (L, task, 3, &addr)) {
				task->from_envelope_orig = *paddr;
				task->from_envelope = addr;
				lua_pushboolean (L, true);
			}
			else {
				lua_pushboolean (L, false);
			}
		}
		else {
			lua_pushboolean (L, false);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_task_get_principal_recipient (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	const gchar *r;

	if (task) {
		r = rspamd_task_get_principal_recipient (task);
		if (r != NULL) {
			lua_pushstring (L, r);
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
lua_task_get_reply_sender (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	struct rspamd_mime_header *rh;

	if (task) {

		rh = rspamd_message_get_header_array (task, "Reply-To", FALSE);

		if (rh) {
			GPtrArray *addrs;

			addrs = rspamd_email_address_from_mime (task->task_pool, rh->decoded,
					strlen (rh->decoded), NULL, -1);

			if (addrs == NULL || addrs->len == 0) {
				lua_pushnil (L);
			}
			else {
				struct rspamd_email_address *addr;

				addr = (struct rspamd_email_address *)g_ptr_array_index (addrs, 0);
				lua_pushlstring (L, addr->addr, addr->addr_len);
			}
		}
		else if (MESSAGE_FIELD_CHECK (task, from_mime) &&
				MESSAGE_FIELD (task, from_mime)->len >= 1) {
			struct rspamd_email_address *addr;

			addr = (struct rspamd_email_address *)g_ptr_array_index (
					MESSAGE_FIELD (task, from_mime), 0);

			lua_pushlstring (L, addr->addr, addr->addr_len);
		}
		else if (task->from_envelope) {
			lua_pushlstring (L, task->from_envelope->addr,
					task->from_envelope->addr_len);
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
lua_task_get_user (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);

	if (task) {
		if (task->user != NULL) {
			lua_pushstring (L, task->user);
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
lua_task_set_user (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	const gchar *new_user;

	if (task) {

		if (lua_type (L, 2) == LUA_TSTRING) {
			new_user = lua_tostring (L, 2);

			if (task->user) {
				/* Push old user */
				lua_pushstring (L, task->user);
			}
			else {
				lua_pushnil (L);
			}

			task->user = rspamd_mempool_strdup (task->task_pool, new_user);
		}
		else {
			/* Reset user */
			if (task->user) {
				/* Push old user */
				lua_pushstring (L, task->user);
			}
			else {
				lua_pushnil (L);
			}

			task->user = NULL;
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_task_get_from_ip (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);

	if (task) {
		if (task->from_addr) {
			rspamd_lua_ip_push (L, task->from_addr);
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
lua_task_set_from_ip (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	rspamd_inet_addr_t *addr = NULL;

	if (!task) {
		return luaL_error (L, "no task");
	}
	else {
		if (lua_type (L, 2) == LUA_TSTRING) {
			gsize len;
			const gchar *ip_str = lua_tolstring (L, 2, &len);

			if (!rspamd_parse_inet_address (&addr,
					ip_str,
					len,
					RSPAMD_INET_ADDRESS_PARSE_DEFAULT)) {
				return luaL_error (L, "invalid IP string: %s", ip_str);
			}
			else {
				if (task->from_addr) {
					rspamd_inet_address_free (task->from_addr);
				}

				task->from_addr = addr;
			}
		}
		else if (lua_type (L, 2) == LUA_TUSERDATA) {
			struct rspamd_lua_ip *ip = lua_check_ip (L, 2);

			if (ip && ip->addr) {
				if (task->from_addr) {
					rspamd_inet_address_free (task->from_addr);
				}

				task->from_addr = rspamd_inet_address_copy (ip->addr);
			}
			else {
				return luaL_error (L, "invalid IP object");
			}
		}
		else {
			return luaL_error (L, "invalid IP argument type: %s", lua_typename (L,
					lua_type (L, 2)));
		}
	}

	return 0;
}

static gint
lua_task_get_from_ip_num (lua_State *L)
{
	LUA_TRACE_POINT;
	msg_err ("this function is deprecated and should no longer be used");
	lua_pushnil (L);
	return 1;
}

static gint
lua_task_get_client_ip (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);

	if (task) {
		if (task->client_addr) {
			rspamd_lua_ip_push (L, task->client_addr);
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
lua_task_get_helo (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);

	if (task) {
		if (task->helo != NULL) {
			lua_pushstring (L, task->helo);
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
lua_task_get_subject (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);

	if (task) {
		if (MESSAGE_FIELD_CHECK (task, subject) != NULL) {
			lua_pushstring (L, MESSAGE_FIELD (task, subject));
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
lua_task_set_helo (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	const gchar *new_helo;

	if (task) {
		new_helo = luaL_checkstring (L, 2);
		if (new_helo) {
			task->helo = rspamd_mempool_strdup (task->task_pool, new_helo);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 0;
}

static gint
lua_task_get_hostname (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);

	if (task) {
		if (task->hostname != NULL) {
			/* Check whether it looks like an IP address */
			if (*task->hostname == '[') {
				/*
				 * From the milter documentation:
				 *  If the reverse lookup fails or if none of the IP
				 *  addresses of the resolved host name matches the
				 *  original IP address, hostname will contain the
				 *  message sender's IP address enclosed in square
				 *  brackets (e.g. `[a.b.c.d]')
				 */
				lua_pushnil (L);
			}
			else {
				lua_pushstring (L, task->hostname);
			}
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
lua_task_set_hostname (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	const gchar *new_hostname;

	if (task) {
		new_hostname = luaL_checkstring (L, 2);
		if (new_hostname) {
			task->hostname = rspamd_mempool_strdup (task->task_pool,
					new_hostname);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 0;
}

static gint
lua_task_get_images (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	guint nelt = 0, i;
	struct rspamd_mime_part *part;
	struct rspamd_image **pimg;

	if (task) {
		if (task->message) {
			if (!lua_task_get_cached (L, task, "images")) {
				lua_createtable (L, MESSAGE_FIELD (task, parts)->len, 0);

				PTR_ARRAY_FOREACH (MESSAGE_FIELD (task, parts), i, part) {
					if (part->part_type == RSPAMD_MIME_PART_IMAGE) {
						pimg = lua_newuserdata (L, sizeof (struct rspamd_image *));
						rspamd_lua_setclass (L, "rspamd{image}", -1);
						*pimg = part->specific.img;
						lua_rawseti (L, -2, ++nelt);
					}
				}

				lua_task_set_cached (L, task, "images", -1);
			}
		}
		else {
			lua_newtable (L);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_task_get_archives (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	guint nelt = 0, i;
	struct rspamd_mime_part *part;
	struct rspamd_archive **parch;

	if (task) {
		if (task->message) {
			if (!lua_task_get_cached (L, task, "archives")) {
				lua_createtable (L, MESSAGE_FIELD (task, parts)->len, 0);

				PTR_ARRAY_FOREACH (MESSAGE_FIELD (task, parts), i, part) {
					if (part->part_type == RSPAMD_MIME_PART_ARCHIVE) {
						parch = lua_newuserdata (L, sizeof (struct rspamd_archive *));
						rspamd_lua_setclass (L, "rspamd{archive}", -1);
						*parch = part->specific.arch;
						lua_rawseti (L, -2, ++nelt);
					}
				}

				lua_task_set_cached (L, task, "archives", -1);
			}
		}
		else {
			lua_newtable (L);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_task_get_dkim_results (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	guint nelt = 0, i;
	struct rspamd_dkim_check_result **pres, **cur;

	if (task) {
		if (!lua_task_get_cached (L, task, "dkim_results")) {
			pres = rspamd_mempool_get_variable (task->task_pool,
					RSPAMD_MEMPOOL_DKIM_CHECK_RESULTS);

			if (pres == NULL) {
				lua_newtable (L);
			}
			else {
				for (cur = pres; *cur != NULL; cur ++) {
					nelt ++;
				}

				lua_createtable (L, nelt, 0);

				for (i = 0; i < nelt; i ++) {
					struct rspamd_dkim_check_result *res = pres[i];
					const gchar *result_str = "unknown";

					lua_createtable (L, 0, 4);

					switch (res->rcode) {
					case DKIM_CONTINUE:
						result_str = "allow";
						break;
					case DKIM_REJECT:
						result_str = "reject";
						break;
					case DKIM_TRYAGAIN:
						result_str = "tempfail";
						break;
					case DKIM_NOTFOUND:
						result_str = "not found";
						break;
					case DKIM_RECORD_ERROR:
						result_str = "bad record";
						break;
					case DKIM_PERM_ERROR:
						result_str = "permanent error";
						break;
					default:
						break;
					}

					rspamd_lua_table_set (L, "result", result_str);

					if (res->domain) {
						rspamd_lua_table_set (L, "domain", res->domain);
					}

					if (res->selector) {
						rspamd_lua_table_set (L, "selector", res->selector);
					}

					if (res->short_b) {
						rspamd_lua_table_set (L, "bhash", res->short_b);
					}

					if (res->fail_reason) {
						rspamd_lua_table_set (L, "fail_reason", res->fail_reason);
					}

					lua_rawseti (L, -2, i + 1);
				}
			}

			lua_task_set_cached (L, task, "dkim_results", -1);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static inline gboolean
lua_push_symbol_result (lua_State *L,
						struct rspamd_task *task,
						const gchar *symbol,
						struct rspamd_symbol_result *symbol_result,
						struct rspamd_scan_result *metric_res,
						gboolean add_metric,
						gboolean add_name)
{

	struct rspamd_symbol_result *s = NULL;
	struct rspamd_symbol_option *opt;
	struct rspamd_symbols_group *sym_group;
	guint i;
	gint j = 1, table_fields_cnt = 4;

	if (!metric_res) {
		metric_res = task->result;
	}

	if (!symbol_result) {
		s = rspamd_task_find_symbol_result (task, symbol, metric_res);
	}
	else {
		s = symbol_result;
	}

	if (s && !(s->flags & RSPAMD_SYMBOL_RESULT_IGNORED)) {
		if (add_metric) {
			table_fields_cnt++;
		}
		if (add_name) {
			table_fields_cnt++;
		}

		lua_createtable (L, 0, table_fields_cnt);

		if (add_name) {
			lua_pushstring (L, "name");
			lua_pushstring (L, symbol);
			lua_settable (L, -3);
		}
		lua_pushstring (L, "score");
		lua_pushnumber (L, s->score);
		lua_settable (L, -3);

		if (s->sym && s->sym->gr) {
			lua_pushstring (L, "group");
			lua_pushstring (L, s->sym->gr->name);
			lua_settable (L, -3);

			lua_pushstring (L, "groups");
			lua_createtable (L, s->sym->groups->len, 0);

			PTR_ARRAY_FOREACH (s->sym->groups, i, sym_group) {
				lua_pushstring (L, sym_group->name);
				lua_rawseti (L, -2, i + 1);
			}

			lua_settable (L, -3);
		}
		else {
			lua_pushstring (L, "group");
			lua_pushstring (L, "ungrouped");
			lua_settable (L, -3);
		}

		if (s->options) {
			lua_pushstring (L, "options");
			lua_createtable (L, kh_size (s->options), 0);

			DL_FOREACH (s->opts_head, opt) {
				lua_pushlstring (L, opt->option, opt->optlen);
				lua_rawseti (L, -2, j++);
			}

			lua_settable (L, -3);
		}

		return TRUE;
	}

	return FALSE;
}

static gint
lua_task_get_symbol (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	const gchar *symbol;
	gboolean found = FALSE;

	symbol = luaL_checkstring (L, 2);

	if (task && symbol) {
		struct rspamd_scan_result *sres = NULL;

		if (lua_isstring (L, 3)) {
			sres = rspamd_find_metric_result (task, lua_tostring (L, 3));

			if (sres == NULL) {
				return luaL_error (L, "invalid scan result: %s",
						lua_tostring (L, 3));
			}
		}

		/* Always push as a table for compatibility :( */
		lua_createtable (L, 1, 0);

		if ((found = lua_push_symbol_result (L, task, symbol,
				NULL, sres, TRUE, FALSE))) {
			lua_rawseti (L, -2, 1);
		}
		else {
			/* Pop table */
			lua_pop (L, 1);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	if (!found) {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_task_has_symbol (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	struct rspamd_symbol_result *s;
	const gchar *symbol;
	gboolean found = FALSE;

	symbol = luaL_checkstring (L, 2);

	if (task && symbol) {
		if (lua_isstring (L, 3)) {
			s = rspamd_task_find_symbol_result (task, symbol,
					rspamd_find_metric_result (task, lua_tostring (L, 3)));

			if (s && !(s->flags & RSPAMD_SYMBOL_RESULT_IGNORED)) {
				found = TRUE;
			}
		}
		else {
			s = rspamd_task_find_symbol_result (task, symbol, NULL);

			if (s && !(s->flags & RSPAMD_SYMBOL_RESULT_IGNORED)) {
				found = TRUE;
			}
		}
		lua_pushboolean (L, found);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_task_enable_symbol (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	const gchar *symbol;
	gboolean found = FALSE;

	symbol = luaL_checkstring (L, 2);

	if (task && symbol) {
		found = rspamd_symcache_enable_symbol (task, task->cfg->cache, symbol);
		lua_pushboolean (L, found);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_task_disable_symbol (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	const gchar *symbol;
	gboolean found = FALSE;

	symbol = luaL_checkstring (L, 2);

	if (task && symbol) {
		found = rspamd_symcache_disable_symbol (task, task->cfg->cache, symbol);
		lua_pushboolean (L, found);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_task_get_symbols (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	struct rspamd_scan_result *mres;
	gint i = 1;
	struct rspamd_symbol_result *s;

	if (task) {
		mres = task->result;

		if (lua_isstring (L, 2)) {
			mres = rspamd_find_metric_result (task, lua_tostring (L, 2));
		}

		if (mres) {
			lua_createtable (L, kh_size (mres->symbols), 0);
			lua_createtable (L, kh_size (mres->symbols), 0);

			kh_foreach_value (mres->symbols, s, {
				if (!(s->flags & RSPAMD_SYMBOL_RESULT_IGNORED)) {
					lua_pushstring (L, s->name);
					lua_rawseti (L, -3, i);
					lua_pushnumber (L, s->score);
					lua_rawseti (L, -2, i);
					i++;
				}
			});
		}
		else {
			lua_createtable (L, 0, 0);
			lua_createtable (L, 0, 0);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 2;
}

static gint
lua_task_get_symbols_all (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	struct rspamd_scan_result *mres;
	struct rspamd_symbol_result *s;
	gboolean found = FALSE;
	gint i = 1;

	if (task) {
		mres = task->result;

		if (lua_isstring (L, 2)) {
			mres = rspamd_find_metric_result (task, lua_tostring (L, 2));
		}

		if (mres) {
			found = TRUE;
			lua_createtable (L, kh_size (mres->symbols), 0);

			kh_foreach_value (mres->symbols, s, {
				if (!(s->flags & RSPAMD_SYMBOL_RESULT_IGNORED)) {
					lua_push_symbol_result (L, task, s->name, s, mres, FALSE, TRUE);
					lua_rawseti (L, -2, i++);
				}
			});
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	if (!found) {
		lua_pushnil (L);
	}

	return 1;
}


static gint
lua_task_get_symbols_numeric (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	struct rspamd_scan_result *mres;
	gint i = 1, id;
	struct rspamd_symbol_result *s;

	if (task) {
		mres = task->result;

		if (lua_isstring (L, 2)) {
			mres = rspamd_find_metric_result (task, lua_tostring (L, 2));
		}

		if (mres) {
			lua_createtable (L, kh_size (mres->symbols), 0);
			lua_createtable (L, kh_size (mres->symbols), 0);

			lua_createtable (L, kh_size (mres->symbols), 0);

			kh_foreach_value (mres->symbols, s, {
				if (!(s->flags & RSPAMD_SYMBOL_RESULT_IGNORED)) {
					id = rspamd_symcache_find_symbol (task->cfg->cache,
							s->name);
					lua_pushinteger (L, id);
					lua_rawseti (L, -3, i);
					lua_pushnumber (L, s->score);
					lua_rawseti (L, -2, i);
					i++;
				}
			});
		}
		else {
			lua_createtable (L, 0, 0);
			lua_createtable (L, 0, 0);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 2;
}

static gint
lua_task_get_groups (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	gboolean need_private;
	struct rspamd_scan_result *mres;
	struct rspamd_symbols_group *gr;
	gdouble gr_score;

	if (task) {
		mres = task->result;

		if (lua_isboolean (L, 2)) {
			need_private = lua_toboolean (L, 2);
		}
		else {
			need_private = !(task->cfg->public_groups_only);
		}

		if (lua_isstring (L, 3)) {
			mres = rspamd_find_metric_result (task, lua_tostring (L, 3));
		}

		if (mres == NULL) {
			lua_pushnil (L);

			return 1;
		}

		lua_createtable (L, 0, kh_size (mres->sym_groups));

		kh_foreach (mres->sym_groups, gr, gr_score, {
			if (!(gr->flags & RSPAMD_SYMBOL_GROUP_PUBLIC)) {
				if (!need_private) {
					continue;
				}
			}

			lua_pushnumber (L, gr_score);
			lua_setfield (L, -2, gr->name);
		});
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

struct tokens_foreach_cbdata {
	struct rspamd_task *task;
	lua_State *L;
	gint idx;
	gboolean normalize;
};

static void
tokens_foreach_cb (struct rspamd_symcache_item *item, gpointer ud)
{
	struct tokens_foreach_cbdata *cbd = ud;
	struct rspamd_symbol_result *s;
	gint flags;
	const gchar *sym;

	sym = rspamd_symcache_item_name (item);
	flags = rspamd_symcache_item_flags (item);

	if (flags & SYMBOL_TYPE_NOSTAT) {
		return;
	}

	if ((s = rspamd_task_find_symbol_result (cbd->task, sym, NULL)) != NULL) {
		if (s->flags & RSPAMD_SYMBOL_RESULT_IGNORED) {
			lua_pushnumber (cbd->L, 0.0);
		}
		else {
			if (cbd->normalize) {
				lua_pushnumber (cbd->L, tanh (s->score));
			}
			else {
				lua_pushnumber (cbd->L, s->score);
			}
		}
	}
	else {
		lua_pushnumber (cbd->L, 0.0);
	}

	lua_rawseti (cbd->L, -2, cbd->idx++);
}

static gint
lua_task_get_symbols_tokens (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	struct tokens_foreach_cbdata cbd;

	if (task) {
		cbd.task = task;
		cbd.L = L;
		cbd.idx = 1;
		cbd.normalize = TRUE;

		if (lua_type(L, 2) == LUA_TBOOLEAN) {
			cbd.normalize = lua_toboolean(L, 2);
		}
		else {
			cbd.normalize = TRUE;
		}

		lua_createtable(L,
				rspamd_symcache_stats_symbols_count(task->cfg->cache), 0);
		rspamd_symcache_foreach(task->cfg->cache, tokens_foreach_cb, &cbd);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	/* Return type is table created */
	return 1;
}

static gint
lua_task_process_ann_tokens (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	gint offset = luaL_checkinteger (L, 4);
	gdouble min_score = 0.0;

	if (task && lua_istable (L, 2) && lua_istable (L, 3)) {
		guint symlen = rspamd_lua_table_size (L, 2);
		if (lua_isnumber (L, 5)) {
			min_score = lua_tonumber (L, 5);
		}

		for (guint i = 1; i <= symlen; i ++, offset ++) {
			const gchar *sym;
			struct rspamd_symbol_result *sres;

			lua_rawgeti (L, 2, i);
			sym = lua_tostring (L, -1);

			/*
			 * TODO: this cycle involves one hash lookup per symbol in a profile
			 * Basically, in a common case that would be a table of all symbols
			 * So we need to do N_symbols hash lookups which is not optimal
			 * The optimal solution is to convert [sym1, sym2, ... symn] profile
			 * to a set {sym1 = true, sym2 = true, ...} and then for each
			 * resulting symbol check this table.
			 *
			 * That would lead to N_results lookups which is usually MUCH smaller
			 */
			sres = rspamd_task_find_symbol_result (task, sym, NULL);

			if (sres && !(sres->flags & RSPAMD_SYMBOL_RESULT_IGNORED)) {

				if (!isnan (sres->score) && !isinf (sres->score) &&
						(!sres->sym ||
							!(rspamd_symcache_item_flags (sres->sym->cache_item) & SYMBOL_TYPE_NOSTAT))) {

					gdouble norm_score;

					if (sres->sym && !isnan (sres->sym->score)) {
						if (sres->sym->score == 0) {

							if (sres->score == 0) {
								/* Binary symbol */
								norm_score = 1.0;
							}
							else {
								norm_score = fabs (tanh (sres->score));
							}
						}
						else {
							/* Get dynamic weight */
							norm_score = fabs (sres->score / sres->sym->score);

							if (norm_score > 1.0) {
								/* Multiple hits, we assume them as a single one */
								norm_score = 1.0;
							}
						}
					}
					else {
						norm_score = fabs (tanh (sres->score));
					}

					lua_pushnumber (L, MAX (min_score , norm_score));
					lua_rawseti (L, 3, offset + 1);
				}
			}

			lua_pop (L, 1); /* Symbol name */
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 0;
}

enum lua_date_type {
	DATE_CONNECT = 0,
	DATE_MESSAGE,
	DATE_INVALID
};

static enum lua_date_type
lua_task_detect_date_type (struct rspamd_task *task,
		lua_State *L, gint idx, gboolean *gmt)
{
	enum lua_date_type type = DATE_CONNECT;

	if (lua_type (L, idx) == LUA_TNUMBER) {
		gint num = lua_tonumber (L, idx);
		if (num >= DATE_CONNECT && num < DATE_INVALID) {
			return num;
		}
	}
	else if (lua_type (L, idx) == LUA_TTABLE) {
		const gchar *str;

		lua_pushvalue (L, idx);
		lua_pushstring (L, "format");
		lua_gettable (L, -2);

		str = lua_tostring (L, -1);

		if (str) {
			if (g_ascii_strcasecmp (str, "message") == 0) {
				type = DATE_MESSAGE;
			}
		}
		else {
			msg_warn_task ("date format has not been specified");
		}

		lua_pop (L, 1);

		lua_pushstring (L, "gmt");
		lua_gettable (L, -2);

		if (lua_type (L, -1) == LUA_TBOOLEAN) {
			*gmt = lua_toboolean (L, -1);
		}

		/* Value and table */
		lua_pop (L, 2);
	}

	return type;
}

static gint
lua_task_get_date (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	struct rspamd_mime_header *h;
	gdouble tim;
	enum lua_date_type type = DATE_CONNECT;
	gboolean gmt = TRUE;

	if (task != NULL) {
		if (lua_gettop (L) > 1) {
			type = lua_task_detect_date_type (task, L, 2, &gmt);
		}
		/* Get GMT date and store it to time_t */
		if (type == DATE_CONNECT) {
			tim = task->task_timestamp;

			if (!gmt) {
				struct tm t;
				time_t tt;

				tt = tim;
				rspamd_localtime (tt, &t);
#if !defined(__sun)
				t.tm_gmtoff = 0;
#endif
				t.tm_isdst = 0;
				/* Preserve fractional part as Lua is aware of it */
				tim = mktime (&t) + (tim - tt);
			}
		}
		else {
			h = rspamd_message_get_header_array(task, "Date", FALSE);

			if (h) {
				time_t tt;
				struct tm t;
				GError *err = NULL;

				tt = rspamd_parse_smtp_date (h->decoded, strlen (h->decoded),
						&err);

				if (err == NULL) {
					if (!gmt) {
						rspamd_localtime (tt, &t);
#if !defined(__sun)
						t.tm_gmtoff = 0;
#endif
						t.tm_isdst = 0;
						tim = mktime (&t);
					}
					else {
						tim = tt;
					}
				}
				else {
					g_error_free (err);
					tim = 0.0;
				}
			}
			else {
				tim = 0.0;
			}
		}

		lua_pushnumber (L, tim);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_task_get_message_id (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);

	if (task != NULL) {
		if (MESSAGE_FIELD_CHECK (task, message_id) != NULL) {
			lua_pushstring (L, MESSAGE_FIELD (task, message_id));
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
lua_task_get_timeval (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	struct timeval tv;

	if (task != NULL) {
		if (lua_isboolean (L, 2) && !!lua_toboolean (L, 2)) {
			lua_pushnumber (L, task->task_timestamp);
		}
		else {
			double_to_tv (task->task_timestamp, &tv);
			lua_createtable (L, 0, 2);
			lua_pushstring (L, "tv_sec");
			lua_pushinteger (L, (lua_Integer) tv.tv_sec);
			lua_settable (L, -3);
			lua_pushstring (L, "tv_usec");
			lua_pushinteger (L, (lua_Integer) tv.tv_usec);
			lua_settable (L, -3);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_task_get_scan_time (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	gboolean set = TRUE;

	if (task != NULL) {
		if (lua_isboolean (L, 2)) {
			set = lua_toboolean (L, 2);
		}

		rspamd_task_set_finish_time (task);
		gdouble diff = task->time_real_finish - task->task_timestamp;
		lua_pushnumber (L, diff);
		lua_pushnumber (L, diff);

		if (!set) {
			/* Reset to nan to allow further calcs in rspamd_task_set_finish_time */
			task->time_real_finish = NAN;
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 2;
}

static gint
lua_task_get_size (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);

	if (task != NULL) {
		lua_pushinteger (L, task->msg.len);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

/**
* - `no_log`: do not log task summary
* - `no_stat`: do not include task into scanned stats
* - `pass_all`: check all filters for task
* - `extended_urls`: output extended info about urls
* - `skip`: skip task processing
*/

#define LUA_TASK_FLAG_WRITE(flag, set) do { \
	task->flags = (set) ? (task->flags | (flag)) : (task->flags & ~(flag)); \
} while(0)

#define LUA_TASK_SET_FLAG(flag, strname, macro, set) do { \
	if (!found && strcmp ((flag), strname) == 0) { \
		LUA_TASK_FLAG_WRITE((macro), set); \
		found = TRUE; \
	} \
} while(0)

#define LUA_TASK_FLAG_READ(flag) do { \
	lua_pushboolean(L, !!(task->flags & (flag))); \
} while(0)

#define LUA_TASK_GET_FLAG(flag, strname, macro) do { \
	if (!found && strcmp ((flag), strname) == 0) { \
		LUA_TASK_FLAG_READ((macro)); \
		found = TRUE; \
	} \
} while(0)

#define LUA_TASK_PROTOCOL_FLAG_READ(flag) do { \
	lua_pushboolean(L, !!(task->protocol_flags & (flag))); \
} while(0)

#define LUA_TASK_GET_PROTOCOL_FLAG(flag, strname, macro) do { \
	if (!found && strcmp ((flag), strname) == 0) { \
		LUA_TASK_PROTOCOL_FLAG_READ((macro)); \
		found = TRUE; \
	} \
} while(0)

static gint
lua_task_set_flag (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	const gchar *flag = luaL_checkstring (L, 2);
	gboolean set = TRUE, found = FALSE;

	if (lua_gettop (L) >= 3) {
		set = lua_toboolean (L, 3);
	}

	if (task != NULL && flag != NULL) {
		LUA_TASK_SET_FLAG (flag, "pass_all", RSPAMD_TASK_FLAG_PASS_ALL, set);
		LUA_TASK_SET_FLAG (flag, "no_log", RSPAMD_TASK_FLAG_NO_LOG, set);
		LUA_TASK_SET_FLAG (flag, "no_stat", RSPAMD_TASK_FLAG_NO_STAT, set);
		LUA_TASK_SET_FLAG (flag, "skip", RSPAMD_TASK_FLAG_SKIP, set);
		LUA_TASK_SET_FLAG (flag, "learn_spam", RSPAMD_TASK_FLAG_LEARN_SPAM, set);
		LUA_TASK_SET_FLAG (flag, "learn_ham", RSPAMD_TASK_FLAG_LEARN_HAM, set);
		LUA_TASK_SET_FLAG (flag, "broken_headers",
				RSPAMD_TASK_FLAG_BROKEN_HEADERS, set);
		LUA_TASK_SET_FLAG (flag, "greylisted", RSPAMD_TASK_FLAG_GREYLISTED, set);
		LUA_TASK_SET_FLAG (flag, "skip_process", RSPAMD_TASK_FLAG_SKIP_PROCESS, set);
		LUA_TASK_SET_FLAG (flag, "message_rewrite", RSPAMD_TASK_FLAG_MESSAGE_REWRITE, set);

		if (!found) {
			msg_warn_task ("unknown flag requested: %s", flag);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 0;
}

static gint
lua_task_has_flag (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	const gchar *flag = luaL_checkstring (L, 2);
	gboolean found = FALSE;

	if (task != NULL && flag != NULL) {
		LUA_TASK_GET_FLAG (flag, "pass_all", RSPAMD_TASK_FLAG_PASS_ALL);
		LUA_TASK_GET_FLAG (flag, "no_log", RSPAMD_TASK_FLAG_NO_LOG);
		LUA_TASK_GET_FLAG (flag, "no_stat", RSPAMD_TASK_FLAG_NO_STAT);
		LUA_TASK_GET_FLAG (flag, "skip", RSPAMD_TASK_FLAG_SKIP);
		LUA_TASK_GET_FLAG (flag, "learn_spam", RSPAMD_TASK_FLAG_LEARN_SPAM);
		LUA_TASK_GET_FLAG (flag, "learn_ham", RSPAMD_TASK_FLAG_LEARN_HAM);
		LUA_TASK_GET_FLAG (flag, "greylisted", RSPAMD_TASK_FLAG_GREYLISTED);
		LUA_TASK_GET_FLAG (flag, "broken_headers",
				RSPAMD_TASK_FLAG_BROKEN_HEADERS);
		LUA_TASK_GET_FLAG (flag, "skip_process",
				RSPAMD_TASK_FLAG_SKIP_PROCESS);
		LUA_TASK_GET_FLAG (flag, "bad_unicode",
				RSPAMD_TASK_FLAG_BAD_UNICODE);
		LUA_TASK_GET_FLAG (flag, "mime",
				RSPAMD_TASK_FLAG_MIME);
		LUA_TASK_GET_FLAG (flag, "message_rewrite",
				RSPAMD_TASK_FLAG_MESSAGE_REWRITE);
		LUA_TASK_GET_PROTOCOL_FLAG (flag, "milter",
				RSPAMD_TASK_PROTOCOL_FLAG_MILTER);

		if (!found) {
			msg_warn_task ("unknown flag requested: %s", flag);
			lua_pushboolean (L, 0);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_task_get_flags (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	gint idx = 1;
	guint flags, bit, i;

	if (task) {
		lua_createtable (L, 8, 0);

		flags = task->flags;

		for (i = 0; i <= RSPAMD_TASK_FLAG_MAX_SHIFT; i ++) {
			bit = (1U << i);

			if (flags & bit) {
				switch (bit) {
				case RSPAMD_TASK_FLAG_PASS_ALL:
					lua_pushstring (L, "pass_all");
					lua_rawseti (L, -2, idx ++);
					break;
				case RSPAMD_TASK_FLAG_NO_LOG:
					lua_pushstring (L, "no_log");
					lua_rawseti (L, -2, idx++);
					break;
				case RSPAMD_TASK_FLAG_NO_STAT:
					lua_pushstring (L, "no_stat");
					lua_rawseti (L, -2, idx++);
					break;
				case RSPAMD_TASK_FLAG_SKIP:
					lua_pushstring (L, "skip");
					lua_rawseti (L, -2, idx++);
					break;
				case RSPAMD_TASK_FLAG_BROKEN_HEADERS:
					lua_pushstring (L, "broken_headers");
					lua_rawseti (L, -2, idx++);
					break;
				case RSPAMD_TASK_FLAG_LEARN_SPAM:
					lua_pushstring (L, "learn_spam");
					lua_rawseti (L, -2, idx++);
					break;
				case RSPAMD_TASK_FLAG_LEARN_HAM:
					lua_pushstring (L, "learn_ham");
					lua_rawseti (L, -2, idx++);
					break;
				case RSPAMD_TASK_FLAG_GREYLISTED:
					lua_pushstring (L, "greylisted");
					lua_rawseti (L, -2, idx++);
					break;
				case RSPAMD_TASK_FLAG_SKIP_PROCESS:
					lua_pushstring (L, "skip_process");
					lua_rawseti (L, -2, idx++);
					break;
				case RSPAMD_TASK_FLAG_MESSAGE_REWRITE:
					lua_pushstring (L, "message_rewrite");
					lua_rawseti (L, -2, idx++);
					break;
				default:
					break;
				}
			}
		}

		if (task->protocol_flags & RSPAMD_TASK_PROTOCOL_FLAG_MILTER) {
			lua_pushstring (L, "milter");
			lua_rawseti (L, -2, idx++);
		}
		if (task->protocol_flags & RSPAMD_TASK_PROTOCOL_FLAG_BODY_BLOCK) {
			lua_pushstring (L, "body_block");
			lua_rawseti (L, -2, idx++);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_task_get_digest (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	gchar hexbuf[sizeof(MESSAGE_FIELD (task, digest)) * 2 + 1];
	gint r;

	if (task) {
		if (task->message) {
			r = rspamd_encode_hex_buf (MESSAGE_FIELD (task, digest),
					sizeof (MESSAGE_FIELD (task, digest)),
					hexbuf, sizeof (hexbuf) - 1);

			if (r > 0) {
				hexbuf[r] = '\0';
				lua_pushstring (L, hexbuf);
			}
			else {
				lua_pushnil (L);
			}
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
lua_task_learn (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	gboolean is_spam = FALSE;
	const gchar *clname = NULL;
	GError *err = NULL;
	int ret = 1;

	if (task == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	is_spam = lua_toboolean(L, 2);
	if (lua_gettop (L) > 2) {
		clname = luaL_checkstring (L, 3);
	}

	if (!rspamd_learn_task_spam (task, is_spam, clname, &err)) {
		lua_pushboolean (L, FALSE);
		if (err != NULL) {
			lua_pushstring (L, err->message);
			ret = 2;
		}
	}
	else {
		lua_pushboolean (L, TRUE);
	}

	return ret;
}

static gint
lua_task_set_settings (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	ucl_object_t *settings;
	const ucl_object_t *act, *metric_elt, *vars, *cur;
	ucl_object_iter_t it = NULL;
	struct rspamd_scan_result *mres;
	guint i;

	settings = ucl_object_lua_import (L, 2);

	if (settings != NULL && task != NULL) {

		if (task->settings) {
			/* Do not allow to set settings on top of the existing ones */
			ucl_object_unref (settings);

			return luaL_error (L, "invalid invocation: settings has been already set");
		}

		metric_elt = ucl_object_lookup (settings, DEFAULT_METRIC);

		if (metric_elt) {
			task->settings = ucl_object_ref (metric_elt);
			ucl_object_unref (settings);
		}
		else {
			task->settings = settings;
		}

		act = ucl_object_lookup (task->settings, "actions");

		if (act && ucl_object_type (act) == UCL_OBJECT) {
			/* Adjust desired actions */
			mres = task->result;

			it = NULL;

			while ((cur = ucl_object_iterate (act, &it, true)) != NULL) {
				const gchar *act_name = ucl_object_key (cur);
				double act_score = ucl_object_type (cur) == UCL_NULL ?
						NAN : ucl_object_todouble (cur), old_score = NAN;
				int act_type;
				gboolean found = FALSE;

				if (!rspamd_action_from_str (act_name, &act_type)) {
					act_type = -1;
				}

				for (i = 0; i < mres->nactions; i++) {
					struct rspamd_action_result *act_res = &mres->actions_limits[i];

					if (act_res->action->action_type == METRIC_ACTION_CUSTOM &&
							act_type == -1) {
						/* Compare by name */
						if (g_ascii_strcasecmp (act_name, act_res->action->name) == 0) {
							old_score = act_res->cur_limit;
							act_res->cur_limit = act_score;
							found = TRUE;
							break;
						}
					}
					else {
						if (act_res->action->action_type == act_type) {
							old_score = act_res->cur_limit;
							act_res->cur_limit = act_score;
							found = TRUE;
							break;
						}
					}
				}

				if (!found) {

					if (!isnan (act_score)) {
						struct rspamd_action *new_act;

						HASH_FIND_STR (task->cfg->actions, act_name, new_act);

						if (new_act == NULL) {
							/* New action! */
							msg_info_task ("added new action %s with threshold %.2f "
										   "due to settings",
									act_name,
									act_score);
							new_act = rspamd_mempool_alloc0 (task->task_pool,
									sizeof (*new_act));
							new_act->name = rspamd_mempool_strdup (task->task_pool, act_name);
							new_act->action_type = METRIC_ACTION_CUSTOM;
							new_act->threshold = act_score;
						}
						else {
							/* A disabled action that is enabled */
							msg_info_task ("enabled disabled action %s with threshold %.2f "
										   "due to settings",
									act_name,
									act_score);
						}

						/* Insert it to the mres structure */
						gsize new_actions_cnt = mres->nactions + 1;
						struct rspamd_action_result *old_actions = mres->actions_limits;

						mres->actions_limits = rspamd_mempool_alloc (task->task_pool,
								sizeof (struct rspamd_action_result) * new_actions_cnt);
						memcpy (mres->actions_limits, old_actions,
								sizeof (struct rspamd_action_result) * mres->nactions);
						mres->actions_limits[mres->nactions].action = new_act;
						mres->actions_limits[mres->nactions].cur_limit = act_score;
						mres->nactions ++;
					}
					/* Disabled/missing action is disabled one more time, not an error */
				}
				else {
					if (isnan (act_score)) {
						msg_info_task ("disabled action %s due to settings",
								act_name);
					}
					else {
						msg_debug_task ("adjusted action %s: %.2f -> %.2f",
								act_name,
								old_score,
								act_score);
					}
				}
			}
		}

		vars = ucl_object_lookup (task->settings, "variables");
		if (vars && ucl_object_type (vars) == UCL_OBJECT) {
			/* Set memory pool variables */
			it = NULL;

			while ((cur = ucl_object_iterate (vars, &it, true)) != NULL) {
				if (ucl_object_type (cur) == UCL_STRING) {
					rspamd_mempool_set_variable (task->task_pool,
							ucl_object_key (cur), rspamd_mempool_strdup (
									task->task_pool,
									ucl_object_tostring (cur)
							), NULL);
				}
			}
		}

		rspamd_symcache_process_settings (task, task->cfg->cache);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 0;
}

static gint
lua_task_set_milter_reply (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	ucl_object_t *reply, *prev;

	reply = ucl_object_lua_import (L, 2);

	if (reply != NULL && task != NULL) {
		prev = rspamd_mempool_get_variable (task->task_pool,
				RSPAMD_MEMPOOL_MILTER_REPLY);

		if (prev) {
			/*
			 * We need to be very special about the add_headers part
			 * If we want to insert some existing object, such as
			 * add_headers = {
			 *   hdr = {value = val1, order = 1},
			 * }
			 *
			 * and new header has something similar:
			 * add_headers = {
			 *   hdr = {value = val2, order = 1},
			 * }
			 *
			 * then we need to convert it to an array...
			 *
			 * add_headers = {
			 *   hdr = [{value = val1, order = 1}, {value = val2, order = 1}],
			 * }
			 *
			 * UCL itself cannot do it directly. So the trick is to extract the
			 * original object, pack it into an array and then insert it back.
			 *
			 * I wish there was a simplier way to do it...
			 */
			const ucl_object_t *add_hdrs = ucl_object_lookup (prev, "add_headers");
			const ucl_object_t *nadd_hdrs = ucl_object_lookup (reply, "add_headers");

			if (add_hdrs && nadd_hdrs) {
				ucl_object_iter_t it = NULL;
				const ucl_object_t *cur;

				while ((cur = ucl_object_iterate (nadd_hdrs, &it, true)) != NULL) {
					gsize klen;
					const gchar *key = ucl_object_keyl (cur, &klen);
					const ucl_object_t *existing;

					existing = ucl_object_lookup_len (add_hdrs, key, klen);

					if (existing && ucl_object_type (existing) != UCL_ARRAY) {
						ucl_object_t *ar = ucl_object_typed_new (UCL_ARRAY);

						ucl_array_append (ar, ucl_object_ref (existing));
						ucl_object_replace_key ((ucl_object_t *)add_hdrs,
								ar, key, klen, false);
					}
				}
			}

			ucl_object_merge (prev, reply, false);
			ucl_object_unref (reply);
		}
		else {
			rspamd_mempool_set_variable (task->task_pool,
					RSPAMD_MEMPOOL_MILTER_REPLY,
					reply, (rspamd_mempool_destruct_t) ucl_object_unref);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 0;
}

static gint
lua_task_get_settings (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);

	if (task != NULL) {

		if (task->settings) {
			return ucl_object_push_lua (L, task->settings, true);
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
lua_task_lookup_settings (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	const gchar *key = NULL;
	const ucl_object_t *elt;

	if (task != NULL) {

		if (lua_isstring (L, 2)) {
			key = lua_tostring (L, 2);
		}

		if (task->settings) {
			if (key == NULL) {
				return ucl_object_push_lua (L, task->settings, true);
			}
			else {
				elt = ucl_object_lookup (task->settings, key);

				if (elt) {
					return ucl_object_push_lua (L, elt, true);
				}
				else {
					lua_pushnil (L);
				}
			}
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
lua_task_get_settings_id (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);

	if (task != NULL) {

		if (task->settings_elt) {
			lua_pushinteger (L, task->settings_elt->id);
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
lua_task_set_settings_id (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	guint32 id = lua_tointeger (L, 2);

	if (task != NULL && id != 0) {

		struct rspamd_config_settings_elt *selt =
				rspamd_config_find_settings_id_ref (task->cfg, id);

		if (selt == NULL) {
			return luaL_error (L, "settings id %f is unknown", (lua_Number)id);
		}
		if (task->settings_elt) {
			/* Overwrite existing settings from Lua */
			REF_RELEASE (task->settings_elt);
			lua_pushboolean (L, true);
		}
		else {
			lua_pushboolean (L, false);
		}

		task->settings_elt = selt;

	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_task_cache_get (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	const gchar *key = luaL_checkstring (L, 2);

	if (task && key) {
		if (!lua_task_get_cached (L, task, key)) {
			lua_pushnil (L);
		}
	}
	else {
		luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_task_cache_set (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	const gchar *key = luaL_checkstring (L, 2);

	if (task && key && lua_gettop (L) >= 3) {
		lua_task_set_cached (L, task, key, 3);
	}
	else {
		luaL_error (L, "invalid arguments");
	}

	return 0;
}

struct lua_file_cbdata {
	gchar *fname;
	gint fd;
	gboolean keep;
};

static void
lua_tmp_file_dtor (gpointer p)
{
	struct lua_file_cbdata *cbdata = p;

	if (!cbdata->keep) {
		unlink (cbdata->fname);
	}

	close (cbdata->fd);
}

static gint
lua_task_store_in_file (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	gboolean force_new = FALSE, keep = FALSE;
	gchar fpath[PATH_MAX];
	const gchar *tmpmask = NULL, *fname = NULL;
	guint mode = 00600;
	gint fd;
	struct lua_file_cbdata *cbdata;
	GError *err = NULL;

	if (task) {
		if (lua_istable (L, 2)) {
			if (!rspamd_lua_parse_table_arguments (L, 2, &err,
					RSPAMD_LUA_PARSE_ARGUMENTS_DEFAULT,
					"filename=S;tmpmask=S;mode=I;force_new=B;keep=B",
					&fname, &tmpmask, &mode, &force_new, &keep)) {
				msg_err_task ("cannot get parameters list: %e", err);

				if (err) {
					g_error_free (err);
				}

				return luaL_error (L, "invalid arguments");
			}
		}
		else if (lua_isnumber (L, 2)) {
			mode = lua_tointeger (L, 2);
		}

		if (!force_new && (task->flags & RSPAMD_TASK_FLAG_FILE) &&
				task->msg.fpath) {
			lua_pushstring (L, task->msg.fpath);
		}
		else {
			if (fname == NULL) {
				if (tmpmask == NULL) {
					rspamd_snprintf (fpath, sizeof (fpath), "%s%c%s",
							task->cfg->temp_dir,
							G_DIR_SEPARATOR, "rmsg-XXXXXXXXXX");
				}
				else {
					rspamd_snprintf (fpath, sizeof (fpath), "%s", tmpmask);
				}

				fd = g_mkstemp_full (fpath, O_WRONLY|O_CREAT|O_EXCL, mode);
				fname = fpath;

				if (fd != -1) {
					fchmod (fd, mode);
				}
			}
			else {
				fd = rspamd_file_xopen (fname, O_WRONLY|O_CREAT|O_EXCL,
						(guint)mode, FALSE);
			}

			if (fd == -1) {
				msg_err_task ("cannot save file: %s", strerror (errno));
				lua_pushnil (L);
			}
			else {
				if (write (fd, task->msg.begin, task->msg.len) == -1) {
					msg_err_task ("cannot write file %s: %s", fpath,
							strerror (errno));
					unlink (fname);
					close (fd);
					lua_pushnil (L);

					return 1;
				}

				cbdata = rspamd_mempool_alloc (task->task_pool, sizeof (*cbdata));
				cbdata->fd = fd;
				cbdata->fname = rspamd_mempool_strdup (task->task_pool, fname);
				cbdata->keep = keep;
				lua_pushstring (L, cbdata->fname);
				rspamd_mempool_add_destructor (task->task_pool,
						lua_tmp_file_dtor, cbdata);
			}
		}
	}
	else {
		luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_task_process_regexp (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	struct rspamd_lua_regexp *re = NULL;
	gboolean strong = FALSE;
	const gchar *type_str = NULL, *header_str = NULL;
	gsize header_len = 0;
	GError *err = NULL;
	gint ret = 0;
	enum rspamd_re_type type = RSPAMD_RE_BODY;

	/*
	 * - `re`* : regular expression object
 	 * - `type`*: type of regular expression:
	 *   + `mime`: mime regexp
	 *   + `rawmime`: raw mime regexp
	 *   + `header`: header regexp
	 *   + `rawheader`: raw header expression
	 *   + `body`: raw body regexp
	 *   + `url`: url regexp
	 * - `header`: for header and rawheader regexp means the name of header
	 * - `strong`: case sensitive match for headers
	 */
	if (task != NULL) {
		if (!rspamd_lua_parse_table_arguments (L, 2, &err,
				RSPAMD_LUA_PARSE_ARGUMENTS_DEFAULT,
				"*re=U{regexp};*type=S;header=V;strong=B",
				&re, &type_str, &header_len, &header_str,
				&strong)) {
			msg_err_task ("cannot get parameters list: %e", err);

			if (err) {
				g_error_free (err);
			}

			return luaL_error (L, "invalid arguments");
		}
		else {
			type = rspamd_re_cache_type_from_string (type_str);

			if ((type == RSPAMD_RE_HEADER || type == RSPAMD_RE_RAWHEADER)
					&& header_str == NULL) {
				msg_err_task (
						"header argument is mandatory for header/rawheader regexps");
			}
			else {
				ret = rspamd_re_cache_process (task, re->re, type,
						(gpointer) header_str, header_len, strong);
			}
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	lua_pushinteger (L, ret);

	return 1;
}

static gint
lua_task_get_metric_result (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	struct rspamd_scan_result *metric_res;
	struct rspamd_action *action;

	if (task) {
		metric_res = task->result;

		if (lua_isstring (L, 2)) {
			metric_res = rspamd_find_metric_result (task, lua_tostring (L, 2));

			if (metric_res == NULL) {
				lua_pushnil (L);

				return 1;
			}
		}

		/* Fields added:
		 * - `score`: current score
		 * - `action`: current action as a string
		 * - `nnegative`: number of negative rules matched
		 * - `npositive`: number of positive rules matched
		 * - `positive_score`: total score for positive rules
		 * - `negative_score`: total score for negative rules
		 * - `passthrough`: set to true if message has a passthrough result
		 */
		lua_createtable (L, 0, 7);

		lua_pushstring (L, "score");
		lua_pushnumber (L, metric_res->score);
		lua_settable (L, -3);

		action = rspamd_check_action_metric (task, NULL, metric_res);

		if (action) {
			lua_pushstring (L, "action");
			lua_pushstring (L, action->name);
			lua_settable (L, -3);
		}

		lua_pushstring (L, "nnegative");
		lua_pushnumber (L, metric_res->nnegative);
		lua_settable (L, -3);

		lua_pushstring (L, "npositive");
		lua_pushnumber (L, metric_res->npositive);
		lua_settable (L, -3);

		lua_pushstring (L, "positive_score");
		lua_pushnumber (L, metric_res->positive_score);
		lua_settable (L, -3);

		lua_pushstring (L, "negative_score");
		lua_pushnumber (L, metric_res->negative_score);
		lua_settable (L, -3);

		lua_pushstring (L, "passthrough");
		lua_pushboolean (L, !!(metric_res->passthrough_result != NULL));
		lua_settable (L, -3);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_task_get_metric_score (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	gdouble rs;
	struct rspamd_scan_result *metric_res;

	if (task) {
		metric_res = task->result;

		if (lua_isstring (L, 2)) {
			metric_res = rspamd_find_metric_result (task, lua_tostring (L, 2));
		}

		if (metric_res != NULL) {
			lua_createtable (L, 2, 0);
			lua_pushnumber (L, isnan (metric_res->score) ? 0.0 : metric_res->score);
			rs = rspamd_task_get_required_score (task, metric_res);
			lua_rawseti (L, -2, 1);
			lua_pushnumber (L, rs);
			lua_rawseti (L, -2, 2);
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
lua_task_get_metric_action (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	struct rspamd_action *action;

	if (task) {
		struct rspamd_scan_result *mres = task->result;

		if (lua_isstring (L, 2)) {
			mres = rspamd_find_metric_result (task, lua_tostring (L, 2));
		}

		if (mres == NULL) {
			lua_pushnil (L);

			return 1;
		}

		action = rspamd_check_action_metric (task, NULL, mres);
		lua_pushstring (L, action->name);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_task_set_metric_score (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	struct rspamd_scan_result *metric_res;
	gdouble nscore;

	if (lua_isnumber (L, 2)) {
		nscore = luaL_checknumber (L, 2);
	}
	else {
		nscore = luaL_checknumber (L, 3);
	}

	if (task) {
		metric_res = task->result;

		if (lua_isstring (L, 4)) {
			metric_res = rspamd_find_metric_result (task, lua_tostring (L, 4));
		}

		if (metric_res != NULL) {
			msg_debug_task ("set metric score from %.2f to %.2f",
				metric_res->score, nscore);
			metric_res->score = nscore;
			lua_pushboolean (L, true);
		}
		else {
			lua_pushboolean (L, false);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_task_disable_action (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	const gchar *action_name;
	struct rspamd_action_result *action_res;

	action_name = luaL_checkstring (L, 2);

	if (task && action_name) {

		for (guint i = 0; i < task->result->nactions; i ++) {
			action_res = &task->result->actions_limits[i];

			if (strcmp (action_name, action_res->action->name) == 0) {
				if (isnan (action_res->cur_limit)) {
					lua_pushboolean (L, false);
				}
				else {
					action_res->cur_limit = NAN;
					lua_pushboolean (L, true);
				}

				break;
			}
		}


	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_task_get_newlines_type (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);

	if (task) {
		if (task->message) {
			switch (MESSAGE_FIELD (task, nlines_type)) {
			case RSPAMD_TASK_NEWLINES_CR:
				lua_pushstring (L, "cr");
				break;
			case RSPAMD_TASK_NEWLINES_LF:
				lua_pushstring (L, "lf");
				break;
			case RSPAMD_TASK_NEWLINES_CRLF:
			default:
				lua_pushstring (L, "crlf");
				break;
			}
		}
		else {
			lua_pushstring (L, "crlf");
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static void
lua_push_stat_token (lua_State *L, rspamd_token_t *tok)
{
	gchar numbuf[64];

	/* Table values
	 * - `data`: 64 bit number encoded as a string
	 * - `t1`: the first token (if any)
	 * - `t2`: the second token (if any)
	 * - `win`: window index
	 * - `flag`: table of strings:
	 *    - `text`: text token
	 *    - `meta`: meta token
	 *    - `lua`: lua meta token
	 *    - `exception`: exception
	 *    - `subject`: subject token
	 *    - `unigram`: unigram token
	 */
	lua_createtable (L, 0, 5);

	rspamd_snprintf (numbuf, sizeof (numbuf), "%uL", tok->data);
	lua_pushstring (L, "data");
	lua_pushstring (L, numbuf);
	lua_settable (L, -3);

	if (tok->t1) {
		lua_pushstring (L, "t1");
		lua_pushlstring (L, tok->t1->stemmed.begin, tok->t1->stemmed.len);
		lua_settable (L, -3);
	}

	if (tok->t2) {
		lua_pushstring (L, "t2");
		lua_pushlstring (L, tok->t2->stemmed.begin, tok->t2->stemmed.len);
		lua_settable (L, -3);
	}

	lua_pushstring (L, "win");
	lua_pushinteger (L, tok->window_idx);
	lua_settable (L, -3);

	lua_pushstring (L, "flags");
	lua_createtable (L, 0, 5);

	/* Flags */
	{
		if (tok->flags & RSPAMD_STAT_TOKEN_FLAG_TEXT) {
			lua_pushstring (L, "text");
			lua_pushboolean (L, true);
			lua_settable (L, -3);
		}
		if (tok->flags & RSPAMD_STAT_TOKEN_FLAG_META) {
			lua_pushstring (L, "meta");
			lua_pushboolean (L, true);
			lua_settable (L, -3);
		}
		if (tok->flags & RSPAMD_STAT_TOKEN_FLAG_LUA_META) {
			lua_pushstring (L, "lua");
			lua_pushboolean (L, true);
			lua_settable (L, -3);
		}
		if (tok->flags & RSPAMD_STAT_TOKEN_FLAG_EXCEPTION) {
			lua_pushstring (L, "exception");
			lua_pushboolean (L, true);
			lua_settable (L, -3);
		}
		if (tok->flags & RSPAMD_STAT_TOKEN_FLAG_HEADER) {
			lua_pushstring (L, "header");
			lua_pushboolean (L, true);
			lua_settable (L, -3);
		}
	}
	lua_settable (L, -3);
}

static gint
lua_task_get_stat_tokens (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	guint i;
	rspamd_token_t *tok;

	if (task) {
		if (!task->tokens) {
			rspamd_stat_process_tokenize (NULL, task);
		}

		if (!task->tokens) {
			lua_pushnil (L);
		}
		else {
			lua_createtable (L, task->tokens->len, 0);

			PTR_ARRAY_FOREACH (task->tokens, i, tok) {
				lua_push_stat_token (L, tok);
				lua_rawseti (L, -2, i + 1);
			}
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_task_set_metric_subject (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	const gchar *subject;

	subject = luaL_checkstring (L, 2);

	if (task && subject) {
		rspamd_mempool_set_variable (task->task_pool, "metric_subject",
			rspamd_mempool_strdup(task->task_pool, subject), NULL);
		lua_pushboolean (L, true);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_task_get_protocol_reply (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	guint flags = 0;
	ucl_object_t *obj;

	if (!task) {
		return luaL_error (L, "invalid arguments");
	}

	if (!(task->processed_stages & (RSPAMD_TASK_STAGE_POST_FILTERS >> 1))) {
		return luaL_error (L, "must not be called before post-filters");
	}

	if (lua_istable (L, 2)) {
		for (lua_pushnil (L); lua_next (L, 2); lua_pop (L, 1)) {
			if (lua_isstring (L, -1)) {
				const gchar *str = lua_tostring (L, -1);

				if (strcmp (str, "default") == 0) {
					flags |= RSPAMD_PROTOCOL_DEFAULT;
				}
				else if (strcmp (str, "basic") == 0) {
					flags |= RSPAMD_PROTOCOL_BASIC;
				}
				else if (strcmp (str, "metrics") == 0) {
					flags |= RSPAMD_PROTOCOL_METRICS;
				}
				else if (strcmp (str, "messages") == 0) {
					flags |= RSPAMD_PROTOCOL_MESSAGES;
				}
				else if (strcmp (str, "rmilter") == 0) {
					flags |= RSPAMD_PROTOCOL_RMILTER;
				}
				else if (strcmp (str, "dkim") == 0) {
					flags |= RSPAMD_PROTOCOL_DKIM;
				}
				else if (strcmp (str, "extra") == 0) {
					flags |= RSPAMD_PROTOCOL_EXTRA;
				}
				else {
					msg_err_task ("invalid protocol flag: %s", str);
				}
			}
		}
	}
	else {
		flags = RSPAMD_PROTOCOL_DEFAULT;
	}

	obj = rspamd_protocol_write_ucl (task, flags);

	if (obj) {
		ucl_object_push_lua (L, obj, true);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_task_headers_foreach (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	enum rspamd_lua_task_header_type how = RSPAMD_TASK_HEADER_PUSH_SIMPLE;
	struct rspamd_lua_regexp *re = NULL;
	struct rspamd_mime_header *hdr, *cur;
	gint old_top;

	if (task && lua_isfunction (L, 2)) {
		if (task->message) {
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

			if (MESSAGE_FIELD (task, headers_order)) {
				hdr = MESSAGE_FIELD (task, headers_order);

				LL_FOREACH2 (hdr, cur, ord_next) {
					if (re && re->re) {
						if (!rspamd_regexp_match (re->re, cur->name,
								strlen (cur->name), FALSE)) {
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
		} /* if (task->message) */
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 0;
}

static gint
lua_task_modify_header (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task(L, 1);
	const gchar *hname = luaL_checkstring (L, 2);

	if (hname && task && lua_type (L, 3) == LUA_TTABLE) {
		if (task->message) {
			ucl_object_t *mods = ucl_object_lua_import(L, 3);

			rspamd_message_set_modified_header(task,
					MESSAGE_FIELD_CHECK (task, raw_headers), hname, mods);
			ucl_object_unref(mods);

			lua_pushboolean (L, true);
		}
		else {
			lua_pushboolean (L, false);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_task_get_meta_words (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	enum rspamd_lua_words_type how = RSPAMD_LUA_WORDS_STEM;

	if (task == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	if (task->meta_words == NULL) {
		lua_createtable (L, 0, 0);
	}
	else {
		if (lua_type (L, 2) == LUA_TSTRING) {
			const gchar *how_str = lua_tostring (L, 2);

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
			else {
				return luaL_error (L, "unknown words type: %s", how_str);
			}
		}

		return rspamd_lua_push_words (L, task->meta_words, how);
	}

	return 1;
}

static guint
lua_lookup_words_array (lua_State *L,
						gint cbpos,
						struct rspamd_task *task,
						struct rspamd_lua_map *map,
						GArray *words)
{
	rspamd_stat_token_t *tok;
	guint i, nmatched = 0;
	gint err_idx;
	gboolean matched;
	const gchar *key;
	gsize keylen;

	for (i = 0; i < words->len; i ++) {
		tok = &g_array_index (words, rspamd_stat_token_t, i);

		matched = FALSE;

		if (tok->normalized.len == 0) {
			continue;
		}

		key = tok->normalized.begin;
		keylen = tok->normalized.len;

		switch (map->type) {
		case RSPAMD_LUA_MAP_SET:
		case RSPAMD_LUA_MAP_HASH:
			/* We know that tok->normalized is zero terminated in fact */
			if (rspamd_match_hash_map (map->data.hash, key, keylen)) {
				matched = TRUE;
			}
			break;
		case RSPAMD_LUA_MAP_REGEXP:
		case RSPAMD_LUA_MAP_REGEXP_MULTIPLE:
			if (rspamd_match_regexp_map_single (map->data.re_map, key,
					keylen)) {
				matched = TRUE;
			}
			break;
		default:
			g_assert_not_reached ();
			break;
		}

		if (matched) {
			nmatched ++;

			lua_pushcfunction (L, &rspamd_lua_traceback);
			err_idx = lua_gettop (L);
			lua_pushvalue (L, cbpos); /* Function */
			rspamd_lua_push_full_word (L, tok);

			if (lua_pcall (L, 1, 0, err_idx) != 0) {
				msg_err_task ("cannot call callback function for lookup words: %s",
						lua_tostring (L, -1));
			}

			lua_settop (L, err_idx - 1);
		}
	}

	return nmatched;
}

static gint
lua_task_lookup_words (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	struct rspamd_lua_map *map = lua_check_map (L, 2);
	struct rspamd_mime_text_part *tp;

	guint i, matches = 0;

	if (task == NULL || map == NULL || task->message == NULL
		|| lua_type (L, 3) != LUA_TFUNCTION) {
		return luaL_error (L, "invalid arguments");
	}

	if (map->type != RSPAMD_LUA_MAP_SET &&
		map->type != RSPAMD_LUA_MAP_REGEXP &&
		map->type != RSPAMD_LUA_MAP_HASH &&
		map->type != RSPAMD_LUA_MAP_REGEXP_MULTIPLE) {
		return luaL_error (L, "invalid map type");
	}

	PTR_ARRAY_FOREACH (MESSAGE_FIELD (task, text_parts), i, tp) {
		if (tp->utf_words) {
			matches += lua_lookup_words_array (L, 3, task, map, tp->utf_words);
		}
	}

	if (task->meta_words) {
		matches += lua_lookup_words_array (L, 3, task, map, task->meta_words);
	}

	lua_pushinteger (L, matches);

	return 1;
}

static gint
lua_task_topointer (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);

	if (task) {
		/* XXX: this might cause issues on arm64 and LuaJIT */
		lua_pushlightuserdata (L, task);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_task_add_named_result (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);
	const gchar *name = luaL_checkstring (L, 2);
	gint cbref;

	if (task && name && lua_isfunction (L, 3)) {
		lua_pushvalue (L, 3);
		cbref = luaL_ref (L, LUA_REGISTRYINDEX);
		rspamd_create_metric_result (task, name, cbref);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 0;
}

static gint
lua_task_get_all_named_results (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_task *task = lua_check_task (L, 1);

	if (task) {
		gint n = 0;
		struct rspamd_scan_result *res;

		DL_COUNT (task->result, res, n);
		lua_createtable (L, n, 0);
		n = 1;

		DL_FOREACH (task->result, res) {
			if (res->name != NULL) {
				lua_pushstring (L, res->name);
			}
			else {
				lua_pushstring (L, DEFAULT_METRIC);
			}

			lua_rawseti (L, -2, n ++);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}


/* Image functions */
static gint
lua_image_get_width (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_image *img = lua_check_image (L);

	if (img != NULL) {
		lua_pushinteger (L, img->width);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_image_get_height (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_image *img = lua_check_image (L);

	if (img != NULL) {
		lua_pushinteger (L, img->height);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_image_get_type (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_image *img = lua_check_image (L);

	if (img != NULL) {
		lua_pushstring (L, rspamd_image_type_str (img->type));
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_image_get_size (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_image *img = lua_check_image (L);

	if (img != NULL) {
		lua_pushinteger (L, img->data->len);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_image_get_filename (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_image *img = lua_check_image (L);

	if (img != NULL) {
		if (img->filename != NULL) {
			lua_pushlstring (L, img->filename->begin, img->filename->len);
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

/* Arvhive methods */
static gint
lua_archive_get_type (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_archive *arch = lua_check_archive (L);

	if (arch != NULL) {
		lua_pushstring (L, rspamd_archive_type_str (arch->type));
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_archive_get_files (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_archive *arch = lua_check_archive (L);
	guint i, max_files = 0;
	struct rspamd_archive_file *f;

	if (arch != NULL) {
		if (lua_isnumber (L, 2)) {
			max_files = lua_tointeger (L, 2);
			max_files = MIN (arch->files->len, max_files);
		}
		else {
			max_files = arch->files->len;
		}

		lua_createtable (L, max_files, 0);

		for (i = 0; i < max_files; i ++) {
			f = g_ptr_array_index (arch->files, i);

			lua_pushlstring (L, f->fname->str, f->fname->len);
			lua_rawseti (L, -2, i + 1);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_archive_get_files_full (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_archive *arch = lua_check_archive (L);
	guint i, max_files = 0;
	struct rspamd_archive_file *f;

	if (arch != NULL) {
		if (lua_isnumber (L, 2)) {
			max_files = lua_tointeger (L, 2);
			max_files = MIN (arch->files->len, max_files);
		}
		else {
			max_files = arch->files->len;
		}

		lua_createtable (L, max_files, 0);

		for (i = 0; i < max_files; i ++) {
			f = g_ptr_array_index (arch->files, i);

			lua_createtable (L, 0, 4);

			lua_pushstring (L, "name");
			lua_pushlstring (L, f->fname->str, f->fname->len);
			lua_settable (L, -3);

			lua_pushstring (L, "compressed_size");
			lua_pushinteger (L, f->compressed_size);
			lua_settable (L, -3);

			lua_pushstring (L, "uncompressed_size");
			lua_pushinteger (L, f->uncompressed_size);
			lua_settable (L, -3);

			lua_pushstring (L, "encrypted");
			lua_pushboolean (L, (f->flags & RSPAMD_ARCHIVE_FILE_ENCRYPTED) ? true : false);
			lua_settable (L, -3);

			lua_rawseti (L, -2, i + 1);
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_archive_is_encrypted (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_archive *arch = lua_check_archive (L);

	if (arch != NULL) {
		lua_pushboolean (L, (arch->flags & RSPAMD_ARCHIVE_ENCRYPTED) ? true : false);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_archive_is_unreadable (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_archive *arch = lua_check_archive (L);

	if (arch != NULL) {
		lua_pushboolean (L, (arch->flags & RSPAMD_ARCHIVE_CANNOT_READ) ? true : false);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_archive_get_size (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_archive *arch = lua_check_archive (L);

	if (arch != NULL) {
		lua_pushinteger (L, arch->size);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_archive_get_filename (lua_State *L)
{
	LUA_TRACE_POINT;
	struct rspamd_archive *arch = lua_check_archive (L);

	if (arch != NULL) {
		lua_pushlstring (L, arch->archive_name->begin, arch->archive_name->len);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

/* Init part */

static gint
lua_load_task (lua_State * L)
{
	lua_newtable (L);
	luaL_register (L, NULL, tasklib_f);

	return 1;
}

static void
luaopen_archive (lua_State * L)
{
	rspamd_lua_new_class (L, "rspamd{archive}", archivelib_m);
	lua_pop (L, 1);
}

void
luaopen_task (lua_State * L)
{
	rspamd_lua_new_class (L, "rspamd{task}", tasklib_m);
	lua_pop (L, 1);

	rspamd_lua_add_preload (L, "rspamd_task", lua_load_task);

	luaopen_archive (L);
}

void
luaopen_image (lua_State * L)
{
	rspamd_lua_new_class (L, "rspamd{image}", imagelib_m);
	lua_pop (L, 1);
}

void
rspamd_lua_task_push (lua_State *L, struct rspamd_task *task)
{
	struct rspamd_task **ptask;

	ptask = lua_newuserdata (L, sizeof (gpointer));
	rspamd_lua_setclass (L, "rspamd{task}", -1);
	*ptask = task;
}
