/*
 * Copyright (c) 2009-2012, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
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
#include "expressions.h"
#include "protocol.h"
#include "filter.h"
#include "dns.h"
#include "util.h"
#include "images.h"
#include "cfg_file.h"
#include "statfile.h"
#include "tokenizers.h"
#include "classifiers.h"
#include "diff.h"

/***
 * @module rspamd_task
 * This module provides routines for tasks manipulation in rspamd. Tasks usually
 * represent messages being scanned, and this API provides access to such elements
 * as headers, symbols, metrics and so on and so forth. Normally, task objects
 * are passed to the lua callbacks allowing to check specific properties of messages
 * and add the corresponding symbols to the scan's results.
@example
rspamd_config.DATE_IN_PAST = function(task)
	if rspamd_config:get_api_version() >= 5 then
	local dm = task:get_date{format = 'message', gmt = true}
	local dt = task:get_date{format = 'connect', gmt = true}
		-- A day
		if dt - dm > 86400 then
			return true
		end
	end

	return false
end
 */

/* Task creation */
/***
 * @function rspamd_task.create_empty()
 * Creates new empty task object.
 * @return {rspamd_task} task object
 */
LUA_FUNCTION_DEF (task, create_empty);
/***
 * @function rspamd_task.create_from_buffer(input)
 * Creates new task object and load its content from the string provided.
 * @param {string} input string that contains MIME message
 * @return {rspamd_task} task object
 */
LUA_FUNCTION_DEF (task, create_from_buffer);
/* Task methods */
LUA_FUNCTION_DEF (task, get_message);
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
 * @method task:get_ev_base()
 * Return asynchronous event base for using in callbacks and resolver.
 * @return {rspamd_ev_base} event base
 */
LUA_FUNCTION_DEF (task, get_ev_base);
/***
 * @method task:insert_result(symbol, weigth[, option1, ...])
 * Insert specific symbol to the tasks scanning results assigning the initial
 * weight to it.
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
 * @method task:set_pre_results(action, description)
 * Sets pre-result for a task. It is used in pre-filters to specify early results
 * of the task scanned. If a pre-filter sets  some result, then further processing
 * may be skipped. For selecting action it is possible to use global table
 * `rspamd_actions` or a string value:
 *
 * - `reject`: reject message permanently
 * - `add header`: add spam header
 * - `rewrite subject`: rewrite subject to spam subject
 * - `greylist`: greylist message
 * @param {rspamd_action or string} action a numeric or string action value
 * @param {string} description optional descripton
@example
local function cb(task)
	local gr = task:get_header('Greylist')
	if gr and gr == 'greylist' then
		task:set_pre_result(rspamd_actions['greylist'], 'Greylisting required')
	end
end
 */
LUA_FUNCTION_DEF (task, set_pre_result);
/***
 * @method task:get_urls()
 * Get all URLs found in a message.
 * @return {table rspamd_url} list of all urls found
@example
local function phishing_cb(task)
	local urls = task:get_urls();

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
 * @method task:get_urls()
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
 * @method task:get_header(name[, case_sensitive])
 * Get decoded value of a header specified with optional case_sensitive flag.
 * By default headers are searched in caseless matter.
 * @param {string} name name of header to get
 * @param {boolean} case_sensitive case sensitiveness flag to search for a header
 * @return {string} decoded value of a header
 */
LUA_FUNCTION_DEF (task, get_header);
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
 * @method task:get_header_full(name[, case_sensitive])
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
LUA_FUNCTION_DEF (task, get_header_full);
/***
 * @method task:get_received_headers()
 * Returns a list of tables of parsed received headers. A tables returned have
 * the following structure:
 *
 * - `from_hostname` - string that represents hostname provided by a peer
 * - `from_ip` - string representation of IP address as provided by a peer
 * - `real_hostname` - hostname as resolved by MTA
 * - `real_ip` - string representation of IP as resolved by PTR request of MTA
 * - `by_hostname` - MTA hostname
 *
 * Please note that in some situations rspamd cannot parse all the fields of received headers.
 * In that case you should check all strings for validity.
 * @return {table of tables} list of received headers described above
 */
LUA_FUNCTION_DEF (task, get_received_headers);
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
 * @method task:inc_dns_req()
 * Increment number of DNS requests for the task. Is used just for logging purposes.
 */
LUA_FUNCTION_DEF (task, inc_dns_req);
/***
 * @method task:call_rspamd_function(function[, param, param...])
 * Calls rspamd expression function `func` with the specified parameters.
 * It returns the boolean result of function invocation.
 * @param {string} function name of internal or registered lua function to call
 * @param {list of strings} params parameters for a function
 * @return {bool} true or false returned by expression function
 */
LUA_FUNCTION_DEF (task, call_rspamd_function);
/***
 * @method task:get_recipients([type])
 * Return SMTP or MIME recipients for a task. This function returns list of internet addresses each one is a table with the following structure:
 *
 * - `name` - name of internet address in UTF8, e.g. for `Vsevolod Stakhov <blah@foo.com>` it returns `Vsevolod Stakhov`
 * - `addr` - address part of the address
 * - `user` - user part (if present) of the address, e.g. `blah`
 * - `domain` - domain part (if present), e.g. `foo.com`
 * @param {integer} type if specified has the following meaning: `0` means try SMTP recipients and fallback to MIME if failed, `1` means checking merely SMTP recipients and `2` means MIME recipients only
 * @return {list of addresses} list of recipients or `nil`
 */
LUA_FUNCTION_DEF (task, get_recipients);
/***
 * @method task:get_from([type])
 * Return SMTP or MIME sender for a task. This function returns list of internet addresses each one is a table with the following structure:
 *
 * - `name` - name of internet address in UTF8, e.g. for `Vsevolod Stakhov <blah@foo.com>` it returns `Vsevolod Stakhov`
 * - `addr` - address part of the address
 * - `user` - user part (if present) of the address, e.g. `blah`
 * - `domain` - domain part (if present), e.g. `foo.com`
 * @param {integer} type if specified has the following meaning: `0` means try SMTP sender and fallback to MIME if failed, `1` means checking merely SMTP sender and `2` means MIME `From:` only
 * @return {list of addresses} list of recipients or `nil`
 */
LUA_FUNCTION_DEF (task, get_from);
/***
 * @method task:get_user()
 * Returns authenticated user name for this task if specified by an MTA.
 * @return {string} username or nil
 */
LUA_FUNCTION_DEF (task, get_user);
LUA_FUNCTION_DEF (task, set_user);
/***
 * @method task:get_from_ip()
 * Returns [ip_addr](ip.md) object of a sender that is provided by MTA
 * @return {rspamd_ip} ip address object
 */
LUA_FUNCTION_DEF (task, get_from_ip);
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
 * @return {list of rspamd_image} images found in a message
 */
LUA_FUNCTION_DEF (task, get_images);
/***
 * @method task:get_symbol(name)
 * Searches for a symbol `name` in all metrics results and returns a list of tables
 * one per metric that describes the symbol inserted. Please note that this function
 * is intended to return values for **inserted** symbols, so if this symbol was not
 * inserted it won't be in the function's output. This method is useful for post-filters mainly.
 * The symbols are returned as the list of the following tables:
 *
 * - `metric` - name of metric
 * - `score` - score of a symbol in that metric
 * - `options` - a table of strings representing options of a symbol
 * @param {string} name symbol's name
 * @return {list of tables} list of tables or nil if symbol was not found in any metric
 */
LUA_FUNCTION_DEF (task, get_symbol);
/***
 * @method task:get_date(type[, gmt])
 * Returns timestamp for a connection or for a MIME message. This function can be called with a
 * single table arguments with the following fields:
 *
 * * `format` - a format of date returned:
 * 	- `message` - returns a mime date as integer (unix timestamp)
 * 	- `message_str` - returns a mime date as string (UTC format)
 * 	- `connect` - returns a unix timestamp of a connection to rspamd
 * 	- `connect_str` - returns connection time in UTC format
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
 * Returns message id of the specified task
 * @return {string} if of a message
 */
LUA_FUNCTION_DEF (task, get_message_id);
LUA_FUNCTION_DEF (task, get_timeval);
/***
 * @method task:get_metric_score(name)
 * Get the current score of metric `name`. Should be used in post-filters only.
 * @param {string} name name of a metric
 * @return {number} the current score of the metric
 */
LUA_FUNCTION_DEF (task, get_metric_score);
/***
 * @method task:get_metric_action(name)
 * Get the current action of metric `name`. Should be used in post-filters only.
 * @param {string} name name of a metric
 * @return {string} the current action of the metric as a string
 */
LUA_FUNCTION_DEF (task, get_metric_action);
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

static const struct luaL_reg tasklib_f[] = {
	LUA_INTERFACE_DEF (task, create_empty),
	LUA_INTERFACE_DEF (task, create_from_buffer),
	{NULL, NULL}
};

static const struct luaL_reg tasklib_m[] = {
	LUA_INTERFACE_DEF (task, get_message),
	LUA_INTERFACE_DEF (task, destroy),
	LUA_INTERFACE_DEF (task, process_message),
	LUA_INTERFACE_DEF (task, set_cfg),
	LUA_INTERFACE_DEF (task, get_cfg),
	LUA_INTERFACE_DEF (task, get_mempool),
	LUA_INTERFACE_DEF (task, get_session),
	LUA_INTERFACE_DEF (task, get_ev_base),
	LUA_INTERFACE_DEF (task, insert_result),
	LUA_INTERFACE_DEF (task, set_pre_result),
	LUA_INTERFACE_DEF (task, get_urls),
	LUA_INTERFACE_DEF (task, get_emails),
	LUA_INTERFACE_DEF (task, get_text_parts),
	LUA_INTERFACE_DEF (task, get_parts),
	LUA_INTERFACE_DEF (task, get_header),
	LUA_INTERFACE_DEF (task, get_header_raw),
	LUA_INTERFACE_DEF (task, get_header_full),
	LUA_INTERFACE_DEF (task, get_received_headers),
	LUA_INTERFACE_DEF (task, get_resolver),
	LUA_INTERFACE_DEF (task, inc_dns_req),
	LUA_INTERFACE_DEF (task, call_rspamd_function),
	LUA_INTERFACE_DEF (task, get_recipients),
	LUA_INTERFACE_DEF (task, get_from),
	LUA_INTERFACE_DEF (task, get_user),
	LUA_INTERFACE_DEF (task, set_user),
	LUA_INTERFACE_DEF (task, get_from_ip),
	LUA_INTERFACE_DEF (task, set_from_ip),
	LUA_INTERFACE_DEF (task, get_from_ip_num),
	LUA_INTERFACE_DEF (task, get_client_ip),
	LUA_INTERFACE_DEF (task, get_helo),
	LUA_INTERFACE_DEF (task, set_helo),
	LUA_INTERFACE_DEF (task, get_hostname),
	LUA_INTERFACE_DEF (task, set_hostname),
	LUA_INTERFACE_DEF (task, get_images),
	LUA_INTERFACE_DEF (task, get_symbol),
	LUA_INTERFACE_DEF (task, get_date),
	LUA_INTERFACE_DEF (task, get_message_id),
	LUA_INTERFACE_DEF (task, get_timeval),
	LUA_INTERFACE_DEF (task, get_metric_score),
	LUA_INTERFACE_DEF (task, get_metric_action),
	LUA_INTERFACE_DEF (task, learn),
	LUA_INTERFACE_DEF (task, set_settings),
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};

/* Textpart methods */
/***
 * @module rspamd_textpart
 * This module provides access to text parts found in a message
 */

/***
 * @method textpart:get_content()
 * Get parsed content of a part
 * @return {string} text contained in the part
 */
LUA_FUNCTION_DEF (textpart, get_content);
/***
 * @method textpart:get_length()
 * Get length of the text inside the part
 * @return {integer} the lenght of text part in bytes
 */
LUA_FUNCTION_DEF (textpart, get_length);
/***
 * @method textpart:is_empty()
 * Check whether a part is empty
 * @return {bool} `true` if a part is empty
 */
LUA_FUNCTION_DEF (textpart, is_empty);
/***
 * @method textpart:is_html()
 * Check whether a part contains HTML
 * @return {bool} `true` if a part html part
 */
LUA_FUNCTION_DEF (textpart, is_html);
/***
 * @method textpart:get_fuzzy()
 * Get fuzzy hash for a message
 * @return {string} fuzzy hash of the part
 */
LUA_FUNCTION_DEF (textpart, get_fuzzy);
/***
 * @method textpart:get_language()
 * Return short language code detected for the part
 * @return {string} language code for the part or nil if language has not been detected
 */
LUA_FUNCTION_DEF (textpart, get_language);
/***
 * @method textpart:compare_distance(part)
 * Compares two parts
 * @param {textpart} another text part
 * @return {number} similarity rate from 0.0 (different parts) to 1.0 (equal parts)
 */
LUA_FUNCTION_DEF (textpart, compare_distance);

static const struct luaL_reg textpartlib_m[] = {
	LUA_INTERFACE_DEF (textpart, get_content),
	LUA_INTERFACE_DEF (textpart, get_length),
	LUA_INTERFACE_DEF (textpart, is_empty),
	LUA_INTERFACE_DEF (textpart, is_html),
	LUA_INTERFACE_DEF (textpart, get_fuzzy),
	LUA_INTERFACE_DEF (textpart, get_language),
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
 * @method mimepart:get_header(name[, case_sensitive])
 * Get decoded value of a header specified with optional case_sensitive flag.
 * By default headers are searched in caseless matter.
 * @param {string} name name of header to get
 * @param {boolean} case_sensitive case sensitiveness flag to search for a header
 * @return {string} decoded value of a header
 */
LUA_FUNCTION_DEF (mimepart, get_header);
/***
 * @method mimepart:get_header_raw(name[, case_sensitive])
 * Get raw value of a header specified with optional case_sensitive flag.
 * By default headers are searched in caseless matter.
 * @param {string} name name of header to get
 * @param {boolean} case_sensitive case sensitiveness flag to search for a header
 * @return {string} raw value of a header
 */
LUA_FUNCTION_DEF (mimepart, get_header_raw);
/***
 * @method mimepart:get_header_full(name[, case_sensitive])
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
LUA_FUNCTION_DEF (mimepart, get_content);
LUA_FUNCTION_DEF (mimepart, get_length);
LUA_FUNCTION_DEF (mimepart, get_type);
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

/* URL methods */
LUA_FUNCTION_DEF (url, get_length);
LUA_FUNCTION_DEF (url, get_host);
LUA_FUNCTION_DEF (url, get_user);
LUA_FUNCTION_DEF (url, get_path);
LUA_FUNCTION_DEF (url, get_text);
LUA_FUNCTION_DEF (url, is_phished);
LUA_FUNCTION_DEF (url, get_phished);

static const struct luaL_reg urllib_m[] = {
	LUA_INTERFACE_DEF (url, get_length),
	LUA_INTERFACE_DEF (url, get_host),
	LUA_INTERFACE_DEF (url, get_user),
	LUA_INTERFACE_DEF (url, get_path),
	LUA_INTERFACE_DEF (url, get_text),
	LUA_INTERFACE_DEF (url, is_phished),
	LUA_INTERFACE_DEF (url, get_phished),
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};

/* Utility functions */
static struct rspamd_task *
lua_check_task (lua_State * L)
{
	void *ud = luaL_checkudata (L, 1, "rspamd{task}");
	luaL_argcheck (L, ud != NULL, 1, "'task' expected");
	return ud ? *((struct rspamd_task **)ud) : NULL;
}

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

static struct rspamd_image *
lua_check_image (lua_State * L)
{
	void *ud = luaL_checkudata (L, 1, "rspamd{image}");
	luaL_argcheck (L, ud != NULL, 1, "'image' expected");
	return ud ? *((struct rspamd_image **)ud) : NULL;
}

static struct uri *
lua_check_url (lua_State * L)
{
	void *ud = luaL_checkudata (L, 1, "rspamd{url}");
	luaL_argcheck (L, ud != NULL, 1, "'url' expected");
	return ud ? *((struct uri **)ud) : NULL;
}

static int
lua_task_create_empty (lua_State *L)
{
	struct rspamd_task **ptask, *task;

	task = rspamd_task_new (NULL);
	ptask = lua_newuserdata (L, sizeof (gpointer));
	rspamd_lua_setclass (L, "rspamd{task}", -1);
	*ptask = task;
	return 1;
}

static int
lua_task_create_from_buffer (lua_State *L)
{
	struct rspamd_task **ptask, *task;
	const gchar *data;
	size_t len;

	data = luaL_checklstring (L, 1, &len);
	if (data) {
		task = rspamd_task_new (NULL);
		ptask = lua_newuserdata (L, sizeof (gpointer));
		rspamd_lua_setclass (L, "rspamd{task}", -1);
		*ptask = task;
		task->msg = g_string_new_len (data, len);
	}
	return 1;
}

static int
lua_task_process_message (lua_State *L)
{
	struct rspamd_task *task = lua_check_task (L);

	if (task != NULL && task->msg != NULL && task->msg->len > 0) {
		if (process_message (task) == 0) {
			lua_pushboolean (L, TRUE);
		}
		else {
			lua_pushboolean (L, FALSE);
		}
	}
	else {
		lua_pushboolean (L, FALSE);
	}

	return 1;
}

static int
lua_task_get_cfg (lua_State *L)
{
	struct rspamd_task *task = lua_check_task (L);
	struct rspamd_config **pcfg;

	pcfg = lua_newuserdata (L, sizeof (gpointer));
	rspamd_lua_setclass (L, "rspamd{config}", -1);
	*pcfg = task->cfg;

	return 1;
}

static int
lua_task_set_cfg (lua_State *L)
{
	struct rspamd_task *task = lua_check_task (L);
	void *ud = luaL_checkudata (L, 2, "rspamd{config}");

	luaL_argcheck (L, ud != NULL, 1, "'config' expected");
	task->cfg = ud ? *((struct rspamd_config **)ud) : NULL;
	return 0;
}

static int
lua_task_destroy (lua_State *L)
{
	struct rspamd_task *task = lua_check_task (L);

	if (task != NULL) {
		rspamd_task_free (task, FALSE);
	}

	return 0;
}

static int
lua_task_get_message (lua_State * L)
{
	GMimeMessage **pmsg;
	struct rspamd_task *task = lua_check_task (L);

	if (task != NULL && task->message != NULL) {
		pmsg = lua_newuserdata (L, sizeof (GMimeMessage *));
		rspamd_lua_setclass (L, "rspamd{message}", -1);
		*pmsg = task->message;
	}
	else {
		lua_pushnil (L);
	}
	return 1;
}

static int
lua_task_get_mempool (lua_State * L)
{
	rspamd_mempool_t **ppool;
	struct rspamd_task *task = lua_check_task (L);

	if (task != NULL) {
		ppool = lua_newuserdata (L, sizeof (rspamd_mempool_t *));
		rspamd_lua_setclass (L, "rspamd{mempool}", -1);
		*ppool = task->task_pool;
	}
	else {
		lua_pushnil (L);
	}
	return 1;
}

static int
lua_task_get_session (lua_State * L)
{
	struct rspamd_async_session **psession;
	struct rspamd_task *task = lua_check_task (L);

	if (task != NULL) {
		psession = lua_newuserdata (L, sizeof (void *));
		rspamd_lua_setclass (L, "rspamd{session}", -1);
		*psession = task->s;
	}
	else {
		lua_pushnil (L);
	}
	return 1;
}

static int
lua_task_get_ev_base (lua_State * L)
{
	struct event_base **pbase;
	struct rspamd_task *task = lua_check_task (L);

	if (task != NULL) {
		pbase = lua_newuserdata (L, sizeof (struct event_base *));
		rspamd_lua_setclass (L, "rspamd{ev_base}", -1);
		*pbase = task->ev_base;
	}
	else {
		lua_pushnil (L);
	}
	return 1;
}

static gint
lua_task_insert_result (lua_State * L)
{
	struct rspamd_task *task = lua_check_task (L);
	const gchar *symbol_name, *param;
	double flag;
	GList *params = NULL;
	gint i, top;

	if (task != NULL) {
		symbol_name =
			rspamd_mempool_strdup (task->task_pool, luaL_checkstring (L, 2));
		flag = luaL_checknumber (L, 3);
		top = lua_gettop (L);
		/* Get additional options */
		for (i = 4; i <= top; i++) {
			param = luaL_checkstring (L, i);
			params =
				g_list_prepend (params,
					rspamd_mempool_strdup (task->task_pool, param));
		}

		rspamd_task_insert_result (task, symbol_name, flag, params);
	}
	return 0;
}

static gint
lua_task_set_pre_result (lua_State * L)
{
	struct rspamd_task *task = lua_check_task (L);
	struct metric_result *mres;
	gchar *action_str;
	gint action = METRIC_ACTION_MAX;

	if (task != NULL) {
		if (lua_type (L, 2) == LUA_TNUMBER) {
			action = lua_tointeger (L, 2);
		}
		else if (lua_type (L, 2) == LUA_TSTRING) {
			rspamd_action_from_str (lua_tostring (L, 2), &action);
		}
		if (action < (gint)task->pre_result.action &&
				action < METRIC_ACTION_MAX &&
				action >= METRIC_ACTION_REJECT) {
			/* We also need to set the default metric to that result */
			mres = rspamd_create_metric_result (task, DEFAULT_METRIC);
			if (mres != NULL) {
				mres->score = mres->metric->actions[action].score;
				mres->action = action;
			}
			task->pre_result.action = action;
			if (lua_gettop (L) >= 3) {
				action_str = rspamd_mempool_strdup (task->task_pool,
						luaL_checkstring (L, 3));
				task->pre_result.str = action_str;
				task->messages = g_list_prepend (task->messages, action_str);
			}
			else {
				task->pre_result.str = "unknown";
			}
			msg_info ("<%s>: set pre-result to %s: '%s'",
						task->message_id, rspamd_action_to_str (action),
						task->pre_result.str);
		}
	}
	return 0;
}

struct lua_tree_cb_data {
	lua_State *L;
	int i;
};

static gboolean
lua_tree_url_callback (gpointer key, gpointer value, gpointer ud)
{
	struct uri **purl;
	struct lua_tree_cb_data *cb = ud;

	purl = lua_newuserdata (cb->L, sizeof (struct uri *));
	rspamd_lua_setclass (cb->L, "rspamd{url}", -1);
	*purl = value;
	lua_rawseti (cb->L, -2, cb->i++);

	return FALSE;
}

static gint
lua_task_get_urls (lua_State * L)
{
	struct rspamd_task *task = lua_check_task (L);
	struct lua_tree_cb_data cb;

	if (task) {
		lua_newtable (L);
		cb.i = 1;
		cb.L = L;
		g_tree_foreach (task->urls, lua_tree_url_callback, &cb);
		return 1;
	}

	lua_pushnil (L);
	return 1;
}

static gint
lua_task_get_emails (lua_State * L)
{
	struct rspamd_task *task = lua_check_task (L);
	struct lua_tree_cb_data cb;

	if (task) {
		lua_newtable (L);
		cb.i = 1;
		cb.L = L;
		g_tree_foreach (task->emails, lua_tree_url_callback, &cb);
		return 1;
	}

	lua_pushnil (L);
	return 1;
}

static gint
lua_task_get_text_parts (lua_State * L)
{
	gint i = 1;
	struct rspamd_task *task = lua_check_task (L);
	GList *cur;
	struct mime_text_part *part, **ppart;

	if (task != NULL) {
		lua_newtable (L);
		cur = task->text_parts;
		while (cur) {
			part = cur->data;
			ppart = lua_newuserdata (L, sizeof (struct mime_text_part *));
			*ppart = part;
			rspamd_lua_setclass (L, "rspamd{textpart}", -1);
			/* Make it array */
			lua_rawseti (L, -2, i++);
			cur = g_list_next (cur);
		}
		return 1;
	}
	lua_pushnil (L);
	return 1;
}

static gint
lua_task_get_parts (lua_State * L)
{
	gint i = 1;
	struct rspamd_task *task = lua_check_task (L);
	GList *cur;
	struct mime_part *part, **ppart;

	if (task != NULL) {
		lua_newtable (L);
		cur = task->parts;
		while (cur) {
			part = cur->data;
			ppart = lua_newuserdata (L, sizeof (struct mime_part *));
			*ppart = part;
			rspamd_lua_setclass (L, "rspamd{mimepart}", -1);
			/* Make it array */
			lua_rawseti (L, -2, i++);
			cur = g_list_next (cur);
		}
		return 1;
	}
	lua_pushnil (L);
	return 1;
}


static gint
lua_push_header (lua_State * L,
		GHashTable *hdrs,
		const gchar *name,
		gboolean strong,
		gboolean full,
		gboolean raw)
{

	struct raw_header *rh;
	gint i = 1;
	const gchar *val;

	rh = g_hash_table_lookup (hdrs, name);

	if (rh == NULL) {
		lua_pushnil (L);
		return 1;
	}

	if (full) {
		lua_newtable (L);
	}

	while (rh) {
		if (rh->name == NULL) {
			rh = rh->next;
			continue;
		}
		/* Check case sensivity */
		if (strong) {
			if (strcmp (rh->name, name) != 0) {
				rh = rh->next;
				continue;
			}
		}
		if (full) {
			/* Create new associated table for a header */
			lua_newtable (L);
			rspamd_lua_table_set (L, "name",	 rh->name);
			if (rh->value) {
				rspamd_lua_table_set (L, "value", rh->value);
			}
			if (rh->decoded) {
				rspamd_lua_table_set (L, "decoded", rh->value);
			}
			lua_pushstring (L, "tab_separated");
			lua_pushboolean (L, rh->tab_separated);
			lua_settable (L, -3);
			lua_pushstring (L, "empty_separator");
			lua_pushboolean (L, rh->empty_separator);
			lua_settable (L, -3);
			rspamd_lua_table_set (L, "separator", rh->separator);
			lua_rawseti (L, -2, i++);
			/* Process next element */
			rh = rh->next;
		}
		else {
			if (raw) {
				val = rh->decoded;
			}
			else {
				val = rh->value;
			}
			if (val) {
				lua_pushstring (L, val);
			}
			else {
				lua_pushnil (L);
			}
			return 1;
		}
	}

	return 1;
}

static gint
lua_task_get_header_common (lua_State *L, gboolean full, gboolean raw)
{
	gboolean strong = FALSE;
	struct rspamd_task *task = lua_check_task (L);
	const gchar *name;

	name = luaL_checkstring (L, 2);

	if (name && task) {
		if (lua_gettop (L) == 3) {
			strong = lua_toboolean (L, 3);
		}
		return lua_push_header (L, task->raw_headers, name, strong, full, raw);
	}
	lua_pushnil (L);
	return 1;
}

static gint
lua_task_get_header_full (lua_State * L)
{
	return lua_task_get_header_common (L, TRUE, TRUE);
}

static gint
lua_task_get_header (lua_State * L)
{
	return lua_task_get_header_common (L, FALSE, FALSE);
}

static gint
lua_task_get_header_raw (lua_State * L)
{
	return lua_task_get_header_common (L, FALSE, TRUE);
}

static gint
lua_task_get_received_headers (lua_State * L)
{
	struct rspamd_task *task = lua_check_task (L);
	GList *cur;
	struct received_header *rh;
	gint i = 1;

	if (task) {
		lua_newtable (L);
		cur = g_list_first (task->received);
		while (cur) {
			rh = cur->data;
			if (rh->is_error || G_UNLIKELY (
					rh->from_ip == NULL &&
					rh->real_ip == NULL &&
					rh->real_hostname == NULL &&
					rh->by_hostname == NULL)) {
				cur = g_list_next (cur);
				continue;
			}
			lua_newtable (L);
			rspamd_lua_table_set (L, "from_hostname", rh->from_hostname);
			lua_pushstring (L, "from_ip");
			rspamd_lua_ip_push_fromstring (L, rh->from_ip);
			lua_settable (L, -3);
			rspamd_lua_table_set (L, "real_hostname", rh->real_hostname);
			lua_pushstring (L, "real_ip");
			rspamd_lua_ip_push_fromstring (L, rh->real_ip);
			lua_settable (L, -3);
			rspamd_lua_table_set (L, "by_hostname", rh->by_hostname);
			lua_rawseti (L, -2, i++);
			cur = g_list_next (cur);
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_task_get_resolver (lua_State *L)
{
	struct rspamd_task *task = lua_check_task (L);
	struct rspamd_dns_resolver **presolver;

	if (task != NULL && task->resolver != NULL) {
		presolver = lua_newuserdata (L, sizeof (void *));
		rspamd_lua_setclass (L, "rspamd{resolver}", -1);
		*presolver = task->resolver;
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_task_inc_dns_req (lua_State *L)
{
	struct rspamd_task *task = lua_check_task (L);

	if (task != NULL) {
		task->dns_requests++;
	}

	return 0;
}

static gint
lua_task_call_rspamd_function (lua_State * L)
{
	struct rspamd_task *task = lua_check_task (L);
	struct expression_function f;
	gint i, top;
	gboolean res;
	gchar *arg;

	if (task) {
		f.name = (gchar *)luaL_checkstring (L, 2);
		if (f.name) {
			f.args = NULL;
			top = lua_gettop (L);
			/* Get arguments after function name */
			for (i = 3; i <= top; i++) {
				arg = (gchar *)luaL_checkstring (L, i);
				if (arg != NULL) {
					f.args = g_list_prepend (f.args, arg);
				}
			}
			res = call_expression_function (&f, task, L);
			lua_pushboolean (L, res);
			if (f.args) {
				g_list_free (f.args);
			}

			return 1;
		}
	}

	lua_pushnil (L);

	return 1;

}



static gboolean
lua_push_internet_address (lua_State *L, InternetAddress *ia)
{
#ifndef GMIME24
	if (internet_address_get_type (ia) == INTERNET_ADDRESS_NAME) {
		lua_newtable (L);
		rspamd_lua_table_set (L, "name", internet_address_get_name (ia));
		rspamd_lua_table_set (L, "addr", internet_address_get_addr (ia));
		return TRUE;
	}
	return FALSE;
#else
	InternetAddressMailbox *iamb;
	const char *addr, *at;
	if (ia && INTERNET_ADDRESS_IS_MAILBOX (ia)) {
		lua_newtable (L);
		iamb = INTERNET_ADDRESS_MAILBOX (ia);
		addr = internet_address_mailbox_get_addr (iamb);
		if (addr) {
			rspamd_lua_table_set (L, "name", internet_address_get_name (ia));
			rspamd_lua_table_set (L, "addr", addr);
			/* Set optional fields */

			at = strchr (addr, '@');
			if (at != NULL) {
				lua_pushstring(L, "user");
				lua_pushlstring(L, addr, at - addr);
				lua_settable (L, -3);
				lua_pushstring(L, "domain");
				lua_pushstring(L, at + 1);
				lua_settable (L, -3);
			}
			return TRUE;
		}
	}

	return FALSE;
#endif
}

/*
 * Push internet addresses to lua as a table
 */
static void
lua_push_internet_address_list (lua_State *L, InternetAddressList *addrs)
{
	InternetAddress *ia;
	gint idx = 1;

#ifndef GMIME24
	/* Gmime 2.2 version */
	InternetAddressList *cur;

	lua_newtable (L);
	cur = addrs;
	while (cur) {
		ia = internet_address_list_get_address (cur);
		if (lua_push_internet_address (L, ia)) {
			lua_rawseti (L, -2, idx++);
		}
		cur = internet_address_list_next (cur);
	}
#else
	/* Gmime 2.4 version */
	gsize len, i;

	lua_newtable (L);
	if (addrs != NULL) {
		len = internet_address_list_length (addrs);
		for (i = 0; i < len; i++) {
			ia = internet_address_list_get_address (addrs, i);
			if (lua_push_internet_address (L, ia)) {
				lua_rawseti (L, -2, idx++);
			}
		}
	}
#endif
}

static gint
lua_task_get_recipients (lua_State *L)
{
	struct rspamd_task *task = lua_check_task (L);
	InternetAddressList *addrs;
	gint what = 0;

	if (task) {
		if (lua_gettop (L) == 2) {
			/* Get what value */
			what = lua_tonumber (L, 2);
		}

		switch (what) {
		case 1:
			/* Here we check merely envelope rcpt */
			addrs = task->rcpt_envelope;
			break;
		case 2:
			/* Here we check merely mime rcpt */
			addrs = task->rcpt_mime;
			break;
		case 0:
		default:
			if (task->rcpt_envelope) {
				addrs = task->rcpt_envelope;
			}
			else {
				addrs = task->rcpt_mime;
			}
			break;
		}

		if (addrs) {
			lua_push_internet_address_list (L, addrs);
		}
		else {
			lua_pushnil (L);
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_task_get_from (lua_State *L)
{
	struct rspamd_task *task = lua_check_task (L);
	InternetAddressList *addrs;
	gint what = 0;

	if (task) {
		if (lua_gettop (L) == 2) {
			/* Get what value */
			what = lua_tonumber (L, 2);
		}

		switch (what) {
		case 1:
			/* Here we check merely envelope rcpt */
			addrs = task->from_envelope;
			break;
		case 2:
			/* Here we check merely mime rcpt */
			addrs = task->from_mime;
			break;
		case 0:
		default:
			if (task->from_envelope) {
				addrs = task->from_envelope;
			}
			else {
				addrs = task->from_mime;
			}
			break;
		}

		if (addrs) {
			lua_push_internet_address_list (L, addrs);
		}
		else {
			lua_pushnil (L);
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_task_get_user (lua_State *L)
{
	struct rspamd_task *task = lua_check_task (L);

	if (task && task->user != NULL) {
		lua_pushstring (L, task->user);
		return 1;
	}

	lua_pushnil (L);
	return 1;
}

static gint
lua_task_set_user (lua_State *L)
{
	struct rspamd_task *task = lua_check_task (L);
	const gchar *new_user;

	if (task) {
		new_user = luaL_checkstring (L, 2);
		if (new_user) {
			task->user = rspamd_mempool_strdup (task->task_pool, new_user);
		}
	}

	return 0;
}

static gint
lua_task_get_from_ip (lua_State *L)
{
	struct rspamd_task *task = lua_check_task (L);

	if (task) {
		rspamd_lua_ip_push (L, &task->from_addr);
	}
	else {
		lua_pushnil (L);
	}
	return 1;
}

static gint
lua_task_set_from_ip (lua_State *L)
{

	msg_err ("this function is deprecated and should no longer be used");
	return 0;
}

static gint
lua_task_get_from_ip_num (lua_State *L)
{
	msg_err ("this function is deprecated and should no longer be used");
	lua_pushnil (L);
	return 1;
}

static gint
lua_task_get_client_ip (lua_State *L)
{
	struct rspamd_task *task = lua_check_task (L);

	if (task) {
		rspamd_lua_ip_push (L, &task->client_addr);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_task_get_helo (lua_State *L)
{
	struct rspamd_task *task = lua_check_task (L);

	if (task) {
		if (task->helo != NULL) {
			lua_pushstring (L, (gchar *)task->helo);
			return 1;
		}
	}

	lua_pushnil (L);
	return 1;
}

static gint
lua_task_set_helo (lua_State *L)
{
	struct rspamd_task *task = lua_check_task (L);
	const gchar *new_helo;

	if (task) {
		new_helo = luaL_checkstring (L, 2);
		if (new_helo) {
			task->helo = rspamd_mempool_strdup (task->task_pool, new_helo);
		}
	}

	return 0;
}

static gint
lua_task_get_hostname (lua_State *L)
{
	struct rspamd_task *task = lua_check_task (L);

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
				lua_pushstring (L, "unknown");
			}
			else {
				lua_pushstring (L, task->hostname);
			}
			return 1;
		}
	}

	lua_pushnil (L);
	return 1;
}

static gint
lua_task_set_hostname (lua_State *L)
{
	struct rspamd_task *task = lua_check_task (L);
	const gchar *new_hostname;

	if (task) {
		new_hostname = luaL_checkstring (L, 2);
		if (new_hostname) {
			task->hostname = rspamd_mempool_strdup (task->task_pool,
					new_hostname);
		}
	}

	return 0;
}

static gint
lua_task_get_images (lua_State *L)
{
	struct rspamd_task *task = lua_check_task (L);
	gint i = 1;
	GList *cur;
	struct rspamd_image **pimg;

	if (task) {
		cur = task->images;
		if (cur != NULL) {
			lua_newtable (L);
			while (cur) {
				pimg = lua_newuserdata (L, sizeof (struct rspamd_image *));
				rspamd_lua_setclass (L, "rspamd{image}", -1);
				*pimg = cur->data;
				lua_rawseti (L, -2, i++);
				cur = g_list_next (cur);
			}
			return 1;
		}
	}

	lua_pushnil (L);
	return 1;
}

static inline gboolean
lua_push_symbol_result (lua_State *L,
	struct rspamd_task *task,
	struct metric *metric,
	const gchar *symbol)
{
	struct metric_result *metric_res;
	struct symbol *s;
	gint j;
	GList *opt;

	metric_res = g_hash_table_lookup (task->results, metric->name);
	if (metric_res) {
		if ((s = g_hash_table_lookup (metric_res->symbols, symbol)) != NULL) {
			j = 0;
			lua_newtable (L);
			lua_pushstring (L, "metric");
			lua_pushstring (L, metric->name);
			lua_settable (L, -3);
			lua_pushstring (L, "score");
			lua_pushnumber (L, s->score);
			lua_settable (L, -3);
			if (s->options) {
				opt = s->options;
				lua_pushstring (L, "options");
				lua_newtable (L);
				while (opt) {
					lua_pushstring (L, opt->data);
					lua_rawseti (L, -2, j++);
					opt = g_list_next (opt);
				}
				lua_settable (L, -3);
			}

			return TRUE;
		}
	}

	return FALSE;
}

static gint
lua_task_get_symbol (lua_State *L)
{
	struct rspamd_task *task = lua_check_task (L);
	const gchar *symbol;
	struct metric *metric;
	GList *cur = NULL, *metric_list;
	gboolean found = FALSE;
	gint i = 1;

	symbol = luaL_checkstring (L, 2);

	if (task && symbol) {
		metric_list = g_hash_table_lookup (task->cfg->metrics_symbols, symbol);
		if (metric_list) {
			lua_newtable (L);
			cur = metric_list;
		}
		else {
			metric = task->cfg->default_metric;
		}

		if (!cur && metric) {
			if ((found = lua_push_symbol_result (L, task, metric, symbol))) {
				lua_newtable (L);
				lua_rawseti (L, -2, i++);
			}
		}
		else {
			while (cur) {
				metric = cur->data;
				if (lua_push_symbol_result (L, task, metric, symbol)) {
					lua_rawseti (L, -2, i++);
					found = TRUE;
				}
				cur = g_list_next (cur);
			}
		}
	}

	if (!found) {
		lua_pushnil (L);
	}
	return 1;
}

enum lua_date_type {
	DATE_CONNECT = 0,
	DATE_MESSAGE,
	DATE_CONNECT_STRING,
	DATE_MESSAGE_STRING
};

static enum lua_date_type
lua_task_detect_date_type (lua_State *L, gint idx, gboolean *gmt)
{
	enum lua_date_type type = DATE_CONNECT;

	if (lua_type (L, idx) == LUA_TNUMBER) {
		gint num = lua_tonumber (L, idx);
		if (num >= DATE_CONNECT && num <= DATE_MESSAGE_STRING) {
			return num;
		}
	}
	else if (lua_type (L, idx) == LUA_TTABLE) {
		const gchar *str;

		lua_pushvalue (L, idx);
		lua_pushstring (L, "format");
		lua_gettable (L, -2);
		str = lua_tostring (L, -1);
		if (g_ascii_strcasecmp (str, "message") == 0) {
			type = DATE_MESSAGE;
		}
		else if (g_ascii_strcasecmp (str, "connect_str") == 0) {
			type = DATE_CONNECT_STRING;
		}
		else if (g_ascii_strcasecmp (str, "message_str") == 0) {
			type = DATE_MESSAGE_STRING;
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
	struct rspamd_task *task = lua_check_task (L);
	gdouble tim;
	enum lua_date_type type = DATE_CONNECT;
	gboolean gmt = TRUE;

	if (task != NULL) {
		if (lua_gettop (L) > 1) {
			type = lua_task_detect_date_type (L, 2, &gmt);
		}
		/* Get GMT date and store it to time_t */
		if (type == DATE_CONNECT || type == DATE_CONNECT_STRING) {
			tim = (tv_to_msec (&task->tv)) / 1000.;

			if (!gmt) {
				struct tm t;
				time_t tt;

				tt = tim;
				localtime_r (&tt, &t);
#if !defined(__sun)
				t.tm_gmtoff = 0;
#endif
				t.tm_isdst = 0;
				tim = mktime (&t);
			}
		}
		else {
			if (task->message) {
				time_t tt;
				gint offset;
				g_mime_message_get_date (task->message, &tt, &offset);

				if (!gmt) {
					tt += (offset * 60 * 60) / 100 + (offset * 60 * 60) % 100;
				}
				tim = tt;
			}
			else {
				tim = 0.0;
			}
		}
		if (type == DATE_CONNECT || type == DATE_MESSAGE) {
			lua_pushnumber (L, tim);
		}
		else {
			GTimeVal tv;
			gchar *out;

			double_to_tv (tim, &tv);
			out = g_time_val_to_iso8601 (&tv);
			lua_pushstring (L, out);
			g_free (out);
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_task_get_message_id (lua_State *L)
{
	struct rspamd_task *task = lua_check_task (L);

	if (task != NULL && task->message_id != NULL) {
		lua_pushstring (L, task->message_id);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_task_get_timeval (lua_State *L)
{
	struct rspamd_task *task = lua_check_task (L);

	if (task != NULL) {
		lua_newtable (L);
		lua_pushstring (L, "tv_sec");
		lua_pushnumber (L, (lua_Number)task->tv.tv_sec);
		lua_settable (L, -3);
		lua_pushstring (L, "tv_usec");
		lua_pushnumber (L, (lua_Number)task->tv.tv_usec);
		lua_settable (L, -3);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}


static gint
lua_task_learn (lua_State *L)
{
	struct rspamd_task *task = lua_check_task (L);
	gboolean is_spam = FALSE;
	const gchar *clname;
	struct rspamd_classifier_config *cl;
	GError *err = NULL;
	int ret = 1;

	is_spam = lua_toboolean(L, 2);
	if (lua_gettop (L) > 2) {
		clname = luaL_checkstring (L, 3);
	}
	else {
		clname = "bayes";
	}

	cl = rspamd_config_find_classifier (task->cfg, clname);

	if (cl == NULL) {
		msg_warn ("classifier %s is not found", clname);
		lua_pushboolean (L, FALSE);
		lua_pushstring (L, "classifier not found");
		ret = 2;
	}
	else {
		if (!rspamd_learn_task_spam (cl, task, is_spam, &err)) {
			lua_pushboolean (L, FALSE);
			if (err != NULL) {
				lua_pushstring (L, err->message);
				ret = 2;
			}
		}
		else {
			lua_pushboolean (L, TRUE);
		}
	}

	return ret;
}

static gint
lua_task_set_settings (lua_State *L)
{
	struct rspamd_task *task = lua_check_task (L);
	ucl_object_t *settings;

	settings = ucl_object_lua_import (L, 2);
	if (settings != NULL) {
		task->settings = settings;
	}

	return 0;
}

static gint
lua_task_get_metric_score (lua_State *L)
{
	struct rspamd_task *task = lua_check_task (L);
	const gchar *metric_name;
	struct metric_result *metric_res;

	metric_name = luaL_checkstring (L, 2);

	if (task && metric_name) {
		if ((metric_res =
			g_hash_table_lookup (task->results, metric_name)) != NULL) {
			lua_newtable (L);
			lua_pushnumber (L, metric_res->score);
			lua_rawseti (L, -2, 1);
			lua_pushnumber (L,
				metric_res->metric->actions[METRIC_ACTION_REJECT].score);
			lua_rawseti (L, -2, 2);
			lua_pushnumber (L,
				metric_res->metric->actions[METRIC_ACTION_REJECT].score);
			lua_rawseti (L, -2, 3);
		}
		else {
			lua_pushnil (L);
		}
		return 1;
	}

	return 0;
}

static gint
lua_task_get_metric_action (lua_State *L)
{
	struct rspamd_task *task = lua_check_task (L);
	const gchar *metric_name;
	struct metric_result *metric_res;
	enum rspamd_metric_action action;

	metric_name = luaL_checkstring (L, 2);

	if (task && metric_name) {
		if ((metric_res =
			g_hash_table_lookup (task->results, metric_name)) != NULL) {
			action = rspamd_check_action_metric (task, metric_res->score,
					NULL,
					metric_res->metric);
			lua_pushstring (L, rspamd_action_to_str (action));
		}
		else {
			lua_pushnil (L);
		}
		return 1;
	}

	return 0;
}

/***
 * @module mime_textpart
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
 * @method text_part:get_content()
 * Get the text of the part
 * @return {string} `UTF8` encoded content of the part
 */
static gint
lua_textpart_get_content (lua_State * L)
{
	struct mime_text_part *part = lua_check_textpart (L);

	if (part == NULL || part->is_empty) {
		lua_pushnil (L);
		return 1;
	}

	lua_pushlstring (L, (const gchar *)part->content->data, part->content->len);

	return 1;
}

/***
 * @method text_part:get_length()
 * Get length of the text of the part
 * @return {integer} length of part in **bytes**
 */
static gint
lua_textpart_get_length (lua_State * L)
{
	struct mime_text_part *part = lua_check_textpart (L);

	if (part == NULL) {
		lua_pushnil (L);
		return 1;
	}

	if (part->is_empty) {
		lua_pushnumber (L, 0);
	}
	else {
		lua_pushnumber (L, part->content->len);
	}

	return 1;
}

/***
 * @method text_part:is_empty()
 * Returns `true` if the specified part is empty
 * @return {bool} whether a part is empty
 */
static gint
lua_textpart_is_empty (lua_State * L)
{
	struct mime_text_part *part = lua_check_textpart (L);

	if (part == NULL) {
		lua_pushnil (L);
		return 1;
	}

	lua_pushboolean (L, part->is_empty);

	return 1;
}
/***
 * @method text_part:is_html()
 * Returns `true` if the specified part has HTML content
 * @return {bool} whether a part is HTML part
 */
static gint
lua_textpart_is_html (lua_State * L)
{
	struct mime_text_part *part = lua_check_textpart (L);

	if (part == NULL) {
		lua_pushnil (L);
		return 1;
	}

	lua_pushboolean (L, part->is_html);

	return 1;
}

/***
 * @method text_part:get_fuzzy()
 * Returns base32 encoded value of fuzzy hash of the specified part
 * @return {string} fuzzy hash value
 */
static gint
lua_textpart_get_fuzzy (lua_State * L)
{
	struct mime_text_part *part = lua_check_textpart (L);
	gchar *out;

	if (part == NULL || part->is_empty) {
		lua_pushnil (L);
		return 1;
	}

	out = rspamd_encode_base32 (part->fuzzy->hash_pipe,
			strlen (part->fuzzy->hash_pipe));
	lua_pushstring (L, out);
	g_free (out);

	return 1;
}

/***
 * @method text_part:is_language()
 * Returns the code of the most used unicode script in the text part. Does not work with raw parts
 * @return {string} short abbreviation (such as `ru`) for the script's language
 */
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

/***
 * @method text_part:compare_distance(other)
 * Calculates the difference to another text part.  This function is intended to work with
 * the parts of `multipart/alternative` container only. If the two parts are not the parts of the
 * same `multipart/alternative` container, then they are considered as unrelated and
 * `-1` is returned.
 * @param {text_part} other text part to compare
 * @return {integer} commodity percentage (e.g. the same strings give `100`, different give `0` and unrelated give `-1`)
 */
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
			if (!part->is_empty && !other->is_empty) {
				if (part->diff_str != NULL && other->diff_str != NULL) {
					diff = rspamd_diff_distance (part->diff_str,
							other->diff_str);
				}
				else {
					diff = rspamd_fuzzy_compare_parts (part, other);
				}
			}
			else if ((part->is_empty &&
				!other->is_empty) || (!part->is_empty && other->is_empty)) {
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

	if (part == NULL) {
		lua_pushnil (L);
		return 1;
	}

	lua_pushlstring (L, (const gchar *)part->content->data, part->content->len);

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
		return lua_push_header (L, part->raw_headers, name, strong, full, raw);
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

/* Image functions */
static gint
lua_image_get_width (lua_State *L)
{
	struct rspamd_image *img = lua_check_image (L);

	if (img != NULL) {
		lua_pushnumber (L, img->width);
	}
	else {
		lua_pushnumber (L, 0);
	}
	return 1;
}

static gint
lua_image_get_height (lua_State *L)
{
	struct rspamd_image *img = lua_check_image (L);

	if (img != NULL) {
		lua_pushnumber (L, img->height);
	}
	else {
		lua_pushnumber (L, 0);
	}

	return 1;
}

static gint
lua_image_get_type (lua_State *L)
{
	struct rspamd_image *img = lua_check_image (L);

	if (img != NULL) {
		lua_pushstring (L, image_type_str (img->type));
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_image_get_size (lua_State *L)
{
	struct rspamd_image *img = lua_check_image (L);

	if (img != NULL) {
		lua_pushinteger (L, img->data->len);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_image_get_filename (lua_State *L)
{
	struct rspamd_image *img = lua_check_image (L);

	if (img != NULL && img->filename != NULL) {
		lua_pushstring (L, img->filename);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

/* URL part */
static gint
lua_url_get_length (lua_State *L)
{
	struct uri *url = lua_check_url (L);

	if (url != NULL) {
		lua_pushinteger (L, strlen (struri (url)));
	}
	else {
		lua_pushnil (L);
	}
	return 1;
}

static gint
lua_url_get_host (lua_State *L)
{
	struct uri *url = lua_check_url (L);

	if (url != NULL) {
		lua_pushlstring (L, url->host, url->hostlen);
	}
	else {
		lua_pushnil (L);
	}
	return 1;
}

static gint
lua_url_get_user (lua_State *L)
{
	struct uri *url = lua_check_url (L);

	if (url != NULL && url->user != NULL) {
		lua_pushlstring (L, url->user, url->userlen);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_url_get_path (lua_State *L)
{
	struct uri *url = lua_check_url (L);

	if (url != NULL) {
		lua_pushlstring (L, url->data, url->datalen);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_url_get_text (lua_State *L)
{
	struct uri *url = lua_check_url (L);

	if (url != NULL) {
		lua_pushstring (L, struri (url));
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_url_is_phished (lua_State *L)
{
	struct uri *url = lua_check_url (L);

	if (url != NULL) {
		lua_pushboolean (L, url->is_phished);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_url_get_phished (lua_State *L)
{
	struct uri **purl, *url = lua_check_url (L);

	if (url) {
		if (url->is_phished && url->phished_url != NULL) {
			purl = lua_newuserdata (L, sizeof (struct uri *));
			rspamd_lua_setclass (L, "rspamd{url}", -1);
			*purl = url->phished_url;

			return 1;
		}
	}

	lua_pushnil (L);
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

void
luaopen_task (lua_State * L)
{
	rspamd_lua_new_class (L, "rspamd{task}", tasklib_m);
	lua_pop (L, 1);                      /* remove metatable from stack */

	rspamd_lua_add_preload (L, "rspamd_task", lua_load_task);
}

void
luaopen_textpart (lua_State * L)
{
	rspamd_lua_new_class (L, "rspamd{textpart}", textpartlib_m);
	luaL_register (L, "rspamd_textpart", null_reg);

	lua_pop (L, 1);                      /* remove metatable from stack */
}

void
luaopen_mimepart (lua_State * L)
{
	rspamd_lua_new_class (L, "rspamd{mimepart}", mimepartlib_m);
	lua_pop (L, 1);                      /* remove metatable from stack */
}

void
luaopen_image (lua_State * L)
{
	rspamd_lua_new_class (L, "rspamd{image}", imagelib_m);
	lua_pop (L, 1);                      /* remove metatable from stack */
}

void
luaopen_url (lua_State * L)
{
	rspamd_lua_new_class (L, "rspamd{url}", urllib_m);
	lua_pop (L, 1);                      /* remove metatable from stack */
}

