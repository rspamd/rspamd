--[[
Copyright (c) 2025, Halon Security AB <support@halon.io>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
]]--

--[[[
-- @module expurgate
-- This module contains eXpurgate integration
--]]

local lua_util = require "lua_util"
local lua_mime = require "lua_mime"
local http = require "rspamd_http"
local upstream_list = require "rspamd_upstream_list"
local rspamd_logger = require "rspamd_logger"
local ucl = require "ucl"
local common = require "lua_scanners/common"

local N = 'expurgate'

local header_key_x_purgate_type = 'X-purgate-type'
local header_key_x_purgate_id = 'X-purgate-ID'

local function expurgate_config(opts)
    local symbols = {}

    local function add_symbol(symbol_name, score, expurgate_type)
        symbols[expurgate_type] = {
            symbol = symbol_name,
            score = score,
        }
    end

    add_symbol('EXPURGATE_UNKNOWN', 0.0, 'unknown')
    add_symbol('EXPURGATE_CLEAN', -1.0, 'clean')
    add_symbol('EXPURGATE_SUSPECT', 3.0, 'suspect')
    add_symbol('EXPURGATE_SPAM', 8.0, 'spam')
    add_symbol('EXPURGATE_BULK', -1.0, 'bulk')

    -- minor categories
    add_symbol('EXPURGATE_CLEAN_EMPTY', 5.0, 'clean.empty')
    add_symbol('EXPURGATE_CLEAN_EMPTY_BODY', -1.0, 'clean.empty-body')
    add_symbol('EXPURGATE_CLEAN_BOUNCE', -1.0, 'clean.bounce')
    add_symbol('EXPURGATE_BULK_ADVERTISING', 7.0, 'bulk.advertising')
    add_symbol('EXPURGATE_BULK_PORN', 7.0, 'bulk.porn')
    add_symbol('EXPURGATE_DANGEROUS_VIRUS', 8.0, 'dangerous.virus')
    add_symbol('EXPURGATE_DANGEROUS_ATTACHMENT', 5.0, 'dangerous.attachment')
    add_symbol('EXPURGATE_DANGEROUS_CODE', 8.0, 'dangerous.code')
    add_symbol('EXPURGATE_DANGEROUS_IFRAME', 5.0, 'dangerous.iframe')
    add_symbol('EXPURGATE_DANGEROUS_VIRUS_OUTBREAK', 8.0, 'dangerous.virus-outbreak')
    add_symbol('EXPURGATE_SUSPECT_URL', 3.0, 'suspect.url')
    add_symbol('EXPURGATE_SUSPECT_URL_COUNT', 3.0, 'suspect.url-count')
    add_symbol('EXPURGATE_SUSPECT_MAIL_COUNT', 3.0, 'suspect.mail-count')
    add_symbol('EXPURGATE_SUSPECT_SENDER', 3.0, 'suspect.sender')
    add_symbol('EXPURGATE_SPAM_PHISHING', 8.0, 'spam.phishing')

    local expurgate_conf = {
        name = N,
        default_port = 783,
        url = '/checkv2',
        use_https = false,
        timeout = 5.0,
        retransmits = 1,
        log_spamcause = false,
        symbol_fail = 'EXPURGATE_FAIL',
        symbol = 'EXPURGATE_CHECK',
        symbols = symbols,
        add_header_x_purgate_id = true,
        add_header_x_purgate_type = false,
    }

    expurgate_conf = lua_util.override_defaults(expurgate_conf, opts)

    if not expurgate_conf.prefix then
        expurgate_conf.prefix = 'rs_' .. expurgate_conf.name .. '_'
    end

    if not expurgate_conf.log_prefix then
        if expurgate_conf.name:lower() == expurgate_conf.type:lower() then
            expurgate_conf.log_prefix = expurgate_conf.name
        else
            expurgate_conf.log_prefix = expurgate_conf.name .. ' (' .. expurgate_conf.type .. ')'
        end
    end

    if not expurgate_conf.servers then
        rspamd_logger.errx(rspamd_config, 'no servers defined')

        return nil
    end

    expurgate_conf.upstreams = upstream_list.create(rspamd_config,
            expurgate_conf.servers,
            expurgate_conf.default_port)

    if expurgate_conf.upstreams then
        lua_util.add_debug_alias('external_services', expurgate_conf.name)
        return expurgate_conf
    end

    rspamd_logger.errx(rspamd_config, 'cannot parse servers %s', expurgate_conf['servers'])
    return nil
end

local function header_value(header)
    if not header or not header.value or not string.len(header.value) == 0 then
        return nil
    end

    return header.value
end

local function expurgate_check(task, content, digest, rule, maybe_part)

    local function expurgate_check_uncached()
        local function expurgate_spamd_url(addr)
            local url
            if rule.use_https then
                url = string.format('https://%s:%d%s', tostring(addr),
                        rule.default_port, rule.url)
            else
                url = string.format('http://%s:%d%s', tostring(addr),
                        rule.default_port, rule.url)
            end

            return url
        end

        local upstream = rule.upstreams:get_upstream_round_robin()
        local addr = upstream:get_addr()
        local retransmits = rule.retransmits

        local url = expurgate_spamd_url(addr)
        local hdrs = {}

        local helo = task:get_helo()
        if helo then
            hdrs['Helo'] = helo
        end

        local hostname = task:get_hostname()
        if hostname then
            hdrs['Hostname'] = hostname
        end

        local mail_from = task:get_from('smtp') or {}
        if mail_from[1] and #mail_from[1].addr > 1 then
            hdrs['From'] = mail_from[1].addr
        end

        local rcpt_to = task:get_recipients('smtp')
        if rcpt_to then
            hdrs['Rcpt'] = {}
            for _, r in ipairs(rcpt_to) do
                table.insert(hdrs['Rcpt'], r.addr)
            end
        end

        local fip = task:get_from_ip()
        if fip and fip:is_valid() then
            hdrs['IP'] = tostring(fip)
        end

        local request_data = {
            task = task,
            url = url,
            body = task:get_content(),
            headers = hdrs,
            timeout = rule.timeout,
        }

        local function expurgate_callback(http_err, code, body, headers)

            local function expurgate_requery()
                -- set current upstream to fail because an error occurred
                upstream:fail()

                -- retry with another upstream until retransmits exceeds
                if retransmits > 0 then

                    retransmits = retransmits - 1

                    lua_util.debugm(rule.name, task,
                            '%s: Request Error: %s - retries left: %s',
                            rule.log_prefix, http_err, retransmits)

                    -- Select a different upstream!
                    upstream = rule.upstreams:get_upstream_round_robin()
                    addr = upstream:get_addr()
                    url = expurgate_spamd_url(addr)

                    lua_util.debugm(rule.name, task, '%s: retry IP: %s:%s',
                            rule.log_prefix, addr, addr:get_port())
                    request_data.url = url

                    http.request(request_data)
                else
                    rspamd_logger.errx(task, '%s: failed to scan, maximum retransmits ' ..
                            'exceed', rule.log_prefix)
                    task:insert_result(rule['symbol_fail'], 0.0, 'failed to scan and ' ..
                            'retransmits exceed')
                end
            end

            if http_err then
                expurgate_requery()
            else
                -- Parse the response
                if upstream then
                    upstream:ok()
                end
                if code ~= 200 then
                    rspamd_logger.errx(task, 'invalid HTTP code: %s, body: %s, headers: %s', code, body, headers)
                    task:insert_result(rule.symbol_fail, 1.0, 'Bad HTTP code: ' .. code)
                    return
                end
                local parser = ucl.parser()
                local ret, err = parser:parse_string(body)
                if not ret then
                    rspamd_logger.errx(task, 'expurgate: bad response body (raw): %s', body)
                    task:insert_result(rule.symbol_fail, 1.0, 'Parser error: ' .. err)
                    return
                end
                local obj = parser:get_object()
                if not obj.milter or type(obj.milter) ~= 'table' then
                    rspamd_logger.errx(task, 'expurgate: bad response JSON (no object `milter`): %s', obj)
                    task:insert_result(rule.symbol_fail, 1.0, 'Bad JSON reply: no `milter` element')
                    return
                end
                if not obj.milter.add_headers or type(obj.milter.add_headers) ~= 'table' then
                    rspamd_logger.errx(task, 'expurgate: bad response JSON (no object `milter.add_headers`): %s', obj)
                    task:insert_result(rule.symbol_fail, 1.0, 'Bad JSON reply: no `milter.add_headers` element')
                    return
                end

                local header_value_x_purgate_id = header_value(obj.milter.add_headers[header_key_x_purgate_id])
                if header_value_x_purgate_id and rule.add_header_x_purgate_id then
                    lua_mime.modify_headers(task, {
                        add = {
                            [header_key_x_purgate_id] = { order = 1, value = header_value_x_purgate_id }
                        }
                    })
                end

                local header_value_x_purgate_type = header_value(obj.milter.add_headers[header_key_x_purgate_type])
                if header_value_x_purgate_type and rule.add_header_x_purgate_type then
                    lua_mime.modify_headers(task, {
                        add = {
                            [header_key_x_purgate_type] = { order = 1, value = header_value_x_purgate_type}
                        }
                    })
                end

                local x_purgate_type = 'unknown'
                if header_value_x_purgate_type then
                    x_purgate_type = string.lower(header_value_x_purgate_type)
                end

                local sym = rule.symbols[x_purgate_type]
                if not sym then
                    sym = rule.symbols.unknown
                end

                local opts = {}
                if obj.score then
                    table.insert(opts, 'score=' .. obj.score)
                end
                if header_value_x_purgate_id then
                    table.insert(opts, 'x-purgate-id=' .. header_value_x_purgate_id)
                end

                if rule.log_spamcause and obj.spamcause then
                    rspamd_logger.infox(task, 'expurgate type="%s", score=%s, spamcause="%s", message-id="%s"',
                            x_purgate_type, obj.score, obj.spamcause, task:get_message_id())
                else
                    lua_util.debugm(rule.name, task, 'expurgate returned type="%s", score=%s, spamcause="%s"',
                            x_purgate_type, obj.score, obj.spamcause)
                end

                task:insert_result(sym.symbol, 1.0, opts)
            end
        end

        request_data.callback = expurgate_callback
        http.request(request_data)
    end

    if common.condition_check_and_continue(task, content, rule, digest,
            expurgate_check_uncached, maybe_part) then
        return
    else
        expurgate_check_uncached()
    end

end

return {
    type = { N, 'scanner' },
    description = 'eXpurgate AntiSpam Filter',
    configure = expurgate_config,
    check = expurgate_check,
    name = N
}
