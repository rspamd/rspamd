--[[
Copyright (c) 2025, Vsevolod Stakhov <vsevolod@rspamd.com>

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
-- @module metadefender
-- This module contains MetaDefender Cloud integration support for hash lookups
-- https://metadefender.opswat.com/
--]]

local lua_util = require "lua_util"
local http = require "rspamd_http"
local rspamd_cryptobox_hash = require "rspamd_cryptobox_hash"
local rspamd_logger = require "rspamd_logger"
local common = require "lua_scanners/common"

local N = 'metadefender'

local function metadefender_config(opts)

  local default_conf = {
    name = N,
    url = 'https://api.metadefender.com/v4/hash',
    timeout = 5.0,
    log_clean = false,
    retransmits = 1,
    cache_expire = 7200, -- expire redis in 2h
    message = '${SCANNER}: spam message found: "${VIRUS}"',
    detection_category = "virus",
    default_score = 1,
    action = false,
    scan_mime_parts = true,
    scan_text_mime = false,
    scan_image_mime = false,
    apikey = nil, -- Required to set by user
    -- Specific for metadefender
    minimum_engines = 3, -- Minimum required to get scored
    full_score_engines = 7, -- After this number we set max score
  }

  default_conf = lua_util.override_defaults(default_conf, opts)

  if not default_conf.prefix then
    default_conf.prefix = 'rs_' .. default_conf.name .. '_'
  end

  if not default_conf.log_prefix then
    if default_conf.name:lower() == default_conf.type:lower() then
      default_conf.log_prefix = default_conf.name
    else
      default_conf.log_prefix = default_conf.name .. ' (' .. default_conf.type .. ')'
    end
  end

  if not default_conf.apikey then
    rspamd_logger.errx(rspamd_config, 'no apikey defined for metadefender, disable checks')

    return nil
  end

  lua_util.add_debug_alias('external_services', default_conf.name)
  return default_conf
end

local function metadefender_check(task, content, digest, rule, maybe_part)
  local function metadefender_check_uncached()
    local function make_url(hash)
      return string.format('%s/%s', rule.url, hash)
    end

    -- MetaDefender uses SHA256 hash
    local hash = rspamd_cryptobox_hash.create_specific('sha256')
    hash:update(content)
    hash = hash:hex()

    local url = make_url(hash)
    lua_util.debugm(N, task, "send request %s", url)
    local request_data = {
      task = task,
      url = url,
      timeout = rule.timeout,
      headers = {
        ['apikey'] = rule.apikey,
      }
    }

    local function md_http_callback(http_err, code, body, headers)
      if http_err then
        rspamd_logger.errx(task, 'HTTP error: %s, body: %s, headers: %s', http_err, body, headers)
        task:insert_result(rule.symbol_fail, 1.0, 'HTTP error: ' .. http_err)
      else
        local cached
        local dyn_score
        -- Parse the response
        if code ~= 200 then
          if code == 404 then
            cached = 'OK'
            if rule['log_clean'] then
              rspamd_logger.infox(task, '%s: hash %s clean (not found)',
                  rule.log_prefix, hash)
            else
              lua_util.debugm(rule.name, task, '%s: hash %s clean (not found)',
                  rule.log_prefix, hash)
            end
          elseif code == 429 then
            -- Request rate limit exceeded
            rspamd_logger.infox(task, 'metadefender request rate limit exceeded')
            task:insert_result(rule.symbol_fail, 1.0, 'rate limit exceeded')
            return
          else
            rspamd_logger.errx(task, 'invalid HTTP code: %s, body: %s, headers: %s', code, body, headers)
            task:insert_result(rule.symbol_fail, 1.0, 'Bad HTTP code: ' .. code)
            return
          end
        else
          local ucl = require "ucl"
          local parser = ucl.parser()
          local res, json_err = parser:parse_string(body)

          lua_util.debugm(rule.name, task, '%s: got reply data: "%s"',
              rule.log_prefix, body)

          if res then
            local obj = parser:get_object()

            -- MetaDefender API response structure:
            -- scan_results.scan_all_result_a: 'Clean', 'Infected', 'Suspicious'
            -- scan_results.scan_all_result_i: numeric result (0=clean)
            -- scan_results.total_detected_avs: number of engines detecting malware
            -- scan_results.total_avs: total number of engines

            if not obj.scan_results then
              rspamd_logger.errx(task, 'invalid JSON reply: no scan_results field, body: %s', body)
              task:insert_result(rule.symbol_fail, 1.0, 'Bad JSON reply: no scan_results')
              return
            end

            local scan_results = obj.scan_results
            local detected = scan_results.total_detected_avs or 0
            local total = scan_results.total_avs or 0

            if detected == 0 then
              cached = 'OK'
              if rule['log_clean'] then
                rspamd_logger.infox(task, '%s: hash %s clean',
                    rule.log_prefix, hash)
              else
                lua_util.debugm(rule.name, task, '%s: hash %s clean',
                    rule.log_prefix, hash)
              end
            else
              if detected < rule.minimum_engines then
                lua_util.debugm(rule.name, task, '%s: hash %s has not enough hits: %s where %s is min',
                    rule.log_prefix, hash, detected, rule.minimum_engines)
                cached = 'OK'
              else
                if detected >= rule.full_score_engines then
                  dyn_score = 1.0
                else
                  local norm_detected = detected - rule.minimum_engines
                  dyn_score = norm_detected / (rule.full_score_engines - rule.minimum_engines)
                end

                if dyn_score < 0 or dyn_score > 1 then
                  dyn_score = 1.0
                end

                local sopt = string.format("%s:%s/%s",
                    hash, detected, total)
                common.yield_result(task, rule, sopt, dyn_score, nil, maybe_part)
                cached = sopt
              end
            end
          else
            -- not res
            rspamd_logger.errx(task, 'invalid JSON reply: %s, body: %s, headers: %s',
                json_err, body, headers)
            task:insert_result(rule.symbol_fail, 1.0, 'Bad JSON reply: ' .. json_err)
            return
          end
        end

        if cached then
          common.save_cache(task, digest, rule, cached, dyn_score, maybe_part)
        end
      end
    end

    request_data.callback = md_http_callback
    http.request(request_data)
  end

  if common.condition_check_and_continue(task, content, rule, digest,
      metadefender_check_uncached) then
    return
  else

    metadefender_check_uncached()
  end

end

return {
  type = 'antivirus',
  description = 'MetaDefender Cloud integration',
  configure = metadefender_config,
  check = metadefender_check,
  name = N
}
