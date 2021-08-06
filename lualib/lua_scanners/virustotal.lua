--[[
Copyright (c) 2019, Vsevolod Stakhov <vsevolod@highsecure.ru>

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
-- @module virustotal
-- This module contains Virustotal integaration support
-- https://www.virustotal.com/
--]]

local lua_util = require "lua_util"
local http = require "rspamd_http"
local rspamd_cryptobox_hash = require "rspamd_cryptobox_hash"
local rspamd_logger = require "rspamd_logger"
local common = require "lua_scanners/common"

local N = 'virustotal'

local function virustotal_config(opts)

  local default_conf = {
    name = N,
    url = 'https://www.virustotal.com/vtapi/v2/file',
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
    -- Specific for virustotal
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
    rspamd_logger.errx(rspamd_config, 'no apikey defined for virustotal, disable checks')

    return nil
  end

  lua_util.add_debug_alias('external_services', default_conf.name)
  return default_conf
end

local function virustotal_check(task, content, digest, rule, maybe_part)
  local function virustotal_check_uncached()
    local function make_url(hash)
      return string.format('%s/report?apikey=%s&resource=%s',
          rule.url, rule.apikey, hash)
    end

    local hash = rspamd_cryptobox_hash.create_specific('md5')
    hash:update(content)
    hash = hash:hex()

    local url = make_url(hash)
    lua_util.debugm(N, task, "send request %s", url)
    local request_data = {
      task = task,
      url = url,
      timeout = rule.timeout,
    }

    local function vt_http_callback(http_err, code, body, headers)
      if http_err then
        rspamd_logger.errx(task, 'HTTP error: %s, body: %s, headers: %s', http_err, body, headers)
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
          elseif code == 204 then
            -- Request rate limit exceeded
            rspamd_logger.infox(task, 'virustotal request rate limit exceeded')
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
          local res,json_err = parser:parse_string(body)

          lua_util.debugm(rule.name, task, '%s: got reply data: "%s"',
              rule.log_prefix, body)

          if res then
            local obj = parser:get_object()
            if not obj.positives or type(obj.positives) ~= 'number' then
              if obj.response_code then
                if obj.response_code == 0 then
                  cached = 'OK'
                  if rule['log_clean'] then
                    rspamd_logger.infox(task, '%s: hash %s clean (not found)',
                        rule.log_prefix, hash)
                  else
                    lua_util.debugm(rule.name, task, '%s: hash %s clean (not found)',
                        rule.log_prefix, hash)
                  end
                else
                  rspamd_logger.errx(task, 'invalid JSON reply: %s, body: %s, headers: %s',
                      'bad response code: ' .. tostring(obj.response_code), body, headers)
                  task:insert_result(rule.symbol_fail, 1.0, 'Bad JSON reply: no `positives` element')
                  return
                end
              else
                rspamd_logger.errx(task, 'invalid JSON reply: %s, body: %s, headers: %s',
                    'no response_code', body, headers)
                task:insert_result(rule.symbol_fail, 1.0, 'Bad JSON reply: no `positives` element')
                return
              end
            else
              if obj.positives < rule.minimum_engines then
                lua_util.debugm(rule.name, task, '%s: hash %s has not enough hits: %s where %s is min',
                    rule.log_prefix, obj.positives, rule.minimum_engines)
                -- TODO: add proper hashing!
                cached = 'OK'
              else
                if obj.positives > rule.full_score_engines then
                  dyn_score = 1.0
                else
                  local norm_pos = obj.positives - rule.minimum_engines
                  dyn_score = norm_pos / (rule.full_score_engines - rule.minimum_engines)
                end

                if dyn_score < 0 or dyn_score > 1 then
                  dyn_score = 1.0
                end
                local sopt = string.format("%s:%s/%s",
                    hash, obj.positives, obj.total)
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

    request_data.callback = vt_http_callback
    http.request(request_data)
  end

  if common.condition_check_and_continue(task, content, rule, digest,
      virustotal_check_uncached) then
    return
  else

    virustotal_check_uncached()
  end

end

return {
  type = 'antivirus',
  description = 'Virustotal integration',
  configure = virustotal_config,
  check = virustotal_check,
  name = N
}
