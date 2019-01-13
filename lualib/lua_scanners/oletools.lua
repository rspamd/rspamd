--[[
Copyright (c) 2018, Vsevolod Stakhov <vsevolod@highsecure.ru>
Copyright (c) 2018, Carsten Rosenberg <c.rosenberg@heinlein-support.de>

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
-- @module oletools
-- This module contains oletools access functions
--]]

local lua_util = require "lua_util"
local tcp = require "rspamd_tcp"
local upstream_list = require "rspamd_upstream_list"
local rspamd_logger = require "rspamd_logger"
local ucl = require "ucl"
local common = require "lua_scanners/common"
local fun = require "fun"

local module_name = 'oletools'

local function oletools_check(task, content, digest, rule)
  local function oletools_check_uncached ()
    local upstream = rule.upstreams:get_upstream_round_robin()
    local addr = upstream:get_addr()
    local retransmits = rule.retransmits

    local function oletools_callback(err, data, conn)

      local function oletools_requery()
        -- set current upstream to fail because an error occurred
        upstream:fail()

        -- retry with another upstream until retransmits exceeds
        if retransmits > 0 then

          retransmits = retransmits - 1

          lua_util.debugm(rule.module_name, task, '%s: Request Error: %s - retries left: %s',
            rule.log_prefix, err, retransmits)

          -- Select a different upstream!
          upstream = rule.upstreams:get_upstream_round_robin()
          addr = upstream:get_addr()

          lua_util.debugm(rule.module_name, task, '%s: retry IP: %s:%s',
            rule.log_prefix, addr, addr:get_port())

          tcp.request({
            task = task,
            host = addr:to_string(),
            port = addr:get_port(),
            timeout = rule['timeout'],
            shutdown = true,
            data = content,
            callback = oletools_callback,
          })
        else
          rspamd_logger.errx(task, '%s: failed to scan, maximum retransmits '..
            'exceed', rule.log_prefix)
          task:insert_result(rule['symbol_fail'], 0.0, 'failed to scan and '..
            'retransmits exceed')
        end
      end

      if err then

        oletools_requery()

      else
        -- Parse the response
        if upstream then upstream:ok() end

        data = tostring(data)

        local ucl_parser = ucl.parser()
        local ok, ucl_err = ucl_parser:parse_string(tostring(data))
        if not ok then
            rspamd_logger.errx(task, "%s: error parsing json response: %s",
              rule.log_prefix, ucl_err)
            return
        end

        local result = ucl_parser:get_object()

        local oletools_rc = {
          [0] = 'RETURN_OK',
          [1] = 'RETURN_WARNINGS',
          [2] = 'RETURN_WRONG_ARGS',
          [3] = 'RETURN_FILE_NOT_FOUND',
          [4] = 'RETURN_XGLOB_ERR',
          [5] = 'RETURN_OPEN_ERROR',
          [6] = 'RETURN_PARSE_ERROR',
          [7] = 'RETURN_SEVERAL_ERRS',
          [8] = 'RETURN_UNEXPECTED',
          [9] = 'RETURN_ENCRYPTED',
        }

        --lua_util.debugm(rule.module_name, task, '%s: result: %s', rule.log_prefix, result)
        lua_util.debugm(rule.module_name, task, '%s: filename: %s', rule.log_prefix, result[2]['file'])
        lua_util.debugm(rule.module_name, task, '%s: type: %s', rule.log_prefix, result[2]['type'])

        if result[1].error ~= nil then
          rspamd_logger.errx(task, '%s: ERROR found: %s', rule.log_prefix,
            result[1].error)
          oletools_requery()
        elseif result[3]['return_code'] == 9 then
          rspamd_logger.warnx(task, '%s: File is encrypted.', rule.log_prefix)
        elseif result[3]['return_code'] > 6 then
          rspamd_logger.errx(task, '%s: Error Returned: %s',
            rule.log_prefix, oletools_rc[result[3]['return_code']])
        elseif result[3]['return_code'] > 1 then
          rspamd_logger.errx(task, '%s: Error Returned: %s',
            rule.log_prefix, oletools_rc[result[3]['return_code']])
          oletools_requery()
        elseif result[2]['analysis'] == 'null' and #result[2]['macros'] == 0 then
          if rule.log_clean == true then
            rspamd_logger.infox(task, '%s: Scanned Macro is OK', rule.log_prefix)
          else
            lua_util.debugm(rule.module_name, task, '%s: No Macro found', rule.log_prefix)
          end
        elseif #result[2]['macros'] > 0 then

          for _,m in ipairs(result[2]['macros']) do
            lua_util.debugm(rule.module_name, task, '%s: macros found - code: %s, ole_stream: %s, '..
              'vba_filename: %s', rule.log_prefix, m.code, m.ole_stream, m.vba_filename)
          end

          local macro_autoexec = false
          local macro_suspicious = false
          local macro_keyword_table = {}

          for _,a in ipairs(result[2]['analysis']) do
            if a.type ~= 'AutoExec' or a.type ~= 'Suspicious' then
              lua_util.debugm(rule.module_name, task, '%s: threat found - type: %s, keyword: %s, '..
                'description: %s', rule.log_prefix, a.type, a.keyword, a.description)
            end
            if a.type == 'AutoExec' then
              macro_autoexec = true
              if rule.extended == true then
                table.insert(macro_keyword_table, a.keyword)
              end
            elseif a.type == 'Suspicious'
              and a.keyword ~= 'Base64 Strings'
              and a.keyword ~= 'Hex Strings'
            then
              macro_suspicious = true
              if rule.extended == true then
                table.insert(macro_keyword_table, a.keyword)
              end
            end
          end

          if macro_autoexec then
            table.insert(macro_keyword_table, 'AutoExec')
          end
          if macro_suspicious then
            table.insert(macro_keyword_table, 'Suspicious')
          end

          lua_util.debugm(rule.module_name, task, '%s: extended: %s', rule.log_prefix, rule.extended)
          if rule.extended == false and macro_autoexec and macro_suspicious then

            lua_util.debugm(rule.module_name, task, '%s: found macro_autoexec and '..
              'macro_suspicious', rule.log_prefix)
            local threat = 'AutoExec+Suspicious'
            common.yield_result(task, rule, threat, rule.default_score)
            common.save_av_cache(task, digest, rule, threat, rule.default_score)

          elseif rule.extended == true and #macro_keyword_table > 0 then

            common.yield_result(task, rule, macro_keyword_table, rule.default_score)
            common.save_av_cache(task, digest, rule, macro_keyword_table, rule.default_score)

          elseif rule.log_clean == true then
            rspamd_logger.infox(task, '%s: Scanned Macro is OK', rule.log_prefix)
          end

        else
          rspamd_logger.warnx(task, '%s: unhandled response', rule.log_prefix)
        end
      end
    end

    tcp.request({
      task = task,
      host = addr:to_string(),
      port = addr:get_port(),
      timeout = rule['timeout'],
      shutdown = true,
      data = content,
      callback = oletools_callback,
    })

  end
  if common.need_av_check(task, content, rule) then
    if common.check_av_cache(task, digest, rule, oletools_check_uncached) then
      return
    else
      oletools_check_uncached()
    end
  end
end

local function oletools_config(opts)

  local oletools_conf = {
    module_name = module_name,
    scan_mime_parts = false,
    scan_text_mime = false,
    scan_image_mime = false,
    default_port = 5954,
    timeout = 15.0,
    log_clean = false,
    retransmits = 2,
    cache_expire = 7200, -- expire redis in 2h
    message = '${SCANNER}: Oletools threat message found: "${VIRUS}"',
    detection_category = "office macro",
    default_score = 1,
    action = false,
    extended = false,
  }

  oletools_conf = lua_util.override_defaults(oletools_conf, opts)

  if not oletools_conf.prefix then
    oletools_conf.prefix = 'rs_' .. oletools_conf.name .. '_'
  end

  if not oletools_conf.log_prefix then
    if oletools_conf.name:lower() == oletools_conf.type:lower() then
      oletools_conf.log_prefix = oletools_conf.name
    else
      oletools_conf.log_prefix = oletools_conf.name .. ' (' .. oletools_conf.type .. ')'
    end
  end

  if not oletools_conf.servers then
    rspamd_logger.errx(rspamd_config, 'no servers defined')

    return nil
  end

  oletools_conf.upstreams = upstream_list.create(rspamd_config,
    oletools_conf.servers,
    oletools_conf.default_port)

  if oletools_conf.upstreams then
    lua_util.add_debug_alias('antivirus', oletools_conf.module_name)
    return oletools_conf
  end

  rspamd_logger.errx(rspamd_config, 'cannot parse servers %s',
    oletools_conf.servers)
  return nil
end

return {
  type = {module_name,'office macro scanner', 'hash', 'scanner'},
  description = 'oletools office macro scanner',
  configure = oletools_config,
  check = oletools_check,
  name = module_name
}
