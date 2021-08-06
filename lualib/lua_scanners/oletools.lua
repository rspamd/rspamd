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
-- This module contains oletools access functions.
-- Olefy is needed: https://github.com/HeinleinSupport/olefy
--]]

local lua_util = require "lua_util"
local tcp = require "rspamd_tcp"
local upstream_list = require "rspamd_upstream_list"
local rspamd_logger = require "rspamd_logger"
local ucl = require "ucl"
local common = require "lua_scanners/common"

local N = 'oletools'

local function oletools_config(opts)

  local oletools_conf = {
    name = N,
    scan_mime_parts = true,
    scan_text_mime = false,
    scan_image_mime = false,
    default_port = 10050,
    timeout = 15.0,
    log_clean = false,
    retransmits = 2,
    cache_expire = 86400, -- expire redis in 1d
    min_size = 500,
    symbol = "OLETOOLS",
    message = '${SCANNER}: Oletools threat message found: "${VIRUS}"',
    detection_category = "office macro",
    default_score = 1,
    action = false,
    extended = false,
    symbol_type = 'postfilter',
    dynamic_scan = true,
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
    lua_util.add_debug_alias('external_services', oletools_conf.name)
    return oletools_conf
  end

  rspamd_logger.errx(rspamd_config, 'cannot parse servers %s',
      oletools_conf.servers)
  return nil
end

local function oletools_check(task, content, digest, rule, maybe_part)
  local function oletools_check_uncached ()
    local upstream = rule.upstreams:get_upstream_round_robin()
    local addr = upstream:get_addr()
    local retransmits = rule.retransmits
    local protocol = 'OLEFY/1.0\nMethod: oletools\nRspamd-ID: ' .. task:get_uid() .. '\n\n'
    local json_response = ""

    local function oletools_callback(err, data, conn)

      local function oletools_requery(error)
        -- set current upstream to fail because an error occurred
        upstream:fail()

        -- retry with another upstream until retransmits exceeds
        if retransmits > 0 then

          retransmits = retransmits - 1

          -- Select a different upstream!
          upstream = rule.upstreams:get_upstream_round_robin()
          addr = upstream:get_addr()

          lua_util.debugm(rule.name, task, '%s: error: %s; retry IP: %s; retries left: %s',
              rule.log_prefix, err, addr, retransmits)

          tcp.request({
            task = task,
            host = addr:to_string(),
            port = addr:get_port(),
            timeout = rule.timeout,
            shutdown = true,
            data = { protocol, content },
            callback = oletools_callback,
          })
        else
          rspamd_logger.errx(task, '%s: failed to scan, maximum retransmits '..
              'exceed - err: %s', rule.log_prefix, error)
          common.yield_result(task, rule,
              'failed to scan, maximum retransmits exceed - err: ' .. error,
              0.0, 'fail', maybe_part)
        end
      end

      if err then

        oletools_requery(err)

      else
        -- Parse the response
        if upstream then upstream:ok() end

        json_response = json_response .. tostring(data)

	      if not string.find(json_response, '\t\n\n\t') and #data == 8192 then
          lua_util.debugm(rule.name, task, '%s: no stop word: add_read - #json: %s / current packet: %s',
            rule.log_prefix, #json_response, #data)
          conn:add_read(oletools_callback)

        else
          local ucl_parser = ucl.parser()
          local ok, ucl_err = ucl_parser:parse_string(tostring(json_response))
          if not ok then
            rspamd_logger.errx(task, "%s: error parsing json response, retry: %s",
                rule.log_prefix, ucl_err)
            oletools_requery(ucl_err)
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

          -- M=Macros, A=Auto-executable, S=Suspicious keywords, I=IOCs,
          -- H=Hex strings, B=Base64 strings, D=Dridex strings, V=VBA strings
          -- Keep sorted to avoid dragons
          local analysis_cat_table = {
            autoexec = '-',
            base64 = '-',
            dridex = '-',
            hex = '-',
            iocs = '-',
            macro_exist = '-',
            suspicious = '-',
            vba = '-'
          }
          local analysis_keyword_table = {}

          for _, v in ipairs(result) do

            if v.error ~= nil and v.type ~= 'error' then
              -- olefy, not oletools error
              rspamd_logger.errx(task, '%s: ERROR found: %s', rule.log_prefix,
                  v.error)
              if v.error == 'File too small' then
                common.save_cache(task, digest, rule, 'OK', 1.0, maybe_part)
                common.log_clean(task, rule, 'File too small to be scanned for macros')
                return
              else
                oletools_requery(v.error)
              end

            elseif tostring(v.type) == "MetaInformation" and v.version ~= nil then
              -- if MetaInformation section - check and print script and version

              lua_util.debugm(N, task, '%s: version: %s %s', rule.log_prefix,
                  tostring(v.script_name), tostring(v.version))

            elseif tostring(v.type) == "MetaInformation" and v.return_code ~= nil then
              -- if MetaInformation section - check return_code

              local oletools_rc_code = tonumber(v.return_code)
              if oletools_rc_code == 9 then
                rspamd_logger.warnx(task, '%s: File is encrypted.', rule.log_prefix)
                common.yield_result(task, rule,
                    'failed - err: ' .. oletools_rc[oletools_rc_code],
                    0.0, 'encrypted', maybe_part)
                common.save_cache(task, digest, rule, 'encrypted', 1.0, maybe_part)
                return
              elseif oletools_rc_code == 5 then
                rspamd_logger.warnx(task, '%s: olefy could not open the file - error: %s', rule.log_prefix,
                    result[2]['message'])
                common.yield_result(task, rule,
                    'failed - err: ' .. oletools_rc[oletools_rc_code],
                    0.0, 'fail', maybe_part)
                return
              elseif oletools_rc_code > 6 then
                rspamd_logger.errx(task, '%s: MetaInfo section error code: %s',
                    rule.log_prefix, oletools_rc[oletools_rc_code])
                rspamd_logger.errx(task, '%s: MetaInfo section message: %s',
                    rule.log_prefix, result[2]['message'])
                common.yield_result(task, rule,
                    'failed - err: ' .. oletools_rc[oletools_rc_code],
                    0.0, 'fail', maybe_part)
                return
              elseif oletools_rc_code > 1 then
                rspamd_logger.errx(task, '%s: Error message: %s',
                    rule.log_prefix, result[2]['message'])
                oletools_requery(oletools_rc[oletools_rc_code])
              end

            elseif tostring(v.type) == "error" then
              -- error section found - check message
              rspamd_logger.errx(task, '%s: Error section error code: %s',
                  rule.log_prefix, v.error)
              rspamd_logger.errx(task, '%s: Error section message: %s',
                  rule.log_prefix, v.message)
              --common.yield_result(task, rule, 'failed - err: ' .. v.error, 0.0, 'fail')

            elseif type(v.analysis) == 'table' and type(v.macros) == 'table'  then
              -- analysis + macro found - evaluate response

              if type(v.analysis) == 'table' and #v.analysis == 0 and #v.macros == 0 then
                rspamd_logger.warnx(task, '%s: maybe unhandled python or oletools error', rule.log_prefix)
                oletools_requery('oletools unhandled error')

              elseif #v.macros > 0 then

                analysis_cat_table.macro_exist = 'M'

                lua_util.debugm(rule.name, task,
                    '%s: filename: %s', rule.log_prefix, result[2]['file'])
                lua_util.debugm(rule.name, task,
                    '%s: type: %s', rule.log_prefix, result[2]['type'])

                for _,m in ipairs(v.macros) do
                  lua_util.debugm(rule.name, task, '%s: macros found - code: %s, ole_stream: %s, '..
                      'vba_filename: %s', rule.log_prefix, m.code, m.ole_stream, m.vba_filename)
                end

                for _,a in ipairs(v.analysis) do
                  lua_util.debugm(rule.name, task, '%s: threat found - type: %s, keyword: %s, '..
                      'description: %s', rule.log_prefix, a.type, a.keyword, a.description)
                  if a.type == 'AutoExec' then
                    analysis_cat_table.autoexec = 'A'
                    table.insert(analysis_keyword_table, a.keyword)
                  elseif a.type == 'Suspicious' then
                    if rule.extended == true or
                      (a.keyword ~= 'Base64 Strings' and a.keyword ~= 'Hex Strings')
                    then
                      analysis_cat_table.suspicious = 'S'
                      table.insert(analysis_keyword_table, a.keyword)
                    end
                  elseif a.type == 'IOC' then
                    analysis_cat_table.iocs = 'I'
                  elseif a.type == 'Hex strings' then
                    analysis_cat_table.hex = 'H'
                  elseif a.type == 'Base64 strings' then
                    analysis_cat_table.base64 = 'B'
                  elseif a.type == 'Dridex strings' then
                    analysis_cat_table.dridex = 'D'
                  elseif a.type == 'VBA strings' then
                    analysis_cat_table.vba = 'V'
                  end
                end
              end
            end
          end

          lua_util.debugm(N, task, '%s: analysis_keyword_table: %s', rule.log_prefix, analysis_keyword_table)
          lua_util.debugm(N, task, '%s: analysis_cat_table: %s', rule.log_prefix, analysis_cat_table)

          if rule.extended == false and analysis_cat_table.autoexec == 'A' and analysis_cat_table.suspicious == 'S' then
            -- use single string as virus name
            local threat = 'AutoExec + Suspicious (' .. table.concat(analysis_keyword_table, ',') .. ')'
            lua_util.debugm(rule.name, task, '%s: threat result: %s', rule.log_prefix, threat)
            common.yield_result(task, rule, threat, rule.default_score, nil, maybe_part)
            common.save_cache(task, digest, rule, threat, rule.default_score, maybe_part)

          elseif rule.extended == true and #analysis_keyword_table > 0 then
            -- report any flags (types) and any most keywords as individual virus name
            local analysis_cat_table_values_sorted = {}

            -- see https://github.com/rspamd/rspamd/commit/6bd3e2b9f49d1de3ab882aeca9c30bc7d526ac9d#commitcomment-40130493
            -- for details
            local analysis_cat_table_keys_sorted = lua_util.keys(analysis_cat_table)
            table.sort(analysis_cat_table_keys_sorted)

            for _,v in ipairs(analysis_cat_table_keys_sorted) do
              table.insert(analysis_cat_table_values_sorted, analysis_cat_table[v])
            end

            table.insert(analysis_keyword_table, 1, table.concat(analysis_cat_table_values_sorted))

            lua_util.debugm(rule.name, task, '%s: extended threat result: %s',
                rule.log_prefix, table.concat(analysis_keyword_table, ','))

            common.yield_result(task, rule, analysis_keyword_table,
                rule.default_score, nil, maybe_part)
            common.save_cache(task, digest, rule, analysis_keyword_table,
                rule.default_score, maybe_part)

          elseif analysis_cat_table.macro_exist == '-' and #analysis_keyword_table == 0 then
            common.save_cache(task, digest, rule, 'OK', 1.0, maybe_part)
            common.log_clean(task, rule, 'No macro found')

          else
            common.save_cache(task, digest, rule, 'OK', 1.0, maybe_part)
            common.log_clean(task, rule, 'Scanned Macro is OK')
          end
        end
      end
    end

    tcp.request({
      task = task,
      host = addr:to_string(),
      port = addr:get_port(),
      timeout = rule.timeout,
      shutdown = true,
      data = { protocol, content },
      callback = oletools_callback,
    })

  end

  if common.condition_check_and_continue(task, content, rule, digest,
      oletools_check_uncached, maybe_part) then
    return
  else
    oletools_check_uncached()
  end

end

return {
  type = {N, 'attachment scanner', 'hash', 'scanner'},
  description = 'oletools office macro scanner',
  configure = oletools_config,
  check = oletools_check,
  name = N
}
