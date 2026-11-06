--[[
Copyright (c) 2026, Gioele Pannetto <gioele@pannet.to>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
]] --

--[[[
-- @module avast_rest
-- This module contains avast rest integration
--]]

local lua_util = require "lua_util"
local rspamd_logger = require "rspamd_logger"
local upstream_list = require "rspamd_upstream_list"
local rspamd_http = require "rspamd_http"
local common = require "lua_scanners/common"
local ucl = require "ucl"

local N = 'avast_rest'

local function avastrest_configure(opts)
  local conf = {
    name = N,
    timeout = 4.0,
    -- Scan full files. By default, the scanner chooses which parts of each file should be scanned and skips the rest as an optimization.
    full = false,
    -- Unpack archives during scan.
    archives = true,
    -- Scanning sensitivity: Report potentially unwanted programs.
    pup = true,
    -- Level of heuristics: 0=disabled, 40=low, 80=medium, 100=high
    heuristics = 80,
    -- Host and port to avast Rest API
    servers = nil,
    -- Whether to use https
    use_https = false,
    log_clean = false,
    retransmits = 1,
    message = '${SCANNER}: virus found: "${VIRUS}"',
    cache_expire = 3600,
    detection_category = "virus",
  }

  conf = lua_util.override_defaults(conf, opts)

  if not conf.prefix then
    conf.prefix = 'rs_' .. conf.name .. '_'
  end

  if not conf['servers'] then
    rspamd_logger.errx(rspamd_config, 'no servers defined')
    return nil
  end

  conf['upstreams'] = upstream_list.create(rspamd_config, conf['servers'], conf.use_https and 443 or 8080)

  if not conf.symbol_skipped then
    conf.symbol_skipped = opts.symbol .. '_SKIPPED'
  end

  if conf['upstreams'] then
    lua_util.add_debug_alias('antivirus', conf.name)
    return conf
  end

  rspamd_logger.errx(rspamd_config, 'cannot parse servers %s', conf['servers'])

  return nil
end

local function avastrest_check(task, content, digest, rule, maybe_part)
  local function avastrest_check_uncached()
    local function make_url(addr)
      local prefix = rule.use_https and "https" or "http"

      return string.format(
        "%s://%s:%s/v1/scan?filename=%s.eml&email=true&full=%s&archives=%s&pup=%s&heuristics=%d",
        prefix, tostring(addr), addr:get_port(),
        task:get_uid(), tostring(rule.full), tostring(rule.archives), tostring(rule.pup),
        rule.heuristics)
    end

    local retransmits = rule.retransmits
    local upstream = rule.upstreams:get_upstream_round_robin()
    local addr = upstream:get_addr()

    local request_data = {
      task = task,
      url = make_url(addr),
      body = content,
      timeout = rule.timeout,
      upstream = upstream,
      mime_type = "application/octet-stream",
      method = "post",
    }

    local function http_response_cb(err, code, body, _)
      local function requery()
        upstream:fail()

        if retransmits <= 0 then
          rspamd_logger.errx(rspamd_config, '%s: failed to scan, maximum retransmits exceed', rule.log_prefix)
          common.yield_result(task, rule, 'http error', 0.0, 'fail', maybe_part)
          return
        end

        retransmits = retransmits - 1

        lua_util.debugm(rule.name, task, '%s: Request Error: %s - retries left: %s', rule.log_prefix, err,
          retransmits)

        upstream = rule.upstreams:get_upstream_round_robin()
        addr = upstream:get_addr()

        lua_util.debugm(rule.name, task, '%s: retry IP: %s:%s', rule.log_prefix, addr, addr:get_port())
        request_data.url = make_url(addr)
        request_data.upstream = upstream

        rspamd_http.request(request_data)
      end

      if err then
        requery()
        return
      end

      if upstream then
        upstream:ok()
      end

      if code ~= 200 then
        rspamd_logger.errx(rspamd_config, '%s: bad status code %d: %s', rule.log_prefix, code, err)
        common.yield_result(task, rule, 'bad status code ' .. code, 0.0, 'fail', maybe_part)
        return
      end

      local parser = ucl.parser()
      local res, parse_err = parser:parse_string(body)

      if not res then
        rspamd_logger.errx(rspamd_config, '%s: UCL parse error: %s', rule.log_prefix, parse_err)
        common.yield_result(task, rule, 'UCL parse error', 0.0, 'fail', maybe_part)
        return
      end

      local issues_obj = parser:get_object()["issues"]
      local cached

      local issues = {}
      for _, issue in ipairs(issues_obj) do
        if issue["virus"] then
          table.insert(issues, issue["virus"])
        else
          cached = "SKIPPED"
          common.yield_result(task, rule, issue['warning_str'] or 'Message skipped by scanner', 0.0, 'skipped',
            maybe_part)
        end
      end

      if #issues > 0 then
        cached = issues
        common.yield_result(task, rule, cached, 1.0, nil, maybe_part)
      elseif not cached then
        cached = "OK"
        common.log_clean(task, rule)
      end

      common.save_cache(task, digest, rule, cached, 1.0, maybe_part)
    end

    request_data.callback = http_response_cb
    rspamd_http.request(request_data)
  end

  if common.condition_check_and_continue(task, content, rule, digest,
        avastrest_check_uncached, maybe_part) then
    return
  else
    avastrest_check_uncached()
  end
end

return {
  check = avastrest_check,
  configure = avastrest_configure,
  name = N,
  type = 'antivirus',
  description = 'Avast antivirus via Rest API',
}
