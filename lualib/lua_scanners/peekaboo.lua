--[[
Copyright (c) 2026, Vsevolod Stakhov <vsevolod@rspamd.com>
Copyright (c) 2026, Carsten Rosenberg <c.rosenberg@heinlein-support.de>

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
-- @module peekaboo
-- This module contains peekaboo access functions.
-- Peekaboo is needed: https://github.com/scVENUS/PeekabooAV
--]]

local lua_util = require "lua_util"
local upstream_list = require "rspamd_upstream_list"
local rspamd_util = require "rspamd_util"
local rspamd_http = require "rspamd_http"
local rspamd_logger = require "rspamd_logger"
local ucl = require "ucl"
local common = require "lua_scanners/common"

local N = 'peekaboo'

local static_boundary = rspamd_util.random_hex(32)

local function peekaboo_config(opts)

  local peekaboo_conf = {
    name = N,
    scan_mime_parts = true,
    scan_text_mime = false,
    scan_image_mime = false,
    mime_parts_match_archive = false,
    url_check = '/v1/scan',
    url_report = '/v1/report',
    default_port = 8100,
    use_https = false,
    no_ssl_verify = true,
    use_gzip = false,
    keepalive = true,
    timeout = 3.0,
    log_clean = false,
    set_clean_symbol = false,
    retransmits = 2,
    cache_expire = 7200, -- expire redis in 1d
    min_size = 300,
    message = '${SCANNER}: Peekaboo threat message found: "${VIRUS}"',
    detection_category = "sandbox threat",
    default_score = 1,
    action = false,
    dynamic_scan = false,
    symbol = "PEEKABOO",
    symbol_report = 'PEEKABOO_REPORT',
    symbol_type = 'callback',
    symbol_report_type = 'postfilter',
    symbols = {
      peekaboo_good = {
        symbol = 'PEEKABOO_GOOD';
        score = -1.0;
        description = "The Peekaboo Whitelist entry";
      },
      peekaboo_pass = {
        symbol = 'PEEKABOO_PASS';
        score = 0.0;
        description = "The Peekaboo no threat detected";
      },
      peekaboo_in_process = {
        symbol = 'PEEKABOO_IN_PROCESS';
        score = 0;
        description = "The Peekaboo analysis was not finished";
      }
    },
    peekaboo_cache_name = N..'_jobs'
  }

  peekaboo_conf = lua_util.override_defaults(peekaboo_conf, opts)

  if not peekaboo_conf.prefix then
    peekaboo_conf.prefix = 'rs_' .. peekaboo_conf.name .. '_'
  end

  if not peekaboo_conf.log_prefix then
    if peekaboo_conf.name:lower() == peekaboo_conf.type:lower() then
      peekaboo_conf.log_prefix = peekaboo_conf.name
    else
      peekaboo_conf.log_prefix = peekaboo_conf.name .. ' (' .. peekaboo_conf.type .. ')'
    end
  end

  if not peekaboo_conf.servers then
    rspamd_logger.errx(rspamd_config, 'no servers defined')

    return nil
  end

  peekaboo_conf.upstreams = upstream_list.create(rspamd_config,
      peekaboo_conf.servers,
      peekaboo_conf.default_port)

  if peekaboo_conf.upstreams then
    lua_util.add_debug_alias('external_services', peekaboo_conf.name)
    return peekaboo_conf
  end

  rspamd_logger.errx(rspamd_config, 'cannot parse servers %s',
      peekaboo_conf.servers)
  return nil
end

local function peekaboo_url(rule, addr, maybe_url)
  local url
  local port = addr:get_port()

  if port == 0 then
    port = rule.default_port
  end
  if rule.use_https then
    url = string.format('https://%s:%d%s', tostring(addr),
        port, maybe_url)
  else
    url = string.format('http://%s:%d%s', tostring(addr),
        port, maybe_url)
  end

  return url
end


local function peekaboo_check(task, content, digest, rule, maybe_part)
  local function peekaboo_check_uncached ()
    local upstream = rule.upstreams:get_upstream_round_robin()
    local addr = upstream:get_addr()
    local retransmits = rule.retransmits
    local log_prefix = rule.log_prefix..'_check'

    local request_url = peekaboo_url(rule, addr, rule.url_check)

    local form_data = {}
    local request_headers = {
      ['Content-Type'] = string.format('multipart/form-data; boundary="%s"', static_boundary)
    }

    local content_disposition = maybe_part:get_header('Content-Disposition')
    if content_disposition and string.sub(content_disposition,1,6) == 'inline' then
      request_headers['X-Content-Disposition'] = 'inline'
    end

    local mime_type, mime_subtype, mime_attr = maybe_part:get_type_full()

    local detected_extension = maybe_part:get_detected_ext()

    table.insert(form_data, string.format('--%s\r\n', static_boundary))
    if mime_attr['name'] then
      table.insert(form_data,
          string.format('Content-Disposition: form-data; name="file"; filename="%s"\r\n',
              mime_attr['name']))
    elseif detected_extension then
      table.insert(form_data,
          string.format('Content-Disposition: form-data; name="file"; filename="file.%s"\r\n',
              detected_extension))
    else
      table.insert(form_data,
          string.format('Content-Disposition: form-data; name="file"; filename=""\r\n'))
    end

    if mime_type then
      table.insert(form_data,
          string.format('Content-Type: %s/%s\r\n', mime_type, mime_subtype))
    else
      table.insert(form_data, 'Content-Type: text/plain\r\n')
    end

    lua_util.debugm(N, task, '%s: form-data BODY : %s', log_prefix, form_data)

    table.insert(form_data, '\r\n')
    table.insert(form_data, content)
    table.insert(form_data, '\r\n')
    table.insert(form_data, string.format('--%s--\r\n', static_boundary))

    lua_util.debugm(N, task, '%s: HTTP headers : %s', log_prefix, request_headers)

    local function peekaboo_callback(err_message, code, body, headers)

      local function peekaboo_requery(error)
        -- set current upstream to fail because an error occurred
        upstream:fail()

        -- retry with another upstream until retransmits exceeds
        if retransmits > 0 then

          retransmits = retransmits - 1

          -- Select a different upstream!
          upstream = rule.upstreams:get_upstream_round_robin()
          if not upstream then
            common.yield_result(task, rule,
                'no upstream available for retry', 0.0, 'fail', maybe_part)
            return
          end
          addr = upstream:get_addr()

          lua_util.debugm(N, task, '%s: error: %s; retry IP: %s; retries left: %s',
            log_prefix, error, addr, retransmits)

          request_url = peekaboo_url(rule, addr, rule.url_check)

          rspamd_http.request({
            task=task,
            url=request_url,
            timeout=rule.timeout,
            body=form_data,
            callback=peekaboo_callback,
            headers=request_headers,
            gzip=rule.use_gzip,
            no_ssl_verify=rule.no_ssl_verify,
            keepalive=rule.keepalive,
          })
        else
          rspamd_logger.errx(task, '%s: failed to scan, maximum retransmits '..
              'exceed - err: %s', log_prefix, error)
          common.yield_result(task, rule,
              'failed to scan, maximum retransmits exceed - err: ' .. error,
              0.0, 'fail', maybe_part)
        end
      end

      if err_message or (code and tonumber(code) >= 500) then

        if not code then code = 'error' end
        peekaboo_requery(code..' - '..err_message)

      else
        -- Parse the response
        if upstream then upstream:ok() end

        local peekaboo_jobs_table = task:cache_get(rule.peekaboo_cache_name) or {}

        lua_util.debugm(N, task, '%s: return_debug: %s', log_prefix, tostring(body))

        local ucl_parser = ucl.parser()
        local ok, ucl_err = ucl_parser:parse_string(tostring(body))
        if not ok then
          rspamd_logger.errx(task, "%s: error parsing json response, retry: %s",
            log_prefix, ucl_err)
          peekaboo_requery(ucl_err)
          return
        end

        local result = ucl_parser:get_object()

        lua_util.debugm(N, task, '%s: Job ID: %s', log_prefix, result.job_id)
        peekaboo_jobs_table[digest] = result.job_id
        task:cache_set(rule.peekaboo_cache_name, peekaboo_jobs_table)

      end
    end

    rspamd_http.request({
      task=task,
      url=request_url,
      timeout=rule.timeout,
      body=form_data,
      callback=peekaboo_callback,
      headers=request_headers,
      gzip=rule.use_gzip,
      no_ssl_verify=rule.no_ssl_verify,
      keepalive=rule.keepalive,
    })

  end

  if common.condition_check_and_continue(task, content, rule, digest,
      peekaboo_check_uncached, maybe_part) then
    return
  else
    peekaboo_check_uncached()
  end

end

local function peekaboo_report(task, content, digest, rule, maybe_part)

  local upstream = rule.upstreams:get_upstream_round_robin()
  local addr = upstream:get_addr()
  local retransmits = rule.retransmits
  local log_prefix = rule.log_prefix..'_report'

  local request_url = peekaboo_url(rule, addr, rule.url_report)

  local peekaboo_jobs_table = task:cache_get(rule.peekaboo_cache_name)

  if not peekaboo_jobs_table then return end

  local job_id = peekaboo_jobs_table[digest]

  local function peekaboo_callback(err_message, code, body, headers)

    local function peekaboo_requery(error)
      -- set current upstream to fail because an error occurred
      upstream:fail()

      -- retry with another upstream until retransmits exceeds
      if retransmits > 0 then

        retransmits = retransmits - 1

        -- Select a different upstream!
        upstream = rule.upstreams:get_upstream_round_robin()
        if not upstream then
          common.yield_result(task, rule,
              'no upstream available for retry', 0.0, 'fail', maybe_part)
          return
        end
        addr = upstream:get_addr()

        request_url = peekaboo_url(rule, addr, rule.url_report)

        lua_util.debugm(N, task, '%s error: %s; retry IP: %s; retries left: %s',
          log_prefix, error, addr, retransmits)

        rspamd_http.request({
          task=task,
          url=request_url..'/'..job_id,
          callback=peekaboo_callback,
          timeout = rule.timeout,
          mime_type='text/plain',
          no_ssl_verify=rule.no_ssl_verify,
          keepalive=rule.keepalive,
        })
      else
        rspamd_logger.errx(task, '%s: failed to scan, maximum retransmits '..
            'exceed - err: %s', log_prefix, error)
        common.yield_result(task, rule,
            'failed to scan, maximum retransmits exceed - err: ' .. error,
            0.0, 'fail', maybe_part)
      end
    end

    if err_message or (code and tonumber(code) >= 500) then

      if not code then code = 'error' end
      peekaboo_requery(code..' - '..err_message)

    elseif tonumber(code) == 404 then

      lua_util.debugm(N, task, '%s: got 404 - not finished for job: %s',
        log_prefix, job_id)
      common.yield_result(task, rule, string.format('job_id: %s', job_id),
        0.0, rule.symbols.peekaboo_in_process.symbol, maybe_part)
    else
      -- Parse the response
      if upstream then upstream:ok() end
      local ucl_parser = ucl.parser()
      local ok, ucl_err = ucl_parser:parse_string(tostring(body))
      if not ok then
        rspamd_logger.errx(task, "%s %s: error parsing json response, retry: %s",
          log_prefix, job_id, ucl_err)
        peekaboo_requery(ucl_err)
        return
      end

      local result = ucl_parser:get_object()

      lua_util.debugm(N, task, '%s: job-id %s - JSON OBJECT - %s', log_prefix, job_id, result)

      if result.result and tostring(result.result) ~= '' then
        if tostring(result.result) == 'bad' then
          lua_util.debugm(N, task, '%s: job-id %s - found bad result - %s (%s)',
            log_prefix, job_id, result.result, result.reason)
          common.yield_result(task, rule, string.format("job-id %s: %s", job_id, result.reason),
            1.0, nil, maybe_part)
          common.save_cache(task, digest, rule,
            string.format("job-id %s: %s", job_id, result.reason), 1.0, maybe_part)
        elseif tostring(result.result) == 'failed' or tostring(result.result) == 'unchecked' then
          lua_util.debugm(N, task, '%s: job-id %s - found failed/unchecked result - %s (%s)',
            log_prefix, job_id, result.result, result.reason)
          common.yield_result(task, rule, string.format("job-id %s: %s", job_id, result.reason),
            1.0, 'fail', maybe_part)
        elseif tostring(result.result) == 'good' then
          lua_util.debugm(N, task, '%s: job-id %s - found good result - %s (%s)',
            log_prefix, job_id, result.result, result.reason)
          common.yield_result(task, rule, string.format("job-id %s: %s", job_id, result.reason),
            rule.symbols.peekaboo_good.score, rule.symbols.peekaboo_good.symbol, maybe_part)
        elseif tostring(result.result) == 'ignored' then
          lua_util.debugm(N, task, '%s: job-id %s - found ignored result - %s (%s)',
            log_prefix, job_id, result.result, result.reason)
        elseif tostring(result.result) == 'unknown' then
          if rule.set_clean_symbol then
            common.yield_result(task, rule, string.format("job-id %s: %s", job_id, result.reason),
              rule.symbols.peekaboo_pass.score, rule.symbols.peekaboo_pass.symbol, maybe_part)
          end
          lua_util.debugm(N, task, '%s: job-id %s - found unknown result (no threat found) - %s (%s)',
            log_prefix, job_id, result.result, result.reason)
        end
      else
        rspamd_logger.errx(task, "%s %s: REPORT no result found: %s (%s)",
          log_prefix, job_id, result.result, type(result.result))
      end
    end
  end

  if job_id and tostring(job_id) ~= "" then
    lua_util.debugm(N, task, '%s: Calling Job-ID : %s', log_prefix, job_id)
    rspamd_http.request({
      task=task,
      url=request_url..'/'..job_id,
      callback=peekaboo_callback,
      timeout = rule.timeout,
      mime_type='text/plain',
      no_ssl_verify=rule.no_ssl_verify,
      keepalive=rule.keepalive,
    })
  else
    rspamd_logger.infox(task, "%s: JOB-ID for part not in cache",
      log_prefix)
  end
end

return {
  type = {N, 'attachment scanner', 'hash', 'scanner'},
  description = 'Peekaboo Sandbox Threat Scanner',
  configure = peekaboo_config,
  check = peekaboo_check,
  report = peekaboo_report,
  name = N
}
