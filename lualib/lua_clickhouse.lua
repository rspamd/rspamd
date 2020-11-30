--[[
Copyright (c) 2018, Vsevolod Stakhov <vsevolod@highsecure.ru>
Copyright (c) 2018, Mikhail Galanin <mgalanin@mimecast.com>

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
-- @module lua_clickhouse
-- This module contains Clickhouse access functions
--]]

local rspamd_logger = require "rspamd_logger"
local rspamd_http = require "rspamd_http"
local lua_util = require "lua_util"
local rspamd_text = require "rspamd_text"

local exports = {}
local N = 'clickhouse'

local default_timeout = 10.0

local function escape_spaces(query)
  return query:gsub('%s', '%%20')
end

local function ch_number(a)
  if (a+2^52)-2^52 == a then
    -- Integer
    return tostring(math.floor(a))
  end

  return tostring(a)
end

local function clickhouse_quote(str)
  if str then
    return str:gsub('[\'\\\n\t\r]', {
      ['\''] = [[\']],
      ['\\'] = [[\\]],
      ['\n'] = [[\n]],
      ['\t'] = [[\t]],
      ['\r'] = [[\r]],
    })
  end

  return ''
end

-- Converts an array to a string suitable for clickhouse
local function array_to_string(ar)
  for i,elt in ipairs(ar) do
    local t = type(elt)
    if t == 'string' then
      ar[i] = string.format('\'%s\'', clickhouse_quote(elt))
    elseif t == 'userdata' then
      ar[i] = string.format('\'%s\'', clickhouse_quote(tostring(elt)))
    elseif t == 'number' then
      ar[i] = ch_number(elt)
    end
  end

  return table.concat(ar, ',')
end

-- Converts a row into TSV, taking extra care about arrays
local function row_to_tsv(row)

  for i,elt in ipairs(row) do
    local t = type(elt)
    if t == 'table' then
      row[i] = '[' .. array_to_string(elt) .. ']'
    elseif t == 'number' then
      row[i] = ch_number(elt)
    elseif t == 'userdata' then
      row[i] = clickhouse_quote(tostring(elt))
    else
      row[i] = clickhouse_quote(elt)
    end
  end

  return rspamd_text.fromtable(row, '\t')
end

exports.row_to_tsv = row_to_tsv

-- Parses JSONEachRow reply from CH
local function parse_clickhouse_response_json_eachrow(params, data, row_cb)
  local ucl = require "ucl"

  if data == nil then
    -- clickhouse returned no data (i.e. empty result set): exiting
    return {}
  end

  local function parse_string(s)
    local parser = ucl.parser()
    local res, err
    if type(s) == 'string' then
      res,err = parser:parse_string(s)
    else
      res,err = parser:parse_text(s)
    end

    if not res then
      rspamd_logger.errx(params.log_obj, 'Parser error: %s', err)
      return nil
    end
    return parser:get_object()
  end

  -- iterate over rows and parse
  local parsed_rows = {}
  for plain_row in data:lines() do
    if plain_row and #plain_row > 1 then
      local parsed_row = parse_string(plain_row)
      if parsed_row then
        if row_cb then
          row_cb(parsed_row)
        else
          table.insert(parsed_rows, parsed_row)
        end
      end
    end
  end

  return parsed_rows
end

-- Parses JSON reply from CH
local function parse_clickhouse_response_json(params, data)
  local ucl = require "ucl"

  if data == nil then
    -- clickhouse returned no data (i.e. empty result set) considered valid!
    return nil, {}
  end

  local function parse_string(s)
    local parser = ucl.parser()
    local res, err

    if type(s) == 'string' then
      res,err = parser:parse_string(s)
    else
      res,err = parser:parse_text(s)
    end

    if not res then
      rspamd_logger.errx(params.log_obj, 'Parser error: %s', err)
      return nil
    end
    return parser:get_object()
  end

  local json = parse_string(data)

  if not json then
    return 'bad json', {}
  end

  return nil,json
end

-- Helper to generate HTTP closure
local function mk_http_select_cb(upstream, params, ok_cb, fail_cb, row_cb)
  local function http_cb(err_message, code, data, _)
    if code ~= 200 or err_message then
      if not err_message then err_message = data end
      local ip_addr = upstream:get_addr():to_string(true)

      if fail_cb then
        fail_cb(params, err_message, data)
      else
        rspamd_logger.errx(params.log_obj,
            "request failed on clickhouse server %s: %s",
            ip_addr, err_message)
      end
      upstream:fail()
    else
      upstream:ok()
      local rows = parse_clickhouse_response_json_eachrow(params, data, row_cb)

      if rows then
        if ok_cb then
          ok_cb(params, rows)
        else
          lua_util.debugm(N, params.log_obj,
              "http_select_cb ok: %s, %s, %s, %s", err_message, code,
              data:gsub('[\n%s]+', ' '), _)
        end
      else
        if fail_cb then
          fail_cb(params, 'failed to parse reply', data)
        else
          local ip_addr = upstream:get_addr():to_string(true)
          rspamd_logger.errx(params.log_obj,
            "request failed on clickhouse server %s: %s",
            ip_addr, 'failed to parse reply')
        end
      end
    end
  end

  return http_cb
end

-- Helper to generate HTTP closure
local function mk_http_insert_cb(upstream, params, ok_cb, fail_cb)
  local function http_cb(err_message, code, data, _)
    if code ~= 200 or err_message then
      if not err_message then err_message = data end
      local ip_addr = upstream:get_addr():to_string(true)

      if fail_cb then
        fail_cb(params, err_message, data)
      else
        rspamd_logger.errx(params.log_obj,
            "request failed on clickhouse server %s: %s",
            ip_addr, err_message)
      end
      upstream:fail()
    else
      upstream:ok()

      if ok_cb then
        local err,parsed = parse_clickhouse_response_json(data)

        if err then
          fail_cb(params, err, data)
        else
          ok_cb(params, parsed)
        end

      else
        lua_util.debugm(N, params.log_obj,
            "http_insert_cb ok: %s, %s, %s, %s", err_message, code,
            data:gsub('[\n%s]+', ' '), _)
      end
    end
  end

  return http_cb
end

--[[[
-- @function lua_clickhouse.select(upstream, settings, params, query,
      ok_cb, fail_cb)
-- Make select request to clickhouse
-- @param {upstream} upstream clickhouse server upstream
-- @param {table} settings global settings table:
--   * use_gsip: use gzip compression
--   * timeout: request timeout
--   * no_ssl_verify: skip SSL verification
--   * user: HTTP user
--   * password: HTTP password
-- @param {params} HTTP request params
-- @param {string} query select query (passed in HTTP body)
-- @param {function} ok_cb callback to be called in case of success
-- @param {function} fail_cb callback to be called in case of some error
-- @param {function} row_cb optional callback to be called on each parsed data row (instead of table insertion)
-- @return {boolean} whether a connection was successful
-- @example
--
--]]
exports.select = function (upstream, settings, params, query, ok_cb, fail_cb, row_cb)
  local http_params = {}

  for k,v in pairs(params) do http_params[k] = v end

  http_params.callback = mk_http_select_cb(upstream, http_params, ok_cb, fail_cb, row_cb)
  http_params.gzip = settings.use_gzip
  http_params.mime_type = 'text/plain'
  http_params.timeout = settings.timeout or default_timeout
  http_params.no_ssl_verify = settings.no_ssl_verify
  http_params.user = settings.user
  http_params.password = settings.password
  http_params.body = query
  http_params.log_obj = params.task or params.config
  http_params.opaque_body = true

  lua_util.debugm(N, http_params.log_obj, "clickhouse select request: %s", http_params.body)

  if not http_params.url then
    local connect_prefix = "http://"
    if settings.use_https then
      connect_prefix = 'https://'
    end
    local ip_addr = upstream:get_addr():to_string(true)
    local database = settings.database or 'default'
    http_params.url = string.format('%s%s/?database=%s&default_format=JSONEachRow',
        connect_prefix, ip_addr, escape_spaces(database))
  end

  return rspamd_http.request(http_params)
end

--[[[
-- @function lua_clickhouse.select_sync(upstream, settings, params, query,
      ok_cb, fail_cb, row_cb)
-- Make select request to clickhouse
-- @param {upstream} upstream clickhouse server upstream
-- @param {table} settings global settings table:
--   * use_gsip: use gzip compression
--   * timeout: request timeout
--   * no_ssl_verify: skip SSL verification
--   * user: HTTP user
--   * password: HTTP password
-- @param {params} HTTP request params
-- @param {string} query select query (passed in HTTP body)
-- @param {function} ok_cb callback to be called in case of success
-- @param {function} fail_cb callback to be called in case of some error
-- @param {function} row_cb optional callback to be called on each parsed data row (instead of table insertion)
-- @return
--          {string} error message if exists
--          nil | {rows} | {http_response}
-- @example
--
--]]
exports.select_sync = function (upstream, settings, params, query, row_cb)
  local http_params = {}

  for k,v in pairs(params) do http_params[k] = v end

  http_params.gzip = settings.use_gzip
  http_params.mime_type = 'text/plain'
  http_params.timeout = settings.timeout or default_timeout
  http_params.no_ssl_verify = settings.no_ssl_verify
  http_params.user = settings.user
  http_params.password = settings.password
  http_params.body = query
  http_params.log_obj = params.task or params.config
  http_params.opaque_body = true

  lua_util.debugm(N, http_params.log_obj, "clickhouse select request: %s", http_params.body)

  if not http_params.url then
    local connect_prefix = "http://"
    if settings.use_https then
      connect_prefix = 'https://'
    end
    local ip_addr = upstream:get_addr():to_string(true)
    local database = settings.database or 'default'
    http_params.url = string.format('%s%s/?database=%s&default_format=JSONEachRow',
        connect_prefix, ip_addr, escape_spaces(database))
  end

  local err, response = rspamd_http.request(http_params)

  if err then
    return err, nil
  elseif response.code ~= 200 then
    return response.content, response
  else
    lua_util.debugm(N, http_params.log_obj, "clickhouse select response: %1", response)
    local rows = parse_clickhouse_response_json_eachrow(params, response.content, row_cb)
    return nil, rows
  end
end

--[[[
-- @function lua_clickhouse.insert(upstream, settings, params, query, rows,
      ok_cb, fail_cb)
-- Insert data rows to clickhouse
-- @param {upstream} upstream clickhouse server upstream
-- @param {table} settings global settings table:
--   * use_gsip: use gzip compression
--   * timeout: request timeout
--   * no_ssl_verify: skip SSL verification
--   * user: HTTP user
--   * password: HTTP password
-- @param {params} HTTP request params
-- @param {string} query select query (passed in `query` request element with spaces escaped)
-- @param {table|mixed} rows mix of strings, numbers or tables (for arrays)
-- @param {function} ok_cb callback to be called in case of success
-- @param {function} fail_cb callback to be called in case of some error
-- @return {boolean} whether a connection was successful
-- @example
--
--]]
exports.insert = function (upstream, settings, params, query, rows,
                              ok_cb, fail_cb)
  local http_params = {}

  for k,v in pairs(params) do http_params[k] = v end

  http_params.callback = mk_http_insert_cb(upstream, http_params, ok_cb, fail_cb)
  http_params.gzip = settings.use_gzip
  http_params.mime_type = 'text/plain'
  http_params.timeout = settings.timeout or default_timeout
  http_params.no_ssl_verify = settings.no_ssl_verify
  http_params.user = settings.user
  http_params.password = settings.password
  http_params.method = 'POST'
  http_params.body = {rspamd_text.fromtable(rows, '\n'), '\n'}
  http_params.log_obj = params.task or params.config

  if not http_params.url then
    local connect_prefix = "http://"
    if settings.use_https then
      connect_prefix = 'https://'
    end
    local ip_addr = upstream:get_addr():to_string(true)
    local database = settings.database or 'default'
    http_params.url = string.format('%s%s/?database=%s&query=%s%%20FORMAT%%20TabSeparated',
        connect_prefix,
        ip_addr,
        escape_spaces(database),
        escape_spaces(query))
  end

  return rspamd_http.request(http_params)
end

--[[[
-- @function lua_clickhouse.generic(upstream, settings, params, query,
      ok_cb, fail_cb)
-- Make a generic request to Clickhouse (e.g. alter)
-- @param {upstream} upstream clickhouse server upstream
-- @param {table} settings global settings table:
--   * use_gsip: use gzip compression
--   * timeout: request timeout
--   * no_ssl_verify: skip SSL verification
--   * user: HTTP user
--   * password: HTTP password
-- @param {params} HTTP request params
-- @param {string} query Clickhouse query (passed in `query` request element with spaces escaped)
-- @param {function} ok_cb callback to be called in case of success
-- @param {function} fail_cb callback to be called in case of some error
-- @return {boolean} whether a connection was successful
-- @example
--
--]]
exports.generic = function (upstream, settings, params, query,
                           ok_cb, fail_cb)
  local http_params = {}

  for k,v in pairs(params) do http_params[k] = v end

  http_params.callback = mk_http_insert_cb(upstream, http_params, ok_cb, fail_cb)
  http_params.gzip = settings.use_gzip
  http_params.mime_type = 'text/plain'
  http_params.timeout = settings.timeout or default_timeout
  http_params.no_ssl_verify = settings.no_ssl_verify
  http_params.user = settings.user
  http_params.password = settings.password
  http_params.log_obj = params.task or params.config
  http_params.body = query

  if not http_params.url then
    local connect_prefix = "http://"
    if settings.use_https then
      connect_prefix = 'https://'
    end
    local ip_addr = upstream:get_addr():to_string(true)
    local database = settings.database or 'default'
    http_params.url = string.format('%s%s/?database=%s&default_format=JSONEachRow',
        connect_prefix, ip_addr, escape_spaces(database))
  end

  return rspamd_http.request(http_params)
end

--[[[
-- @function lua_clickhouse.generic_sync(upstream, settings, params, query,
      ok_cb, fail_cb)
-- Make a generic request to Clickhouse (e.g. alter)
-- @param {upstream} upstream clickhouse server upstream
-- @param {table} settings global settings table:
--   * use_gsip: use gzip compression
--   * timeout: request timeout
--   * no_ssl_verify: skip SSL verification
--   * user: HTTP user
--   * password: HTTP password
-- @param {params} HTTP request params
-- @param {string} query Clickhouse query (passed in `query` request element with spaces escaped)
-- @return {boolean} whether a connection was successful
-- @example
--
--]]
exports.generic_sync = function (upstream, settings, params, query)
  local http_params = {}

  for k,v in pairs(params) do http_params[k] = v end

  http_params.gzip = settings.use_gzip
  http_params.mime_type = 'text/plain'
  http_params.timeout = settings.timeout or default_timeout
  http_params.no_ssl_verify = settings.no_ssl_verify
  http_params.user = settings.user
  http_params.password = settings.password
  http_params.log_obj = params.task or params.config
  http_params.body = query

  if not http_params.url then
    local connect_prefix = "http://"
    if settings.use_https then
      connect_prefix = 'https://'
    end
    local ip_addr = upstream:get_addr():to_string(true)
    local database = settings.database or 'default'
    http_params.url = string.format('%s%s/?database=%s&default_format=JSON',
        connect_prefix, ip_addr, escape_spaces(database))
  end

  local err, response = rspamd_http.request(http_params)

  if err then
    return err, nil
  elseif response.code ~= 200 then
    return response.content, response
  else
    lua_util.debugm(N, http_params.log_obj, "clickhouse generic response: %1", response)
    local e,obj = parse_clickhouse_response_json(params, response.content)

    if e then
      return e,nil
    end
    return nil, obj
  end
end

return exports
