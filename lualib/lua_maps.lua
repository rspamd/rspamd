--[[[
-- @module lua_maps
-- This module contains helper functions for managing rspamd maps
--]]

--[[
Copyright (c) 2022, Vsevolod Stakhov <vsevolod@rspamd.com>

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

local rspamd_logger = require "rspamd_logger"
local ts = require("tableshape").types
local lua_util = require "lua_util"

local exports = {}

local maps_cache = {}

local function map_hash_key(data, mtype)
  local hash = require "rspamd_cryptobox_hash"
  local st = hash.create_specific('xxh64')
  st:update(data)
  st:update(mtype)

  return st:hex()
end

local function starts(where,st)
  return string.sub(where,1,string.len(st))==st
end

local function cut_prefix(where,st)
  return string.sub(where,#st + 1)
end

local function maybe_adjust_type(data,mtype)
  local function check_prefix(prefix, t)
    if starts(data, prefix) then
      data = cut_prefix(data, prefix)
      mtype = t

      return true
    end

    return false
  end

  local known_types = {
    {'regexp;', 'regexp'},
    {'re;', 'regexp'},
    {'regexp_multi;', 'regexp_multi'},
    {'re_multi;', 'regexp_multi'},
    {'glob;', 'glob'},
    {'glob_multi;', 'glob_multi'},
    {'radix;', 'radix'},
    {'ipnet;', 'radix'},
    {'set;', 'set'},
    {'hash;', 'hash'},
    {'plain;', 'hash'},
    {'cdb;', 'cdb'},
    {'cdb:/', 'cdb'},
  }

  if mtype == 'callback' then
    return mtype
  end

  for _,t in ipairs(known_types) do
    if check_prefix(t[1], t[2]) then
      return data,mtype
    end
  end

  -- No change
  return data,mtype
end


local external_map_schema = ts.shape{
  external = ts.equivalent(true), -- must be true
  backend = ts.string, -- where to get data, required
  method = ts.one_of{"body", "header", "query"}, -- how to pass input
  encode = ts.one_of{"json", "messagepack"}:is_optional(), -- how to encode input (if relevant)
  timeout = (ts.number + ts.string / lua_util.parse_time_interval):is_optional(),
}

local rspamd_http = require "rspamd_http"
local ucl = require "ucl"

local function url_encode_string(str)
  -- TODO: implement encoding
  return str
end

local function query_external_map(map_config, upstreams, key, callback, task)
  local http_method = (map_config.method == 'body' or map_config.method == 'form') and 'POST' or 'GET'
  local upstream = upstreams:get_upstream_round_robin()
  local http_headers = {}
  local http_body = nil
  local url = map_config.backend

  if type(key) == 'string' or type(key) == 'userdata' then
    if map_config.method == 'body' then
      http_body = key
    elseif map_config.method == 'header' then
      http_headers = {
        key = key
      }
    elseif map_config.method == 'query' then
      url = string.format('%s?%s', url, url_encode_string(key))
    end
  elseif type(key) == 'table' then
    if map_config.method == 'body' then
      if map_config.encode == 'json' then
        http_body = ucl.to_format(key, 'json-compact', true)
      elseif map_config.encode == 'messagepack' then
        http_body = ucl.to_format(key, 'messagepack', true)
      else
        local caller = debug.getinfo(2) or {}
        rspamd_logger.errx(task,
            "requested external map key with a wrong combination body method and missing encode; caller: %s:%s",
            caller.short_src, caller.currentline)
        callback(false, 'invalid map usage', 500, task)
      end
    else
      -- query/header and no encode
      if map_config.method == 'query' then
        -- TODO: encode key/value pairs into query params
      elseif map_config.method == 'header' then
        http_headers = key
      else
        local caller = debug.getinfo(2) or {}
        rspamd_logger.errx(task,
            "requested external map key with a wrong combination of encode and input; caller: %s:%s",
            caller.short_src, caller.currentline)
        callback(false, 'invalid map usage', 500, task)

        return
      end
    end
  end

  local function map_callback(err, code, body, _)
    if err then
      callback(false, err, code, task)
    else
      callback(true, body, 200, task)
    end
  end

  local ret = rspamd_http.request{
    task = task,
    url = map_config.backend,
    callback = map_callback,
    timeout = map_config.timeout or 1.0,
    keepalive = true,
    upstream = upstream,
    method = http_method,
    headers = http_headers,
    body = http_body,
  }

  if not ret then
    callback(false, 'http request error', 500, task)
  end
end

--[[[
-- @function lua_maps.map_add_from_ucl(opt, mtype, description)
-- Creates a map from static data
-- Returns true if map was added or nil
-- @param {string or table} opt data for map (or URL)
-- @param {string} mtype type of map (`set`, `map`, `radix`, `regexp`)
-- @param {string} description human-readable description of map
-- @param {function} callback optional callback that will be called on map match (required for external maps)
-- @return {bool} true on success, or `nil`
--]]
local function rspamd_map_add_from_ucl(opt, mtype, description, callback)
  local ret = {
    get_key = function(t, k, key_callback, task)
      if t.__data then
        local cb = key_callback or callback
        if t.__external then
          if cb or not task then
            local caller = debug.getinfo(2) or {}
            rspamd_logger.errx(rspamd_config, "requested external map key without callback; caller: %s:%s",
                caller.short_src, caller.currentline)
            return nil
          end
          query_external_map(t.__data, t.__upstreams, k, cb, task)
        else
          local result = t.__data:get_key(k)
          if cb then
            if result then
              cb(true, result, 200, task)
            else
              cb(false, 'not found', 404, task)
            end
          else
            return result
          end
        end
      end

      return nil
    end
  }
  local ret_mt = {
    __index = function(t, k, key_callback, task)
      if t.__data then
        return t.get_key(k, key_callback, task)
      end

      return nil
    end
  }

  if not opt then
    return nil
  end

  if type(opt) == 'string' then
    opt,mtype = maybe_adjust_type(opt, mtype)
    local cache_key = map_hash_key(opt, mtype)
    if not callback and maps_cache[cache_key] then
      rspamd_logger.infox(rspamd_config, 'reuse url for %s(%s)',
          opt, mtype)

      return maps_cache[cache_key]
    end
    -- We have a single string, so we treat it as a map
    local map = rspamd_config:add_map{
      type = mtype,
      description = description,
      url = opt,
    }

    if map then
      ret.__data = map
      ret.hash = cache_key
      setmetatable(ret, ret_mt)
      maps_cache[cache_key] = ret
      return ret
    end
  elseif type(opt) == 'table' then
    local cache_key = lua_util.table_digest(opt)
    if not callback and maps_cache[cache_key] then
      rspamd_logger.infox(rspamd_config, 'reuse url for complex map definition %s: %s',
          cache_key:sub(1,8), description)

      return maps_cache[cache_key]
    end

    if opt[1] then
      -- Adjust each element if needed
      local adjusted
      for i,source in ipairs(opt) do
        local nsrc,ntype = maybe_adjust_type(source, mtype)

        if mtype ~= ntype then
          if not adjusted then
            mtype = ntype
          end
          adjusted = true
        end
        opt[i] = nsrc
      end

      if mtype == 'radix' then

        if string.find(opt[1], '^%d') then
          local map = rspamd_config:radix_from_ucl(opt)

          if map then
            ret.__data = map
            setmetatable(ret, ret_mt)
            maps_cache[cache_key] = ret
            return ret
          end
        else
          -- Plain table
          local map = rspamd_config:add_map{
            type = mtype,
            description = description,
            url = opt,
          }
          if map then
            ret.__data = map
            setmetatable(ret, ret_mt)
            maps_cache[cache_key] = ret
            return ret
          end
        end
      elseif mtype == 'regexp' or mtype == 'glob' then
        if string.find(opt[1], '^/%a') or string.find(opt[1], '^http') then
          -- Plain table
          local map = rspamd_config:add_map{
            type = mtype,
            description = description,
            url = opt,
          }
          if map then
            ret.__data = map
            setmetatable(ret, ret_mt)
            maps_cache[cache_key] = ret
            return ret
          end
        else
          local map = rspamd_config:add_map{
            type = mtype,
            description = description,
            url = {
              url = 'static',
              data = opt,
            }
          }
          if map then
            ret.__data = map
            setmetatable(ret, ret_mt)
            maps_cache[cache_key] = ret
            return ret
          end
        end
      else
        if string.find(opt[1], '^/%a') or string.find(opt[1], '^http') then
          -- Plain table
          local map = rspamd_config:add_map{
            type = mtype,
            description = description,
            url = opt,
          }
          if map then
            ret.__data = map
            setmetatable(ret, ret_mt)
            maps_cache[cache_key] = ret
            return ret
          end
        else
          local data = {}
          local nelts = 0
          -- Plain array of keys, count merely numeric elts
          for _,elt in ipairs(opt) do
            if type(elt) == 'string' then
              -- Numeric table
              if mtype == 'hash' then
                -- Treat as KV pair
                local pieces = lua_util.str_split(elt, ' ')
                if #pieces > 1 then
                  local key = table.remove(pieces, 1)
                  data[key] = table.concat(pieces, ' ')
                else
                  data[elt] = true
                end
              else
                data[elt] = true
              end

              nelts = nelts + 1
            end
          end

          if nelts > 0 then
            -- Plain Lua table that is used as a map
            ret.__data = data
            ret.get_key = function(t, k)
              if k ~= '__data' then
                return t.__data[k]
              end

              return nil
            end

            maps_cache[cache_key] = ret
            return ret
          else
            -- Empty map, huh?
            rspamd_logger.errx(rspamd_config, 'invalid map element: %s',
                opt)
          end
        end
      end
    else
      if opt.external then
        -- External map definition, missing fields are handled by schema
        local parse_res,parse_err = external_map_schema(opt)

        if parse_res then
          ret.__upstreams = lua_util.http_upstreams_by_url(rspamd_config:get_mempool(), opt.backend)
          if ret.__upstreams then
            ret.__data = opt
            ret.__external = true
            setmetatable(ret, ret_mt)

            return ret
          else
            rspamd_logger.errx(rspamd_config, 'cannot parse external map upstreams: %s',
                opt.backend)
          end
        else
          rspamd_logger.errx(rspamd_config, 'cannot parse external map: %s',
              parse_err)
        end
      else
        -- We have some non-trivial object so let C code to deal with it somehow...
        local map = rspamd_config:add_map{
          type = mtype,
          description = description,
          url = opt,
        }
        if map then
          ret.__data = map
          setmetatable(ret, ret_mt)
          maps_cache[cache_key] = ret
          return ret
        end
      end
    end -- opt[1]
  end

  return nil
end

--[[[
-- @function lua_maps.map_add(mname, optname, mtype, description)
-- Creates a map from configuration elements (static data or URL)
-- Returns true if map was added or nil
-- @param {string} mname config section to use
-- @param {string} optname option name to use
-- @param {string} mtype type of map ('set', 'hash', 'radix', 'regexp', 'glob')
-- @param {string} description human-readable description of map
-- @param {function} callback optional callback that will be called on map match (required for external maps)
-- @return {bool} true on success, or `nil`
--]]

local function rspamd_map_add(mname, optname, mtype, description, callback)
  local opt = rspamd_config:get_module_opt(mname, optname)

  return rspamd_map_add_from_ucl(opt, mtype, description, callback)
end

exports.rspamd_map_add = rspamd_map_add
exports.map_add = rspamd_map_add
exports.rspamd_map_add_from_ucl = rspamd_map_add_from_ucl
exports.map_add_from_ucl = rspamd_map_add_from_ucl

-- Check `what` for being lua_map name, otherwise just compares key with what
local function rspamd_maybe_check_map(key, what)
  local fun = require "fun"

  if type(what) == "table" then
    return fun.any(function(elt) return rspamd_maybe_check_map(key, elt) end, what)
  end
  if type(rspamd_maps) == "table" then
    local mn
    if starts(what, "map:") then
      mn = string.sub(what, 4)
    elseif starts(what, "map://") then
      mn = string.sub(what, 6)
    end

    if mn and rspamd_maps[mn] then
      return rspamd_maps[mn]:get_key(key)
    else
      return what:lower() == key
    end
  else
    return what:lower() == key
  end

end

exports.rspamd_maybe_check_map = rspamd_maybe_check_map

--[[[
-- @function lua_maps.fill_config_maps(mname, options, defs)
-- Fill maps that could be defined in defs, from the config in the options
-- Defs is a table indexed by a map's parameter name and defining it's config,
-- for example:
defs = {
  my_map = {
    type = 'map',
    description = 'my cool map',
    optional = true,
  }
}
-- Then this function will look for opts.my_map parameter and try to replace it's with
-- a map with the specific type, description but not failing if it was empty.
-- It will also set options.my_map_orig to the original value defined in the map
--]]
exports.fill_config_maps = function(mname, opts, map_defs)
  assert(type(opts) == 'table')
  assert(type(map_defs) == 'table')
  for k, v in pairs(map_defs) do
    if opts[k] then
      local map = rspamd_map_add_from_ucl(opts[k], v.type or 'map', v.description)
      if not map then
        rspamd_logger.errx(rspamd_config, 'map add error %s for module %s', k, mname)
        return false
      end
      opts[k..'_orig'] = opts[k]
      opts[k] = map
    elseif not v.optional then
      rspamd_logger.errx(rspamd_config, 'cannot find non optional map %s for module %s', k, mname)
      return false
    end
  end

  return true
end

local direct_map_schema = ts.shape{ -- complex object
  name = ts.string:is_optional(),
  description = ts.string:is_optional(),
  timeout = ts.number,
  data = ts.array_of(ts.string):is_optional(),
  -- Tableshape has no options support for something like key1 or key2?
  upstreams = ts.one_of{
    ts.string,
    ts.array_of(ts.string),
  }:is_optional(),
  url = ts.one_of{
    ts.string,
    ts.array_of(ts.string),
  }:is_optional(),
}

exports.map_schema = ts.one_of{
  ts.string, -- 'http://some_map'
  ts.array_of(ts.string), -- ['foo', 'bar']
  ts.one_of{direct_map_schema, external_map_schema}
}

return exports
