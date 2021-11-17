--[[
Copyright (c) 2020, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

-- Controller maps plugin
local maps_cache
local maps_aliases
local lua_util = require "lua_util"
local ts = require("tableshape").types
local ucl = require "ucl"

local function maybe_fill_maps_cache()
  if not maps_cache then
    maps_cache = {}
    maps_aliases = {}
    local maps = rspamd_config:get_maps()
    for _,m in ipairs(maps) do
      -- We get the first url here and that's it
      local url = m:get_uri()
      if url ~= 'static' then
        if not maps_cache[url] then
          local alias = url:match('/([^/]+)$')
          maps_cache[url] = m
          if not maps_aliases[alias] then
            maps_aliases[alias] = url
          end
        else
          -- Do not override, as we don't care about duplicate maps that come from different
          -- sources.
          -- In theory, that should be cached but there are some exceptions even so far...
          url = math.random() -- to shut luacheck about empty branch with a comment
        end
      end
    end
  end
end

local function check_specific_map(input, uri, m, results, report_misses)
  local value = m:get_key(input)

  if value then
    local result = {
      map = uri,
      alias = uri:match('/([^/]+)$'),
      value = value,
      key = input,
      hit = true,
    }
    table.insert(results, result)
  elseif report_misses then
    local result = {
      map = uri,
      alias = uri:match('/([^/]+)$'),
      key = input,
      hit = false,
    }
    table.insert(results, result)
  end
end

local function handle_query_map(_, conn, req_params)
  maybe_fill_maps_cache()
  local keys_to_check = {}

  if req_params.value and req_params.value ~= '' then
    keys_to_check[1] = req_params.value
  elseif req_params.values then
    keys_to_check = lua_util.str_split(req_params.values, ',')
  end

  local results = {}
  for _,key in ipairs(keys_to_check) do
    for uri,m in pairs(maps_cache) do
      check_specific_map(key, uri, m, results, req_params.report_misses)
    end
  end
  conn:send_ucl{
    success = (#results > 0),
    results = results
  }
end

local function handle_query_specific_map(_, conn, req_params)
  maybe_fill_maps_cache()
  -- Fill keys to check
  local keys_to_check = {}
  if req_params.value and req_params.value ~= '' then
    keys_to_check[1] = req_params.value
  elseif req_params.values then
    keys_to_check = lua_util.str_split(req_params.values, ',')
  end
  local maps_to_check = maps_cache
  -- Fill maps to check
  if req_params.maps then
    local map_names = lua_util.str_split(req_params.maps, ',')
    maps_to_check = {}
    for _,mn in ipairs(map_names) do
      if maps_cache[mn] then
        maps_to_check[mn] = maps_cache[mn]
      else
        local alias = maps_aliases[mn]

        if alias then
          maps_to_check[alias] = maps_cache[alias]
        else
          conn:send_error(404, 'no such map: ' .. mn)
        end
      end
    end
  end

  local results = {}
  for _,key in ipairs(keys_to_check) do
    for uri,m in pairs(maps_to_check) do
      check_specific_map(key, uri, m, results, req_params.report_misses)
    end
  end

  conn:send_ucl{
    success = (#results > 0),
    results = results
  }
end

local function handle_list_maps(_, conn, _)
  maybe_fill_maps_cache()
  conn:send_ucl{
    maps = lua_util.keys(maps_cache),
    aliases = maps_aliases
  }
end

local query_json_schema = ts.shape{
  maps = ts.array_of(ts.string):is_optional(),
  report_misses = ts.boolean:is_optional(),
  values = ts.array_of(ts.string),
}

local function handle_query_json(task, conn)
  maybe_fill_maps_cache()

  local parser = ucl.parser()
  local ok, err = parser:parse_text(task:get_rawbody())
  if not ok then
    conn:send_error(400, err)
    return
  end
  local obj = parser:get_object()

  ok, err = query_json_schema:transform(obj)
  if not ok then
    conn:send_error(400, err)
    return
  end

  local maps_to_check = {}
  local report_misses = obj.report_misses
  local results = {}

  if obj.maps then
    for _,mn in ipairs(obj.maps) do
      if maps_cache[mn] then
        maps_to_check[mn] = maps_cache[mn]
      else
        local alias = maps_aliases[mn]

        if alias then
          maps_to_check[alias] = maps_cache[alias]
        else
          conn:send_error(400, 'no such map: ' .. mn)
          return
        end
      end
    end
  else
    maps_to_check = maps_cache
  end

  for _,key in ipairs(obj.values) do
    for uri,m in pairs(maps_to_check) do
      check_specific_map(key, uri, m, results, report_misses)
    end
  end
  conn:send_ucl{
    success = (#results > 0),
    results = results
  }
end

return {
  query = {
    handler = handle_query_map,
    enable = false,
  },
  query_json = {
    handler = handle_query_json,
    enable = false,
    need_task = true,
  },
  query_specific = {
    handler = handle_query_specific_map,
    enable = false,
  },
  list = {
    handler = handle_list_maps,
    enable = false,
  },
}
