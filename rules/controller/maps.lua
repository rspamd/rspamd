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
        end
      end
    end
  end
end

local function handle_query_map(_, conn, req_params)
  maybe_fill_maps_cache()
  if req_params.value and req_params.value ~= '' then
    local results = {}
    for uri,m in pairs(maps_cache) do
      local value = m:get_key(req_params.value)

      if value then
        local result = {
          map = uri,
          alias = uri:match('/([^/]+)$'),
          value = value
        }
        table.insert(results, result)
      end
    end
    conn:send_ucl{
      success = (#results > 0),
      results = results
    }
  else
    conn:send_error(404, 'missing value')
  end
end

local function handle_list_maps(_, conn, _)
  maybe_fill_maps_cache()
  conn:send_ucl({maps = lua_util.keys(maps_cache),
                 aliases = maps_aliases})
end

return {
  query = {
    handler = handle_query_map,
    enable = false,
  },
  list = {
    handler = handle_list_maps,
    enable = false,
  },
}