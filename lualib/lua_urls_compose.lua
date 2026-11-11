--[[
Copyright (c) 2026, Vsevolod Stakhov <vsevolod@rspamd.com>

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
-- @module lua_urls_compose
-- This module contains functions to compose urls queries from hostname
-- to TLD part
--]]

local N = "lua_urls_compose"
local lua_util = require "lua_util"
local rspamd_tld_lookup = require "rspamd_tld_lookup"
local bit = require "bit"

local maps_cache = {}

local exports = {}

-- Composition map rules use the public suffix list syntax with slightly
-- different semantics:
--  * `foo.bar` composes to the rule plus one preceding label (like a
--    public suffix)
--  * `*.foo.bar` composes to the whole host under the rule
--  * `!baz.foo.bar` cancels composition, the default eSLD is used
local function process_url(self, log_obj, url_tld, url_host)
  if not self.suffix_set then
    -- Map is not loaded yet
    return url_tld
  end

  local domain, flags = self.suffix_set:registrable(url_host)

  if not domain then
    lua_util.debugm(N, log_obj, 'not found compose rule for %s -> %s',
        url_host, url_tld)

    return url_tld
  end

  if bit.band(flags, rspamd_tld_lookup.flags.exception) ~= 0 then
    lua_util.debugm(N, log_obj, 'found compose exclusion for %s -> %s',
        url_host, url_tld)

    return url_tld
  end

  if bit.band(flags, rspamd_tld_lookup.flags.wildcard) ~= 0 then
    -- Wildcard compose rules are greedy: keep the whole host
    lua_util.debugm(N, log_obj, 'found compose wildcard for %s -> %s',
        url_host, url_host)

    return url_host
  end

  lua_util.debugm(N, log_obj, 'found compose inclusion for %s -> %s',
      url_host, domain)

  return domain
end

local function compose_map_cb(self, map_text)
  local suffix_set = rspamd_tld_lookup.create()
  local nrules = 0

  local function process_map_line(l)
    -- Strip comments and surrounding spaces
    l = l:gsub('#.*$', '')
    l = l:match('^%s*(.-)%s*$')

    if #l == 0 then
      return
    end

    if l:sub(1, 2) == '*.' then
      -- Compose wildcards match zero or more labels, whilst suffix
      -- wildcards require exactly one, so add the bare parent as well
      suffix_set:add_rule(l)
      suffix_set:add_rule(l:sub(3))
    else
      suffix_set:add_rule(l)
    end

    nrules = nrules + 1
  end

  for line in map_text:lines(true) do
    process_map_line(line)
  end

  self.suffix_set = suffix_set
  lua_util.debugm(N, rspamd_config, 'loaded %s compose rules', nrules)
end

exports.add_composition_map = function(cfg, map_obj)
  local hash_key = map_obj
  if type(map_obj) == 'table' then
    hash_key = lua_util.unordered_table_digest(map_obj)
  end

  local map = maps_cache[hash_key]

  if not map then
    local ret = {
      process_url = process_url,
      hash = hash_key,
    }

    map = cfg:add_map {
      type = 'callback',
      description = 'URL compose map',
      url = map_obj,
      callback = function(input)
        compose_map_cb(ret, input)
      end,
      opaque_data = true,
    }

    ret.map = map
    maps_cache[hash_key] = ret
    map = ret
  end

  return map
end

exports.inject_composition_rules = function(cfg, rules)
  local hash_key = rules
  local rspamd_text = require "rspamd_text"
  if type(rules) == 'table' then
    hash_key = lua_util.unordered_table_digest(rules)
  end

  local map = maps_cache[hash_key]

  if not map then
    local ret = {
      process_url = process_url,
      hash = hash_key,
    }

    compose_map_cb(ret, rspamd_text.fromtable(rules, '\n'))
    maps_cache[hash_key] = ret
    map = ret
  end

  return map
end

return exports
