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

--[[[
-- @module lua_urls_compose
-- This module contains functions to compose urls queries from hostname
-- to TLD part
--]]

local N = "lua_urls_compose"
local lua_util = require "lua_util"
local rspamd_util = require "rspamd_util"
local bit = require "bit"
local rspamd_trie = require "rspamd_trie"
local fun = require "fun"

local maps_cache = {}

local exports = {}

local function process_url(self, log_obj, url_tld, url_host)
  local tld_elt = self.tlds[url_tld]

  if tld_elt then
    lua_util.debugm(N, log_obj, 'found compose rule for %s (%s host)',
        url_tld, url_host)

    for _,excl in ipairs(tld_elt.except_rules) do
      local matched,ret = excl[2](url_host)
      if matched then
        lua_util.debugm(N, log_obj, 'found compose exclusion for %s (%s) -> %s',
            url_host, excl[1], ret)

        return ret
      end
    end

    if tld_elt.multipattern_compose_rules then
      local matches = tld_elt.multipattern_compose_rules:match(url_host)

      if #matches == 1 then
        local lua_pat = tld_elt.compose_rules[matches[1]]

        local matched,ret = lua_pat[2](url_host)

        if not matched then
          lua_util.debugm(N, log_obj, 'NOT found compose inclusion for %s (%s) -> %s',
              url_host, lua_pat[1], url_tld)

          return url_tld
        else
          lua_util.debugm(N, log_obj, 'found compose inclusion for %s (%s) -> %s',
              url_host, lua_pat[1], ret)

          return ret
        end
      end
    else
      -- Match one by one
      for _,lua_pat in ipairs(tld_elt.compose_rules) do
        local matched,ret = lua_pat[2](url_host)
        if matched then
          lua_util.debugm(N, log_obj, 'found compose inclusion for %s (%s) -> %s',
              url_host, lua_pat[1], ret)

          return ret
        end
      end
    end

    lua_util.debugm(N, log_obj, 'not found compose inclusion for %s in %s -> %s',
        url_host, url_tld, url_tld)
  end

  return url_tld
end

local function tld_pattern_transform(tld_pat)
  -- Convert tld like pattern to a lua match pattern
  -- blah -> %.blah
  -- *.blah -> .*%.blah

  if tld_pat:sub(1, 1) == '*' then
    tld_pat = tld_pat:gsub('%*', '.*%%') .. '$'
  else
    tld_pat = string.format('([^.]*%%.%s)$', tld_pat)
  end

  return tld_pat
end

local function include_elt_gen(pat)
  pat = tld_pattern_transform(pat)
  return function(_, host)
    local match = pat:match(host)
    if match then
      return true,match
    end

    return false
  end
end

local function exclude_elt_gen(pat)
  pat = tld_pattern_transform(pat)
  return function(tld, host)
    if host:match(pat) then
      return true,tld
    end

    return false
  end
end

local function compose_map_cb(self, map_text)
  local lpeg = require "lpeg"

  local singleline_comment = lpeg.P '#' * (1 - lpeg.S '\r\n\f') ^ 0
  local comments_strip_grammar = lpeg.C((1 - lpeg.P '#') ^ 1) * lpeg.S(' \t')^0 * singleline_comment^0

  local function process_tld_rule(tld_elt, l)
    if l:sub(1, 1) == '!' then
      -- Exclusion elt
      table.insert(tld_elt.except_rules, {l, exclude_elt_gen(l:sub(2))})
    else
      table.insert(tld_elt.compose_rules, {l, include_elt_gen(l)})
    end
  end

  local function process_map_line(l)
    -- Skip empty lines and comments
    if #l == 0 then return end
    l = comments_strip_grammar(l)
    if not l or #l == 0 then return end

    -- Get TLD
    local tld = rspamd_util.get_tld(l)

    if tld then
      local tld_elt = self.tlds[tld]

      if not tld_elt then
        tld_elt = {
          compose_rules = {},
          except_rules = {},
          multipattern_compose_rules = nil
        }
        self.tlds[tld] = tld_elt
      end
      process_tld_rule(tld_elt, l)
    else
      lua_util.debugm(N, rspamd_config, 'cannot read tld from compose map line: %s', l)
    end
  end

  for _,line in map_text:lines() do
    process_map_line(line)
  end

  local multipattern_threshold = 32
  for tld,tld_elt in pairs(self.tlds) do
    if rspamd_trie.has_hyperscan() and #tld_elt.compose_rules >= multipattern_threshold then
      lua_util.debugm(N, rspamd_config, 'tld %s has %s rules, apply multipattern',
          tld, #tld_elt.compose_rules)
      local flags = bit.bor(rspamd_trie.flags.re,
          rspamd_trie.flags.dot_all,
          rspamd_trie.flags.no_start,
          rspamd_trie.flags.single_match)


      -- We now convert our internal patterns to multipattern patterns
      local mp_table = fun.totable(fun.map(function(pat_elt)
        local pat_str = pat_elt[1]
        if pat_str:sub(1, 1) == '*' then
          return '\\.?.*\\.?' .. pat_str .. '$'
        else
          return '\\.?' .. pat_str .. '$'
        end
      end))
      tld_elt.multipattern_compose_rules = rspamd_trie.create(mp_table, flags)
    end
  end
end

exports.add_composition_map = function(cfg, map_obj)
  local hash_key = map_obj
  if type(map_obj) == 'table' then
    hash_key = lua_util.table_digest(map_obj)
  end

  local map = maps_cache[hash_key]

  if not map then
    local ret = {
      process_url = process_url,
      hash = hash_key,
      tlds = {},
    }

    map = cfg:add_map{
      type = 'callback',
      description = 'URL compose map',
      url = map_obj,
      callback = function(input) compose_map_cb(ret, input) end,
      opaque_data = true,
    }

    ret.map = map
    maps_cache[hash_key] = ret
    map = ret
  end

  return map
end

return exports