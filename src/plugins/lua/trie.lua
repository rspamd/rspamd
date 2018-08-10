--[[
Copyright (c) 2011-2015, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

if confighelp then
  return
end

-- Trie is rspamd module designed to define and operate with suffix trie

local N = 'trie'
local rspamd_logger = require "rspamd_logger"
local rspamd_trie = require "rspamd_trie"
local fun = require "fun"
local lua_util = require "lua_util"

local mime_trie
local raw_trie
local body_trie

-- here we store all patterns as text
local mime_patterns = {}
local raw_patterns = {}
local body_patterns = {}

-- here we store params for each pattern, so for each i = 1..n patterns[i]
-- should have corresponding params[i]
local mime_params = {}
local raw_params = {}
local body_params = {}

local function tries_callback(task)

  local matched = {}

  local function gen_trie_cb(type)
    local patterns = mime_patterns
    local params = mime_params
    if type == 'rawmessage' then
      patterns = raw_patterns
      params = raw_params
    elseif type == 'rawbody' then
      patterns = body_patterns
      params = body_params
    end

    return function (idx, pos)
      local param = params[idx]
      local pattern = patterns[idx]
      local pattern_idx = pattern .. tostring(idx) .. type

      if param['multi'] or not matched[pattern_idx] then
        lua_util.debugm(N, task, "<%1> matched pattern %2 at pos %3",
          task:get_message_id(), pattern, pos)
        task:insert_result(param['symbol'], 1.0, type)
        if not param['multi'] then
          matched[pattern_idx] = true
        end
      end
    end
  end

  if mime_trie then
    mime_trie:search_mime(task, gen_trie_cb('mime'))
  end
  if raw_trie then
    raw_trie:search_rawmsg(task, gen_trie_cb('rawmessage'))
  end
  if body_trie then
    body_trie:search_rawbody(task, gen_trie_cb('rawbody'))
  end
end

local function process_single_pattern(pat, symbol, cf)
  if pat then
    local multi = false
    if cf['multi'] then multi = true end

    if cf['raw'] then
      table.insert(raw_patterns, pat)
      table.insert(raw_params, {symbol=symbol, multi=multi})
    elseif cf['body'] then
      table.insert(body_patterns, pat)
      table.insert(body_params, {symbol=symbol, multi=multi})
    else
      table.insert(mime_patterns, pat)
      table.insert(mime_params, {symbol=symbol, multi=multi})
    end
  end
end

local function process_trie_file(symbol, cf)
  local file = io.open(cf['file'])

  if not file then
    rspamd_logger.errx(rspamd_config, 'Cannot open trie file %1', cf['file'])
  else
    if cf['binary'] then
      rspamd_logger.errx(rspamd_config, 'binary trie patterns are not implemented yet: %1',
        cf['file'])
    else
      for line in file:lines() do
        local pat = string.match(line, '^([^#].*[^%s])%s*$')
        process_single_pattern(pat, symbol, cf)
      end
    end
  end
end

local function process_trie_conf(symbol, cf)
  if type(cf) ~= 'table' then
    rspamd_logger.errx(rspamd_config, 'invalid value for symbol %1: "%2", expected table',
      symbol, cf)
    return
  end

  if cf['file'] then
    process_trie_file(symbol, cf)
  elseif cf['patterns'] then
    fun.each(function(pat)
      process_single_pattern(pat, symbol, cf)
    end, cf['patterns'])
  end
end

local opts =  rspamd_config:get_all_opt("trie")
if opts then
  for sym, opt in pairs(opts) do
     process_trie_conf(sym, opt)
  end

  if #raw_patterns > 0 then
    raw_trie = rspamd_trie.create(raw_patterns)
    rspamd_logger.infox(rspamd_config, 'registered raw search trie from %1 patterns', #raw_patterns)
	end

  if #mime_patterns > 0 then
    mime_trie = rspamd_trie.create(mime_patterns)
    rspamd_logger.infox(rspamd_config, 'registered mime search trie from %1 patterns', #mime_patterns)
  end

  if #body_patterns > 0 then
    body_trie = rspamd_trie.create(body_patterns)
    rspamd_logger.infox(rspamd_config, 'registered body search trie from %1 patterns', #body_patterns)
  end

  local id = -1
  if mime_trie or raw_trie or body_trie then
    id = rspamd_config:register_symbol({
      name = 'TRIE_CALLBACK',
      type = 'callback',
      callback = tries_callback
    })
  else
    rspamd_logger.infox(rspamd_config, 'no tries defined')
  end

  if id ~= -1 then
    for sym in pairs(opts) do
      rspamd_config:register_symbol({
        name = sym,
        type = 'virtual',
        parent = id
      })
    end
  end
else
  rspamd_logger.infox(rspamd_config, "Module is unconfigured")
  lua_util.disable_module(N, "config")
end
