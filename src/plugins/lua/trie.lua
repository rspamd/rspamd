--[[
Copyright (c) 2011-2015, Vsevolod Stakhov <vsevolod@highsecure.ru>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
]]--

-- Trie is rspamd module designed to define and operate with suffix trie

local rspamd_logger = require "rspamd_logger"
local rspamd_trie = require "rspamd_trie"
local _ = require "fun"

local mime_trie
local raw_trie

-- here we store all patterns as text
local mime_patterns = {}
local raw_patterns = {}

-- here we store params for each pattern, so for each i = 1..n patterns[i] 
-- should have corresponding params[i]
local mime_params = {}
local raw_params = {}

local function tries_callback(task)
  
  local matched = {}

  local function gen_trie_cb(raw)
    local patterns = mime_patterns
    local params = mime_params
    if raw then
      patterns = raw_patterns
      params = raw_params
    end
    
    return function (idx, pos)
      local param = params[idx]
      local pattern = patterns[idx]
      
      rspamd_logger.debugx("<%1> matched pattern %2 at pos %3",
        task:get_message_id(), pattern, pos)
      
      if params['multi'] or not matched[pattern] then
        task:insert_result(params['symbol'], 1.0)
        if not params['multi'] then
          matched[pattern] = true
        end
      end
    end
  end
  
  if mime_trie then
    mime_trie:search_mime(task, gen_trie_cb(false))
  end
  if raw_trie then
    raw_trie:search_rawmsg(task, gen_trie_cb(true))
  end
end

local function process_single_pattern(pat, symbol, cf)
  if pat then
    if cf['raw'] then
      table.insert(raw_patterns, pat)
      table.insert(raw_params, {symbol=symbol, multi=multi})
    else
      table.insert(mime_patterns, pat)
      table.insert(mime_params, {symbol=symbol, multi=multi})
    end
  end
end

local function process_trie_file(symbol, cf)
  file = io.open(cf['file'])
  
  if not file then
    rspamd_logger.errx('Cannot open trie file %1', cf['file'])
  else
    if cf['binary'] then
      rspamd_logger.errx('binary trie patterns are not implemented yet: %1', 
        cf['file'])
    else
      local multi = false
      if cf['multi'] then multi = true end
      
      for line in file:lines() do
        local pat = string.match(line, '^([^#].*[^%s])%s*$')
        process_single_pattern(pat, symbol, cf)
      end
    end
  end
end

local function process_trie_conf(symbol, cf)
  local raw = false
  
  if type(cf) ~= 'table' then
    rspamd_logger.errx('invalid value for symbol %1: "%2", expected table', 
      symbol, cf)
    return
  end
  
  if cf['raw'] then raw = true end
  
  if cf['file'] then
    process_trie_file(symbol, cf)
  elseif cf['patterns'] then
    _.each(function(pat)
      process_single_pattern(pat, symbol, cf)
    end, cf['patterns'])
  end
  
  rspamd_config:register_virtual_symbol(symbol, 1.0)
end

local opts =  rspamd_config:get_key("trie")
if opts then
  for sym, opt in pairs(opts) do
     process_trie_conf(sym, opt)
  end
  
  if #raw_patterns > 0 then
    raw_trie = rspamd_trie.create(raw_patterns)
    rspamd_logger.infox('registered raw search trie from %1 patterns', #raw_patterns)
	end

  if #mime_patterns > 0 then
    mime_trie = rspamd_trie.create(mime_patterns)
    rspamd_logger.infox('registered mime search trie from %1 patterns', #mime_patterns)
  end

  if mime_trie or raw_trie then
    rspamd_config:register_callback_symbol('TRIE', 1.0, tries_callback)
  else
    rspamd_logger.err('no tries defined')
  end
end
