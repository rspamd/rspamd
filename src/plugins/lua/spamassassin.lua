--[[
Copyright (c) 2015, Vsevolod Stakhov <vsevolod@highsecure.ru>
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

-- This plugin is intended to read and parse spamassassin rules with regexp
-- rules. SA plugins or statistics are not supported

local rspamd_logger = require "rspamd_logger"
local rspamd_regexp = require "rspamd_regexp"
local _ = require "fun"
--local dumper = require 'pl.pretty'.dump
local rules = {}
local section = rspamd_config:get_key("spamassassin")

local function split(str)
  local result = {}

  for token in string.gmatch(str, "[^%s]+") do
    table.insert(result, token)
  end
  
  return result
end

local function process_sa_conf(f)
  local cur_rule = {}
  local valid_rule = false
  
  local function insert_cur_rule()
   -- We have previous rule valid
   rules[cur_rule['symbol']] = cur_rule
   cur_rule = {}
   valid_rule = false
  end
  
  local function words_to_re(words, start)
    return table.concat(_.totable(_.drop_n(start, words)), " ");
  end
  
  for l in f:lines() do
    (function ()
    if string.len(l) == 0 or
      _.nth(1, _.drop_while(function(c) return c == ' ' end, _.iter(l))) == '#' then
      return
    end
      
    local slash = string.find(l, '/')
    
    words = _.totable(_.filter(function(w) return w ~= "" end, _.iter(split(l))))
    if words[1] == "header" and slash then
      -- header SYMBOL Header ~= /regexp/
      if valid_rule then
        insert_cur_rule()
      end
      cur_rule['type'] = 'header'
      cur_rule['symbol'] = words[2]
      cur_rule['header'] = words[3]
      cur_rule['re_expr'] = words_to_re(words, 4)
      cur_rule['re'] = rspamd_regexp.create_cached(cur_rule['re_expr'])
      if cur_rule['re'] then valid_rule = true end
    elseif words[1] == "body" and slash then
      -- body SYMBOL /regexp/
      if valid_rule then
        insert_cur_rule()
      end
      cur_rule['type'] = 'part'
      cur_rule['symbol'] = words[2]
      cur_rule['re_expr'] = words_to_re(words, 2)
      cur_rule['re'] = rspamd_regexp.create_cached(cur_rule['re_expr'])
      if cur_rule['re'] then valid_rule = true end
    elseif words[1] == "rawbody" and slash then
      -- body SYMBOL /regexp/
      if valid_rule then
        insert_cur_rule()
      end
      cur_rule['type'] = 'message'
      cur_rule['symbol'] = words[2]
      cur_rule['re_expr'] = words_to_re(words, 2)
      cur_rule['re'] = rspamd_regexp.create_cached(cur_rule['re_expr'])
      if cur_rule['re'] then valid_rule = true end
    elseif words[1] == "meta" then
      -- meta SYMBOL expression
      if valid_rule then
        insert_cur_rule()
      end
      cur_rule['type'] = 'meta'
      cur_rule['symbol'] = words[2]
      cur_rule['meta'] = words_to_re(words, 2)
      if cur_rule['meta'] then valid_rule = true end
    elseif words[1] == "describe" and valid_rule then
      cur_rule['description'] = words_to_re(words, 1)
    end
    end)()
  end
  if valid_rule then
    insert_cur_rule()
  end
end

if type(section) == "table" then
  for _,fn in pairs(section) do
    f = io.open(fn, "r")
    if f then
      process_sa_conf(f)
    end
  end
end