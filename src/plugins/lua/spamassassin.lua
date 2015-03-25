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
local rspamd_expression = require "rspamd_expression"
local rspamd_mempool = require "rspamd_mempool"
local _ = require "fun"
--local dumper = require 'pl.pretty'.dump
local rules = {}
local atoms = {}
local metas = {}
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
    if words[1] == "header" then
      -- header SYMBOL Header ~= /regexp/
      if valid_rule then
        insert_cur_rule()
      end
      if slash then
        cur_rule['type'] = 'header'
        cur_rule['symbol'] = words[2]
        cur_rule['header'] = words[3]
        
        if words[4] == '!~' then
          cur_rule['not'] = true
        end
        
        cur_rule['re_expr'] = words_to_re(words, 4)
        cur_rule['re'] = rspamd_regexp.create_cached(cur_rule['re_expr'])
        
        if not cur_rule['re'] then
          rspamd_logger.warn(string.format("Cannot parse regexp '%s' for %s",
            cur_rule['re_expr'], cur_rule['symbol']))
        end
        
        --Now check for modifiers inside header's name
        local semicolon = string.find(cur_rule['header'], ':')
        if semicolon then
          local func = string.sub(cur_rule['header'], semicolon + 1)
          local hdr =  string.sub(cur_rule['header'], 1, semicolon - 1)
          cur_rule['header'] = hdr
          
          if hdr == 'ALL' then
            -- We can handle all only with 'raw' condition
            if func == 'raw' then
              cur_rule['type'] = 'function'
              -- Pack closure
              local re = cur_rule['re']
              local not_f = cur_rule['not']
              local sym = cur_rule['symbol']
              cur_rule['function'] = function(task)
                local hdr = task:get_raw_headers()
                if hdr then
                  local match = re:match(hdr)
                  if (match and not not_f) or 
                    (not match and not_f) then
                    task:insert_result(sym, 1.0)
                  end
                end
              end
            else
              -- Not raw
              rspamd_logger.warn('Cannot deal with not raw ALL rule for ' ..
                cur_rule['symbol'])
              return
            end
          else
            -- Just a modifier for a normal header
            if func == 'addr' then
              cur_rule['function'] = function(str)
                local at = string.find(str, '@')
                if at then
                  return string.sub(str, at + 1)
                end
                return str
              end
            elseif func == 'raw' then
              cur_rule['raw'] = true
            else
              rspamd_logger.warn(string.format('Function %s is not supported in %s',
                func, cur_rule['symbol']))
            end
          end
        end
          
        if cur_rule['header'] == 'MESSAGEID' then
          -- Special case for spamassassin
          cur_rule['header'] = 'Message-ID'
          rspamd_logger.info('MESSAGEID support is limited in ' .. cur_rule['symbol'])
        end
        
        if cur_rule['re'] and (cur_rule['header'] or cur_rule['function']) then 
          valid_rule = true 
        end
      else
        -- Maybe we know the function and can convert it
        local s,e = string.find(words[3], 'exists:')
        if e then
           local h = _.foldl(function(acc, s) return acc .. s end,
            '', _.drop_n(e, words[3]))
           cur_rule['type'] = 'function'
           cur_rule['symbol'] = words[2]
           cur_rule['header'] = h
           cur_rule['function'] = function(task)
            if task:get_header(h) then
              return true
            end
            return false
           end
           valid_rule = true
        end
      end
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
    elseif words[1] == "rawbody" or words[1] == "full" and slash then
      -- body SYMBOL /regexp/
      if valid_rule then
        insert_cur_rule()
      end
      cur_rule['type'] = 'message'
      cur_rule['symbol'] = words[2]
      cur_rule['re_expr'] = words_to_re(words, 2)
      cur_rule['re'] = rspamd_regexp.create_cached(cur_rule['re_expr'])
      if cur_rule['re'] then valid_rule = true end
    elseif words[1] == "uri" then
      -- uri SYMBOL /regexp/
      if valid_rule then
        insert_cur_rule()
      end
      cur_rule['type'] = 'uri'
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
    elseif words[1] == "score" and valid_rule then
      cur_rule['score'] = tonumber(words_to_re(words, 2))
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

-- Now check all valid rules and add the according rspamd rules

local function calculate_score(sym)
  if _.all(function(c) return c == '_' end, _.take_n(2, _.iter(sym))) then
    return 0.0
  end

  return 1.0
end

-- Header rules
_.each(function(k, r)
    local f = function(task)   
      local hdr = task:get_header_full(r['header'])
      if hdr then
        for n, rh in ipairs(hdr) do
          -- Subject for optimization
          local str
          if r['raw'] then
            str =  rh['value']
          else
            str =  rh['decoded']
          end
          if not str then return 0 end
          
          if r['function'] then
            str = r['function'](str)
          end
          local match = r['re']:match(str)
          if (match and not r['not']) or (not match and r['not']) then
            return 1
          end
        end
      elseif r['not'] then
        return 1
      end
      
      return 0
    end
    if r['score'] then
      rspamd_config:set_metric_symbol(k, r['score'], r['description'])
    end
    --rspamd_config:register_symbol(k, calculate_score(k), f)
    atoms[k] = f
  end,
  _.filter(function(k, r)
      return r['type'] == 'header' and r['header']
    end,
    rules))
    
-- Custom function rules
_.each(function(k, r)
    local f = function(task)
      if r['function'](task) then
        return 1
      end
      return 0
    end
    if r['score'] then
      rspamd_config:set_metric_symbol(k, r['score'], r['description'])
    end
    --rspamd_config:register_symbol(k, calculate_score(k), f)
    atoms[k] = f
  end,
  _.filter(function(k, r)
      return r['type'] == 'function' and r['function']
    end,
    rules))

-- Parts rules
_.each(function(k, r)
    local f = function(task)
      local parts = task:get_text_parts()
      if parts then
        for n, part in ipairs(parts) do
          -- Subject for optimization
          if (r['re']:match(part:get_content())) then
            return 1
          end
        end
      end
      return 0
    end
    if r['score'] then
      rspamd_config:set_metric_symbol(k, r['score'], r['description'])
    end
    --rspamd_config:register_symbol(k, calculate_score(k), f)
    atoms[k] = f
  end,
  _.filter(function(k, r)
      return r['type'] == 'part'
    end,
    rules))

-- Raw body rules
_.each(function(k, r)
    local f = function(task)
      if (r['re']:match(task:get_content())) then
        return 1
      end
      return 0
    end
    if r['score'] then
      rspamd_config:set_metric_symbol(k, r['score'], r['description'])
    end
    --rspamd_config:register_symbol(k, calculate_score(k), f)
     atoms[k] = f
  end,
  _.filter(function(k, r)
      return r['type'] == 'message'
    end,
    rules))
-- URL rules
_.each(function(k, r)
    local f = function(task)
      local urls = task:get_urls()
      for _,u in ipairs(urls) do
        if (r['re']:match(u:get_text())) then
          return 1
        end
      end
      return 0
    end
    if r['score'] then
      rspamd_config:set_metric_symbol(k, r['score'], r['description'])
    end
    --rspamd_config:register_symbol(k, calculate_score(k), f)
     atoms[k] = f
  end,
  _.filter(function(k, r)
      return r['type'] == 'uri'
    end,
    rules))


local sa_mempool = rspamd_mempool.create()

local function parse_atom(str)
  local atom = table.concat(_.totable(_.take_while(function(c)
    if string.find(', \t()><+!|&\n', c) then
      return false
    end
    return true
  end, _.iter(str))), '')

  return atom
end

local function process_atom(atom, task)
  local atom_cb = atoms[atom]
  if atom_cb then
    local res = task:cache_get(atom)
    if res < 0 then
      res = atom_cb(task)
      task:cache_set(atom, res)
    end
    return res
  else
    rspamd_logger.err('Cannot find atom ' .. atom)
  end
  return 0
end

-- Meta rules
_.each(function(k, r)
    local expression = nil
    -- Meta function callback
    local meta_cb = function(task)
      local res = task:cache_get(k)
      if res < 0 then
        res = 0
        if expression then
          res = expression:process(task)
        end
        task:cache_set(k, res)
      end
      if res > 0 then
        task:insert_result(k, res)
      end
    end
    expression = rspamd_expression.create(r['meta'],  
      {parse_atom, process_atom}, sa_mempool)
    if not expression then
      rspamd_logger.err('Cannot parse expression ' .. r['meta'])
    else
      if r['score'] then
        rspamd_config:set_metric_symbol(k, r['score'], r['description'])
      end
      rspamd_config:register_symbol(k, calculate_score(k), meta_cb)
      atoms[k] = meta_cb
    end
  end,
  _.filter(function(k, r)
      return r['type'] == 'meta'
    end,
    rules))