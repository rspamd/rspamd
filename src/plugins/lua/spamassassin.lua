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

-- Minimum score to treat symbols as meta
local meta_score_alpha = 0.5

local function split(str, delim)
  local result = {}
  
  if not delim then
    delim = '[^%s]+'
  end

  for token in string.gmatch(str, delim) do
    table.insert(result, token)
  end
  
  return result
end

local function handle_header_def(hline, cur_rule)
  --Now check for modifiers inside header's name
  local hdrs = split(hline, '[^|]+')
  local hdr_params = {}
  local cur_param = {}
  for i,h in ipairs(hdrs) do
    if h == 'ALL' or h == 'ALL:raw' then
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
      return
    else
      local args = split(h, '[^:]+')
      cur_param['strong'] = false
      cur_param['raw'] = false
      cur_param['header'] = args[1]
      
      if cur_param['header'] == 'MESSAGEID' then
        -- Special case for spamassassin
        cur_param['header'] = 'Message-ID'
        rspamd_logger.info('MESSAGEID support is limited in ' .. cur_rule['symbol'])
      end
      
      _.each(function(func)
          if func == 'addr' then
            cur_param['function'] = function(str)
              local at = string.find(str, '@')
              if at then
                return string.sub(str, at + 1)
              end
              return str
            end
          elseif func == 'name' then
            cur_param['function'] = function(str)
              local at = string.find(str, '@')
              if at then
                return string.sub(str, 1, at - 1)
              end
              return str
            end
          elseif func == 'raw' then
            cur_param['raw'] = true
          elseif func == 'case' then
            cur_param['strong'] = true
          else
            rspamd_logger.warn(string.format('Function %s is not supported in %s',
              func, cur_rule['symbol']))
          end
        end, _.tail(args))
        table.insert(hdr_params, cur_param)
    end
    
    cur_rule['header'] = hdr_params
  end
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
  
  local skip_to_endif = false
  for l in f:lines() do
    (function ()
    if string.len(l) == 0 or
      _.nth(1, _.drop_while(function(c) return c == ' ' end, _.iter(l))) == '#' then
      return
    end
    
    if skip_to_endif then
      if string.match(l, '^endif') then
        skip_to_endif = false
      end
      return
    else
      if string.match(l, '^ifplugin') then
        skip_to_endif = true
      end
    end
    
    local slash = string.find(l, '/')
    
    -- Skip comments
    words = _.totable(_.take_while(
      function(w) return string.sub(w, 1, 1) ~= '#' end,
      _.filter(function(w) 
          return w ~= "" end, 
      _.iter(split(l)))))

    if words[1] == "header" then
      -- header SYMBOL Header ~= /regexp/
      if valid_rule then
        insert_cur_rule()
      end
      if slash then
        cur_rule['type'] = 'header'
        cur_rule['symbol'] = words[2]
        
        if words[4] == '!~' then
          cur_rule['not'] = true
        end
        
        cur_rule['re_expr'] = words_to_re(words, 4)
        cur_rule['re'] = rspamd_regexp.create_cached(cur_rule['re_expr'])
        
        if not cur_rule['re'] then
          rspamd_logger.warn(string.format("Cannot parse regexp '%s' for %s",
            cur_rule['re_expr'], cur_rule['symbol']))
        else
          handle_header_def(words[3], cur_rule)
        end
        
        if cur_rule['re'] and cur_rule['symbol'] and 
          (cur_rule['header'] or cur_rule['function']) then 
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
      if cur_rule['re'] and cur_rule['symbol'] then valid_rule = true end
    elseif words[1] == "rawbody" or words[1] == "full" and slash then
      -- body SYMBOL /regexp/
      if valid_rule then
        insert_cur_rule()
      end
      cur_rule['type'] = 'message'
      cur_rule['symbol'] = words[2]
      cur_rule['re_expr'] = words_to_re(words, 2)
      cur_rule['re'] = rspamd_regexp.create_cached(cur_rule['re_expr'])
      if cur_rule['re'] and cur_rule['symbol'] then valid_rule = true end
    elseif words[1] == "uri" then
      -- uri SYMBOL /regexp/
      if valid_rule then
        insert_cur_rule()
      end
      cur_rule['type'] = 'uri'
      cur_rule['symbol'] = words[2]
      cur_rule['re_expr'] = words_to_re(words, 2)
      cur_rule['re'] = rspamd_regexp.create_cached(cur_rule['re_expr'])
      if cur_rule['re'] and cur_rule['symbol'] then valid_rule = true end
    elseif words[1] == "meta" then
      -- meta SYMBOL expression
      if valid_rule then
        insert_cur_rule()
      end
      cur_rule['type'] = 'meta'
      cur_rule['symbol'] = words[2]
      cur_rule['meta'] = words_to_re(words, 2)
      if cur_rule['meta'] and cur_rule['symbol'] then valid_rule = true end
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
  for k,fn in pairs(section) do
    if k == 'alpha' and type(fn) == 'number' then
      meta_score_alpha = fn
    end
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

local function add_sole_meta(sym, rule)
  local r = {
    type = 'meta',
    meta = rule['symbol'],
    score = rule['score'],
    description = rule['description']
  }
  rules[sym] = r
end

-- Header rules
_.each(function(k, r)
    local f = function(task)
      local raw = false
      local str = _.foldl(function(acc, h)
        local hdr = task:get_header_full(h['header'], h['strong'])
        if hdr then
          for n, rh in ipairs(hdr) do
            -- Subject for optimization
            local str
            if h['raw'] then
              str =  rh['value']
              raw = true
            else
              str =  rh['decoded']
            end
            if not str then return 0 end
            
            if h['function'] then
              str = h['function'](str)
            end
            
            acc = acc .. str
          end
        end
        
        return acc
      end, '', r['header'])
      
      if str == '' then
        if r['not'] then return 1 end
        return 0
      end
      
      local match = r['re']:match(str, raw)
      if (match and not r['not']) or (not match and r['not']) then
        return 1
      end
      
      return 0
    end
    if r['score'] then
      local real_score = r['score'] * calculate_score(k)
      if real_score > meta_score_alpha then
        add_sole_meta(k, r)
      end
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
      local real_score = r['score'] * calculate_score(k)
      if real_score > meta_score_alpha then
        add_sole_meta(k, r)
      end
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
          if not part:is_empty() then
            local content = part:get_content()
            local raw = false
            
            if not part:is_utf() then raw = true end
            if r['re']:match(content, raw) then
              return 1
            end
          end
        end
      end
      
      return 0
    end
    if r['score'] then
      local real_score = r['score'] * calculate_score(k)
      if real_score > meta_score_alpha then
        add_sole_meta(k, r)
      end
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
      if r['re']:match(task:get_content(), true) then
        return 1
      end
      return 0
    end
    if r['score'] then
      local real_score = r['score'] * calculate_score(k)
      if real_score > meta_score_alpha then
        add_sole_meta(k, r)
      end
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
      local real_score = r['score'] * calculate_score(k)
      if real_score > meta_score_alpha then
        add_sole_meta(k, r)
      end
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
      if not atoms[k] then
        atoms[k] = meta_cb
      end
    end
  end,
  _.filter(function(k, r)
      return r['type'] == 'meta'
    end,
    rules))