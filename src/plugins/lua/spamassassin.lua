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
local rspamd_trie = require "rspamd_trie"
local util = require "rspamd_util"
local _ = require "fun"

--local dumper = require 'pl.pretty'.dump

-- Known plugins
local known_plugins = {
  'Mail::SpamAssassin::Plugin::FreeMail',
  'Mail::SpamAssassin::Plugin::HeaderEval',
  'Mail::SpamAssassin::Plugin::ReplaceTags',
  'Mail::SpamAssassin::Plugin::RelayEval',
  'Mail::SpamAssassin::Plugin::MIMEEval',
  'Mail::SpamAssassin::Plugin::BodyEval',
  'Mail::SpamAssassin::Plugin::MIMEHeader',
}

-- Internal variables
local rules = {}
local atoms = {}
local metas = {}
local scores = {}
local external_deps = {}
local freemail_domains = {}
local freemail_trie
local replace = {
  tags = {},
  pre = {},
  inter = {},
  post = {},
  rules = {},
}
local internal_regexp = {
  date_shift = rspamd_regexp.create("^\\(\\s*'((?:-?\\d+)|(?:undef))'\\s*,\\s*'((?:-?\\d+)|(?:undef))'\\s*\\)$")
}
local func_cache = {}
local section = rspamd_config:get_all_opt("spamassassin")

-- Minimum score to treat symbols as meta
local meta_score_alpha = 0.5

-- Maximum size of regexp checked
local match_limit = 0

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

local function trim(s)
  return s:match "^%s*(.-)%s*$"
end

local function handle_header_def(hline, cur_rule)
  --Now check for modifiers inside header's name
  local hdrs = split(hline, '[^|]+')
  local hdr_params = {}
  local cur_param = {}
  -- Check if an re is an ordinary re
  local ordinary = true

  for i,h in ipairs(hdrs) do
    if h == 'ALL' or h == 'ALL:raw' then
      ordinary = false
      cur_rule['type'] = 'function'
      -- Pack closure
      local re = cur_rule['re']
      local not_f = cur_rule['not']
      local sym = cur_rule['symbol']
      -- Rule to match all headers
      rspamd_config:register_regexp({
        re = re,
        type = 'allheader'
      })
      cur_rule['function'] = function(task)
        if not re then
          rspamd_logger.errx(task, 're is missing for rule %s', h)
          return 0
        end

        return task:process_regexp({
          re = re,
          type = 'allheader'
        })
      end
    else
      local args = split(h, '[^:]+')
      cur_param['strong'] = false
      cur_param['raw'] = false
      cur_param['header'] = args[1]

      if args[2] then
        -- We have some ops that are required for the header, so it's not ordinary
        ordinary = false
      end

      _.each(function(func)
          if func == 'addr' then
            cur_param['function'] = function(str)
              local addr_parsed = util.parse_addr(str)
              local ret = {}
              if addr_parsed then
                for i,elt in ipairs(addr_parsed) do
                  if elt['addr'] then
                    table.insert(ret, elt['addr'])
                  end
                end
              end

              return ret
            end
          elseif func == 'name' then
            cur_param['function'] = function(str)
              local addr_parsed = util.parse_addr(str)
              local ret = {}
              if addr_parsed then
                for i,elt in ipairs(addr_parsed) do
                  if elt['name'] then
                    table.insert(ret, elt['name'])
                  end
                end
              end

              return ret
            end
          elseif func == 'raw' then
            cur_param['raw'] = true
          elseif func == 'case' then
            cur_param['strong'] = true
          else
            rspamd_logger.warnx(rspamd_config, 'Function %1 is not supported in %2',
              func, cur_rule['symbol'])
          end
        end, _.tail(args))

        local function split_hdr_param(param, headers)
          for i,h in ipairs(headers) do
            local nparam = {}
            for k,v in pairs(param) do
              if k ~= 'header' then
                nparam[k] = v
              end
            end

            nparam['header'] = h
            table.insert(hdr_params, nparam)
          end
        end
        -- Some header rules require splitting to check of multiple headers
        if cur_param['header'] == 'MESSAGEID' then
          -- Special case for spamassassin
          ordinary = false
          split_hdr_param(cur_param, {
            'Message-ID',
            'X-Message-ID',
            'Resent-Message-ID'})
        elseif cur_param['header'] == 'ToCc' then
          ordinary = false
          split_hdr_param(cur_param, { 'To', 'Cc', 'Bcc' })
        else
          table.insert(hdr_params, cur_param)
        end
    end

    cur_rule['ordinary'] = ordinary
    cur_rule['header'] = hdr_params
  end
end


local function freemail_search(input)
  local res = 0
  local function trie_callback(number, pos)
    rspamd_logger.debugx('Matched pattern %1 at pos %2', freemail_domains[number], pos)
    res = res + 1
  end

  if input then
    freemail_trie:match(input, trie_callback, true)
  end

  return res
end

local function gen_eval_rule(arg)
  local eval_funcs = {
    {'check_freemail_from', function(task, remain)
        local from = task:get_from()
        if from then
          return freemail_search(from[1]['addr'])
        end
        return 0
      end},
    {'check_freemail_replyto',
      function(task, remain)
        return freemail_search(task:get_header('Reply-To'))
      end
    },
    {'check_freemail_header',
      function(task, remain)
        -- Remain here contains one or two args: header and regexp to match
        local arg = string.match(remain, "^%(%s*['\"]([^%s]+)['\"]%s*%)$")
        local re = nil
        if not arg then
          arg, re = string.match(remain, "^%(%s*['\"]([^%s]+)['\"]%s*,%s*['\"]([^%s]+)['\"]%s*%)$")
        end

        if arg then
          local h = task:get_header(arg)
          if h then
            local hdr_freemail = freemail_search(h)
            if hdr_freemail > 0 and re then
              r = rspamd_regexp.create_cached(re)
              if r then
                r:match(h)
              else
                rspamd_logger.infox(rspamd_config, 'cannot create regexp %1', re)
                return 0
              end
            end

            return hdr_freemail
          end
        end

        return 0
      end
    },
    {
      'check_for_missing_to_header',
      function (task, remain)
        if not task:get_from(1) then
          return 1
        end

        return 0
      end
    },
    {
      'check_relays_unparseable',
      function(task, remain)
        local rh_mime = task:get_header_full('Received')
        local rh_parsed = task:get_received_headers()

        local rh_cnt = 0
        if rh_mime then rh_cnt = #rh_mime end
        local parsed_cnt = 0
        if rh_parsed then parsed_cnt = #rh_parsed end

        return rh_cnt - parsed_cnt
      end
    },
    {
      'check_for_shifted_date',
      function (task, remain)
        -- Remain here contains two args: start and end hours shift
        local matches = internal_regexp['date_shift']:search(remain, true, true)
        if matches and matches[1] then
          local min_diff = matches[1][2]
          local max_diff = matches[1][3]

          if min_diff == 'undef' then
            min_diff = 0
          else
            min_diff = tonumber(min_diff) * 3600
          end
          if max_diff == 'undef' then
            max_diff = 0
          else
            max_diff = tonumber(max_diff) * 3600
          end

          -- Now get the difference between Date and message received date
          local dm = task:get_date { format = 'message', gmt = true}
          local dt = task:get_date { format = 'connect', gmt = true}
          local diff = dm - dt

          if (max_diff == 0 and diff >= min_diff) or
              (min_diff == 0 and diff <= max_diff) or
              (diff >= min_diff and diff <= max_diff) then
            return 1
          end
        end

        return 0
      end
    },
    {
      'check_for_mime',
      function(task, remain)
        local arg = string.match(remain, "^%(%s*['\"]([^%s]+)['\"]%s*%)$")

        if arg then
          if arg == 'mime_attachment' then
            local parts = task:get_parts()
            if parts then
              for i,p in ipairs(parts) do
                if p:get_filename() then
                  return 1
                end
              end
            end
          else
            rspamd_logger.infox(task, 'unimplemented mime check %1', arg)
          end
        end

        return 0
      end
    }
  }

  for k,f in ipairs(eval_funcs) do
    local pat = string.format('^%s', f[1])
    local first,last = string.find(arg, pat)

    if first then
      local func_arg = string.sub(arg, last + 1)
      return function(task)
        return f[2](task, func_arg)
      end
    end
  end
end

-- Returns parser function or nil
local function maybe_parse_sa_function(line)
  local arg
  local elts = split(line, '[^:]+')
  arg = elts[2]

  rspamd_logger.debugx(rspamd_config, 'trying to parse SA function %1 with args %2',
    elts[1], elts[2])
  local substitutions = {
    {'^exists:',
      function(task) -- filter
        local hdrs_check = {}
        if arg == 'MESSAGEID' then
          hdrs_check = {
            'Message-ID',
            'X-Message-ID',
            'Resent-Message-ID'
          }
        elseif arg == 'ToCc' then
          hdrs_check = { 'To', 'Cc', 'Bcc' }
        else
          hdrs_check = {arg}
        end

        for i,h in ipairs(hdrs_check) do
          if task:get_header(h) then
            return 1
          end
        end
        return 0
      end,
    },
    {'^eval:',
      function(task)
        local func = func_cache[arg]
        if not func then
          func = gen_eval_rule(arg)
          func_cache[arg] = func
        end

        if not func then
          rspamd_logger.errx(rspamd_config, 'cannot find appropriate eval rule for function %1',
            arg)
        else
          return func(task)
        end

        return 0
      end
    },
  }

  for k,s in ipairs(substitutions) do
    if string.find(line, s[1]) then
      return s[2]
    end
  end

  return nil
end

local function words_to_re(words, start)
  return table.concat(_.totable(_.drop_n(start, words)), " ");
end

local function process_tflags(rule, flags)
  _.each(function(flag)
    if flag == 'publish' then
      rule['publish'] = true
    elseif flag == 'multiple' then
      rule['multiple'] = true
    elseif string.match(flag, '^maxhits=(%d+)$') then
      rule['maxhits'] = tonumber(string.match(flag, '^maxhits=(%d+)$'))
    elseif flag == 'nice' then
      rule['nice'] = true
    end
  end, _.drop_n(1, flags))

  if rule['re'] then
    if rule['maxhits'] then
      rule['re']:set_max_hits(rule['maxhits'])
    elseif rule['multiple'] then
      rule['re']:set_max_hits(0)
    else
      rule['re']:set_max_hits(1)
    end
  end
end

local function process_replace(words, tbl)
  local re = words_to_re(words, 2)
  tbl[words[2]] = re
end

local function process_sa_conf(f)
  local cur_rule = {}
  local valid_rule = false

  local function insert_cur_rule()
   if cur_rule['type'] ~= 'meta' and cur_rule['publish'] then
     -- Create meta rule from this rule
     local nsym = '__fake' .. cur_rule['symbol']
     local nrule = {
       type = 'meta',
       symbol = cur_rule['symbol'],
       score = cur_rule['score'],
       meta = nsym,
       description = cur_rule['description'],
     }
     rules[nrule['symbol']] = nrule
     cur_rule['symbol'] = nsym
   end
   -- We have previous rule valid
   if not cur_rule['symbol'] then
     rspamd_logger.errx(rspamd_config, 'bad rule definition: %1', cur_rule)
   end
   rules[cur_rule['symbol']] = cur_rule
   cur_rule = {}
   valid_rule = false
  end

  local function parse_score(words)
    if #words == 3 then
      -- score rule <x>
      rspamd_logger.debugx(rspamd_config, 'found score for %s: %s', words[2], words[3])
      return tonumber(words[3])
    elseif #words == 6 then
      -- score rule <x1> <x2> <x3> <x4>
      -- we assume here that bayes and network are enabled and select <x4>
      rspamd_logger.debugx(rspamd_config, 'found score for %s: %s', words[2], words[6])
      return tonumber(words[6])
    else
      rspamd_logger.errx(rspamd_config, 'invalid score for %s', words[2])
    end

    return 0
  end

  local skip_to_endif = false
  local if_nested = 0
  for l in f:lines() do
    (function ()
    l = trim(l)

    if string.len(l) == 0 or string.sub(l, 1, 1) == '#' then
      return
    end

    if skip_to_endif then
      if string.match(l, '^endif') then
        if_nested = if_nested - 1

        if if_nested == 0 then
          skip_to_endif = false
        end
      elseif string.match(l, '^if') then
        if_nested = if_nested + 1
      end
      return
    else
      if string.match(l, '^ifplugin') then
        local ls = split(l)

        if not _.any(function(pl)
            if pl == ls[2] then return true end
            return false
            end, known_plugins) then
          skip_to_endif = true
          if_nested = 1
        end
      elseif string.match(l, '^if !plugin%(') then
         local pname = string.match(l, '^if !plugin%(([A-Za-z:]+)%)')
         if _.any(function(pl)
           if pl == pname then return true end
           return false
         end, known_plugins) then
           skip_to_endif = true
           if_nested = 1
         end
      elseif string.match(l, '^if') then
        -- Unknown if
        skip_to_endif = true
        if_nested = 1
      end
    end

    local slash = string.find(l, '/')

    -- Skip comments
    words = _.totable(_.take_while(
      function(w) return string.sub(w, 1, 1) ~= '#' end,
      _.filter(function(w)
          return w ~= "" end,
      _.iter(split(l)))))

    if words[1] == "header" or words[1] == 'mimeheader' then
      -- header SYMBOL Header ~= /regexp/
      if valid_rule then
        insert_cur_rule()
      end
      if words[4] and (words[4] == '=~' or words[4] == '!~') then
        cur_rule['type'] = 'header'
        cur_rule['symbol'] = words[2]

        if words[4] == '!~' then
          cur_rule['not'] = true
        end

        cur_rule['re_expr'] = words_to_re(words, 4)
        local unset_comp = string.find(cur_rule['re_expr'], '%s+%[if%-unset:')
        if unset_comp then
          -- We have optional part that needs to be processed
          unset = string.match(string.sub(cur_rule['re_expr'], unset_comp),
            '%[if%-unset:%s*([^%]%s]+)]')
          cur_rule['unset'] = unset
          -- Cut it down
           cur_rule['re_expr'] = string.sub(cur_rule['re_expr'], 1, unset_comp - 1)
        end

        cur_rule['re'] = rspamd_regexp.create(cur_rule['re_expr'])

        if not cur_rule['re'] then
          rspamd_logger.warnx(rspamd_config, "Cannot parse regexp '%1' for %2",
            cur_rule['re_expr'], cur_rule['symbol'])
        else
          cur_rule['re']:set_max_hits(1)
          handle_header_def(words[3], cur_rule)
        end

        if words[1] == 'mimeheader' then
          cur_rule['ordinary'] = false
          cur_rule['mime'] = true
        end

        if cur_rule['re'] and cur_rule['symbol'] and
          (cur_rule['header'] or cur_rule['function']) then
          valid_rule = true
          cur_rule['re']:set_max_hits(1)
          if cur_rule['header'] and cur_rule['ordinary'] then
            for i,h in ipairs(cur_rule['header']) do
              if type(h) == 'string' then
                rspamd_config:register_regexp({
                  re = cur_rule['re'],
                  type = 'header',
                  header = h})
              else
                if h['raw'] then
                  rspamd_config:register_regexp({
                    re = cur_rule['re'],
                    type = 'rawheader',
                    header = h['header']
                  })
                else
                  rspamd_config:register_regexp({
                    re = cur_rule['re'],
                    type = 'header',
                    header = h['header']
                  })
                end
              end
            end
            cur_rule['re']:set_limit(match_limit)
            cur_rule['re']:set_max_hits(1)
          end
        end
      else
        -- Maybe we know the function and can convert it
        local args =  words_to_re(words, 2)
        local func = maybe_parse_sa_function(args)

        if func then
          cur_rule['type'] = 'function'
          cur_rule['symbol'] = words[2]
          cur_rule['function'] = func
          valid_rule = true
        else
          rspamd_logger.infox(rspamd_config, 'unknown function %1', args)
        end
      end
    elseif words[1] == "body" then
      -- body SYMBOL /regexp/
      if valid_rule then
        insert_cur_rule()
      end

      cur_rule['symbol'] = words[2]

      if words[3] and (string.sub(words[3], 1, 1) == '/'
          or string.sub(words[3], 1, 1) == 'm') then
        cur_rule['type'] = 'part'
        cur_rule['re_expr'] = words_to_re(words, 2)
        cur_rule['re'] = rspamd_regexp.create_cached(cur_rule['re_expr'])
        cur_rule['raw'] = true
        if cur_rule['re'] then
          rspamd_config:register_regexp({
            re = cur_rule['re'],
            type = 'mime',
          })
          valid_rule = true
          cur_rule['re']:set_limit(match_limit)
          cur_rule['re']:set_max_hits(1)
        end
      else
        -- might be function
        local args = words_to_re(words, 2)
        local func = maybe_parse_sa_function(args)

        if func then
          cur_rule['type'] = 'function'
          cur_rule['symbol'] = words[2]
          cur_rule['function'] = func
          valid_rule = true
        else
          rspamd_logger.infox(rspamd_config, 'unknown function %1', args)
        end
      end
    elseif words[1] == "rawbody" or words[1] == "full" then
      -- body SYMBOL /regexp/
      if valid_rule then
        insert_cur_rule()
      end

      cur_rule['symbol'] = words[2]

      if words[3] and (string.sub(words[3], 1, 1) == '/'
          or string.sub(words[3], 1, 1) == 'm') then
        cur_rule['type'] = 'message'
        cur_rule['re_expr'] = words_to_re(words, 2)
        cur_rule['re'] = rspamd_regexp.create_cached(cur_rule['re_expr'])
        cur_rule['raw'] = true
        if cur_rule['re'] then
          valid_rule = true
          rspamd_config:register_regexp({
            re = cur_rule['re'],
            type = 'body',
          })
          cur_rule['re']:set_limit(match_limit)
          cur_rule['re']:set_max_hits(1)
        end
      else
        -- might be function
        local args = words_to_re(words, 2)
        local func = maybe_parse_sa_function(args)

        if func then
          cur_rule['type'] = 'function'
          cur_rule['symbol'] = words[2]
          cur_rule['function'] = func
          valid_rule = true
        else
          rspamd_logger.infox(rspamd_config, 'unknown function %1', args)
        end
      end
    elseif words[1] == "uri" then
      -- uri SYMBOL /regexp/
      if valid_rule then
        insert_cur_rule()
      end
      cur_rule['type'] = 'uri'
      cur_rule['symbol'] = words[2]
      cur_rule['re_expr'] = words_to_re(words, 2)
      cur_rule['re'] = rspamd_regexp.create_cached(cur_rule['re_expr'])
      if cur_rule['re'] and cur_rule['symbol'] then
        valid_rule = true
        rspamd_config:register_regexp({
          re = cur_rule['re'],
          type = 'url',
        })
        cur_rule['re']:set_limit(match_limit)
        cur_rule['re']:set_max_hits(1)
      end
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
      cur_rule['description'] = words_to_re(words, 2)
    elseif words[1] == "score" and valid_rule then
      scores[words[2]] = parse_score(words)
    elseif words[1] == 'freemail_domains' then
      _.each(function(dom)
        table.insert(freemail_domains, '@' .. dom)
        end, _.drop_n(1, words))
    elseif words[1] == 'tflags' then
      process_tflags(cur_rule, words)
    elseif words[1] == 'replace_tag' then
      process_replace(words, replace['tags'])
    elseif words[1] == 'replace_pre' then
      process_replace(words, replace['pre'])
    elseif words[1] == 'replace_inter' then
      process_replace(words, replace['inter'])
    elseif words[1] == 'replace_post' then
      process_replace(words, replace['post'])
    elseif words[1] == 'replace_rules' then
      _.each(function(r) table.insert(replace['rules'], r) end,
        _.drop_n(1, words))
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
    elseif k == 'match_limit' and type(fn) == 'number' then
      match_limit = fn
    else
      if type(fn) == 'table' then
        for k,elt in ipairs(fn) do
          f = io.open(elt, "r")
          if f then
            process_sa_conf(f)
          end
        end
      else
        -- assume string
        f = io.open(fn, "r")
        if f then
          process_sa_conf(f)
        end
      end
    end
  end
end

-- Now check all valid rules and add the according rspamd rules

local function calculate_score(sym, rule)
  if _.all(function(c) return c == '_' end, _.take_n(2, _.iter(sym))) then
    return 0.0
  end

  if rule['nice'] or (rule['score'] and rule['score'] < 0.0) then
    return -1.0
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

if freemail_domains then
  freemail_trie = rspamd_trie.create(freemail_domains)
  rspamd_logger.infox(rspamd_config, 'loaded %1 freemail domains definitions',
    #freemail_domains)
end

local function sa_regexp_match(data, re, raw, rule)
  local res = 0
  if not re then
    return 0
  end
  if rule['multiple'] then
    local lim = -1
    if rule['maxhits'] then
      lim = rule['maxhits']
    end
    res = res + re:matchn(data, lim, raw)
  else
    if re:match(data, raw) then res = 1 end
  end

  return res
end

local function apply_replacements(str)
  local pre = ""
  local post = ""
  local inter = ""

  local function check_specific_tag(prefix, s, tbl)
    local replacement = nil
    local ret = s
    _.each(function(n, t)
      local ns,matches = string.gsub(s, string.format("<%s%s>", prefix, n), "")
      if matches > 0 then
        replacement = t
        ret = ns
      end
    end, tbl)

    return ret,replacement
  end

  local repl
  str,repl = check_specific_tag("pre ", str, replace['pre'])
  if repl then
    pre = repl
  end
  str,repl = check_specific_tag("inter ", str, replace['inter'])
  if repl then
    inter = repl
  end
  str,repl = check_specific_tag("post ", str, replace['post'])
  if repl then
    post = repl
  end

  -- XXX: ugly hack
  if inter then
    str = string.gsub(str, "><", string.format(">%s<", inter))
  end

  local function replace_all_tags(s)
    local str, matches
    str = s
    _.each(function(n, t)
        str,matches = string.gsub(str, string.format("<%s>", n),
          string.format("%s%s%s", pre, t, post))
    end, replace['tags'])

    return str
  end

  local s = replace_all_tags(str)


  if str ~= s then
    return true,s
  end

  return false,str
end

-- Replace rule tags
local ntags = {}
local function rec_replace_tags(tag, tagv)
  if ntags[tag] then return ntags[tag] end
  _.each(function(n, t)
    if n ~= tag then
      local s,matches = string.gsub(tagv, string.format("<%s>", n), t)
      if matches > 0 then
        ntags[tag] = rec_replace_tags(tag, s)
      end
    end
  end, replace['tags'])

  if not ntags[tag] then ntags[tag] = tagv end
  return ntags[tag]
end
_.each(function(n, t)
  rec_replace_tags(n, t)
end, replace['tags'])
_.each(function(n, t)
  replace['tags'][n] = t
end, ntags)

_.each(function(r)
  local rule = rules[r]

  if rule['re_expr'] and rule['re'] then
    local res,nexpr = apply_replacements(rule['re_expr'])
    if res then
      local nre = rspamd_regexp.create(nexpr)
      if not nre then
        rspamd_logger.errx(rspamd_config, 'cannot apply replacement for rule %1', r)
        rule['re'] = nil
      else
        local old_max_hits = rule['re']:get_max_hits()
        rspamd_logger.debugx(rspamd_config, 'replace %1 -> %2', r, nexpr)
        rspamd_config:replace_regexp({
          old_re = rule['re'],
          new_re = nre
        })
        rule['re'] = nre
        rule['re_expr'] = nexpr
        nre:set_limit(match_limit)
        nre:set_max_hits(old_max_hits)
      end
    end
  end
end, replace['rules'])

_.each(function(key, score)
  if rules[key] then
    rules[key]['score'] = score
  end
end, scores)

-- Header rules
_.each(function(k, r)
    local f = function(task)
      local raw = false
      local check = {}
      -- Cached path for ordinary expressions
      if r['ordinary'] then
        local h = r['header'][1]
        local t = 'header'

        if h['raw'] then
          t = 'rawheader'
        end

        if not r['re'] then
          rspamd_logger.errx(task, 're is missing for rule %s (%s header)', k,
              h['header'])
          return 0
        end

        local ret = task:process_regexp({
          re = r['re'],
          type = t,
          strong = h['strong'],
          header = h['header'],
          raw = h['raw'],
        })

        if h['not'] then
          return not ret
        end
        return ret
      end

      -- Slow path
      _.each(function(h)
        local headers = {}
        local hname = h['header']

          local hdr
          if h['mime'] then
            local parts = task:get_parts()
            for i,p in ipairs(parts) do
              local m_hdr = p:get_header_full(hname, h['strong'])

              if m_hdr then
                if not hdr then
                  hdr = {}
                end
                for k,mh in ipairs(m_hdr) do
                  table.insert(hdr, mh)
                end
              end
            end
          else
            hdr = task:get_header_full(hname, h['strong'])
          end

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

              if type(str) == 'string' then
                table.insert(check, str)
              else
                for ii,c in ipairs(str) do
                  table.insert(check, c)
                end
              end
            end
          elseif r['unset'] then
            table.insert(check, r['unset'])
          end
      end, r['header'])

      if #check == 0 then
        if r['not'] then return 1 end
        return 0
      end

      for i,c in ipairs(check) do
        local match = sa_regexp_match(c, r['re'], raw, r)
        if (match and not r['not']) or (not match and r['not']) then
          return match
        end
      end

      return 0
    end
    if r['score'] then
      local real_score = r['score'] * calculate_score(k, r)
      if math.abs(real_score) > meta_score_alpha then
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
      local res = r['function'](task)
      if res and res > 0 then
        return res
      end
      return 0
    end
    if r['score'] then
      local real_score = r['score'] * calculate_score(k, r)
      if math.abs(real_score) > meta_score_alpha then
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
      if not r['re'] then
        rspamd_logger.errx(task, 're is missing for rule %s', k)
        return 0
      end

      return task:process_regexp({
        re = r['re'],
        type = 'mime',
      })
    end
    if r['score'] then
      local real_score = r['score'] * calculate_score(k, r)
      if math.abs(real_score) > meta_score_alpha then
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
      if not r['re'] then
        rspamd_logger.errx(task, 're is missing for rule %s', k)
        return 0
      end

      return task:process_regexp({
        re = r['re'],
        type = 'body',
      })
    end
    if r['score'] then
      local real_score = r['score'] * calculate_score(k, r)
      if math.abs(real_score) > meta_score_alpha then
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
      if not r['re'] then
        rspamd_logger.errx(task, 're is missing for rule %s', k)
        return 0
      end

      return task:process_regexp({
        re = r['re'],
        type = 'url',
      })
    end
    if r['score'] then
      local real_score = r['score'] * calculate_score(k, r)
      if math.abs(real_score) > meta_score_alpha then
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
    local res = atom_cb(task)

    if not res then
      rspamd_logger.debugx(task, 'atom: %1, NULL result', atom)
    elseif res > 0 then
      rspamd_logger.debugx(task, 'atom: %1, result: %2', atom, res)
    end
    return res
  elseif external_deps[atom] then
    local res = 0
    if task:get_symbol(atom) then
      res = 1
    end
    rspamd_logger.debugx(task, 'external atom: %1, result: %2', atom, res)

    return res
  else
    rspamd_logger.debugx(task, 'Cannot find atom ' .. atom)
  end
  return 0
end

-- Meta rules
_.each(function(k, r)
    local expression = nil
    -- Meta function callback
    local meta_cb = function(task)
      local res = 0
      if expression then
        res = expression:process(task)
      end
      if res > 0 then
        task:insert_result(k, res)
      end

      return res
    end
    expression = rspamd_expression.create(r['meta'],
      {parse_atom, process_atom}, sa_mempool)
    if not expression then
      rspamd_logger.errx(rspamd_config, 'Cannot parse expression ' .. r['meta'])
    else
      if r['score'] then
        rspamd_config:set_metric_symbol(k, r['score'], r['description'])
      end
      rspamd_config:register_symbol(k, calculate_score(k, r), meta_cb)
      r['expression'] = expression
      if not atoms[k] then
        atoms[k] = meta_cb
      end
    end
  end,
  _.filter(function(k, r)
      return r['type'] == 'meta'
    end,
    rules))

-- Check meta rules for foreign symbols and register dependencies
_.each(function(k, r)
    if r['expression'] then
      local expr_atoms = r['expression']:atoms()

      for i,a in ipairs(expr_atoms) do
        if not atoms[a] then
          rspamd_logger.debugx('atom %1 is foreign for SA plugin, register dependency for %2 on %3',
              a, k, a);
          rspamd_config:register_dependency(k, a)

          if not external_deps[a] then
            external_deps[a] = 1
          end
        end
      end
    end
  end,
  _.filter(function(k, r)
    return r['type'] == 'meta'
  end,
    rules))
