--[[
Copyright (c) 2015, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

-- This plugin is intended to read and parse spamassassin rules with regexp
-- rules. SA plugins or statistics are not supported

local E = {}
local N = 'spamassassin'

local rspamd_logger = require "rspamd_logger"
local rspamd_regexp = require "rspamd_regexp"
local rspamd_expression = require "rspamd_expression"
local rspamd_trie = require "rspamd_trie"
local util = require "rspamd_util"
local lua_util = require "lua_util"
local fun = require "fun"

-- Known plugins
local known_plugins = {
  'Mail::SpamAssassin::Plugin::FreeMail',
  'Mail::SpamAssassin::Plugin::HeaderEval',
  'Mail::SpamAssassin::Plugin::ReplaceTags',
  'Mail::SpamAssassin::Plugin::RelayEval',
  'Mail::SpamAssassin::Plugin::MIMEEval',
  'Mail::SpamAssassin::Plugin::BodyEval',
  'Mail::SpamAssassin::Plugin::MIMEHeader',
  'Mail::SpamAssassin::Plugin::WLBLEval',
  'Mail::SpamAssassin::Plugin::HTMLEval',
}

-- Table that replaces SA symbol with rspamd equivalent
-- Used for dependency resolution
local symbols_replacements = {
  -- SPF replacements
  USER_IN_SPF_WHITELIST = 'WHITELIST_SPF',
  USER_IN_DEF_SPF_WL = 'WHITELIST_SPF',
  SPF_PASS = 'R_SPF_ALLOW',
  SPF_FAIL = 'R_SPF_FAIL',
  SPF_SOFTFAIL = 'R_SPF_SOFTFAIL',
  SPF_HELO_PASS = 'R_SPF_ALLOW',
  SPF_HELLO_FAIL = 'R_SPF_FAIL',
  SPF_HELLO_SOFTFAIL = 'R_SPF_SOFTFAIL',
  -- DKIM replacements
  USER_IN_DKIM_WHITELIST = 'WHITELIST_DKIM',
  USER_IN_DEF_DKIM_WL = 'WHITELIST_DKIM',
  DKIM_VALID = 'R_DKIM_ALLOW',
  -- SURBL replacements
  URIBL_SBL_A = 'URIBL_SBL',
  URIBL_DBL_SPAM = 'DBL_SPAM',
  URIBL_DBL_PHISH = 'DBL_PHISH',
  URIBL_DBL_MALWARE = 'DBL_MALWARE',
  URIBL_DBL_BOTNETCC = 'DBL_BOTNET',
  URIBL_DBL_ABUSE_SPAM = 'DBL_ABUSE',
  URIBL_DBL_ABUSE_REDIR = 'DBL_ABUSE_REDIR',
  URIBL_DBL_ABUSE_MALW = 'DBL_ABUSE_MALWARE',
  URIBL_DBL_ABUSE_BOTCC = 'DBL_ABUSE_BOTNET',
  URIBL_WS_SURBL = 'WS_SURBL_MULTI',
  URIBL_PH_SURBL = 'PH_SURBL_MULTI',
  URIBL_MW_SURBL = 'MW_SURBL_MULTI',
  URIBL_CR_SURBL = 'CRACKED_SURBL',
  URIBL_ABUSE_SURBL = 'ABUSE_SURBL',
  -- Misc rules
  BODY_URI_ONLY = 'R_EMPTY_IMAGE',
  HTML_IMAGE_ONLY_04 = 'HTML_SHORT_LINK_IMG_1',
  HTML_IMAGE_ONLY_08 = 'HTML_SHORT_LINK_IMG_1',
  HTML_IMAGE_ONLY_12 = 'HTML_SHORT_LINK_IMG_1',
  HTML_IMAGE_ONLY_16 = 'HTML_SHORT_LINK_IMG_2',
  HTML_IMAGE_ONLY_20 = 'HTML_SHORT_LINK_IMG_2',
  HTML_IMAGE_ONLY_24 = 'HTML_SHORT_LINK_IMG_3',
  HTML_IMAGE_ONLY_28 = 'HTML_SHORT_LINK_IMG_3',
  HTML_IMAGE_ONLY_32 = 'HTML_SHORT_LINK_IMG_3',
}

-- Internal variables
local rules = {}
local atoms = {}
local scores = {}
local scores_added = {}
local external_deps = {}
local freemail_domains = {}
local pcre_only_regexps = {}
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

-- Mail::SpamAssassin::Plugin::WLBLEval plugin
local sa_lists = {
  from_blacklist = {},
  from_whitelist = {},
  from_def_whitelist = {},
  to_blacklist = {},
  to_whitelist = {},
  elts = 0,
}

local func_cache = {}
local section = rspamd_config:get_all_opt("spamassassin")
if not (section and type(section) == 'table') then
  rspamd_logger.infox(rspamd_config, 'Module is unconfigured')
end

-- Minimum score to treat symbols as meta
local meta_score_alpha = 0.5

-- Maximum size of regexp checked
local match_limit = 0

-- Default priority of the scores registered in the metric
-- Historically this is set to 2 allowing SA scores to override Rspamd scores
local scores_priority = 2

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

local function replace_symbol(s)
  local rspamd_symbol = symbols_replacements[s]
  if not rspamd_symbol then
    return s, false
  end
  return rspamd_symbol, true
end

local ffi
if type(jit) == 'table' then
  ffi = require("ffi")
  ffi.cdef[[
    int rspamd_re_cache_type_from_string (const char *str);
    int rspamd_re_cache_process_ffi (void *ptask,
        void *pre,
        int type,
        const char *type_data,
        int is_strong);
]]
end

local function process_regexp_opt(re, task, re_type, header, strong)
  --[[
  -- This is now broken with lua regexp conditions!
  if type(jit) == 'table' then
    -- Use ffi call
    local itype = ffi.C.rspamd_re_cache_type_from_string(re_type)

    if not strong then
      strong = 0
    else
      strong = 1
    end
    local iret = ffi.C.rspamd_re_cache_process_ffi (task, re, itype, header, strong)

    return tonumber(iret)
  else
    return task:process_regexp(re, re_type, header, strong)
  end
  --]]
  return task:process_regexp(re, re_type, header, strong)
end

local function is_pcre_only(name)
  if pcre_only_regexps[name] then
    rspamd_logger.infox(rspamd_config, 'mark re %s as PCRE only', name)
    return true
  end
  return false
end

local function handle_header_def(hline, cur_rule)
  --Now check for modifiers inside header's name
  local hdrs = split(hline, '[^|]+')
  local hdr_params = {}
  local cur_param = {}
  -- Check if an re is an ordinary re
  local ordinary = true

  for _,h in ipairs(hdrs) do
    if h == 'ALL' or h == 'ALL:raw' then
      ordinary = false
      cur_rule['type'] = 'function'
      -- Pack closure
      local re = cur_rule['re']
      -- Rule to match all headers
      rspamd_config:register_regexp({
        re = re,
        type = 'allheader',
        pcre_only = is_pcre_only(cur_rule['symbol']),
      })
      cur_rule['function'] = function(task)
        if not re then
          rspamd_logger.errx(task, 're is missing for rule %1', h)
          return 0
        end

        return process_regexp_opt(re, task, 'allheader')
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

      fun.each(function(func)
          if func == 'addr' then
            cur_param['function'] = function(str)
              local addr_parsed = util.parse_mail_address(str)
              local ret = {}
              if addr_parsed then
                for _,elt in ipairs(addr_parsed) do
                  if elt['addr'] then
                    table.insert(ret, elt['addr'])
                  end
                end
              end

              return ret
            end
          elseif func == 'name' then
            cur_param['function'] = function(str)
              local addr_parsed = util.parse_mail_address(str)
              local ret = {}
              if addr_parsed then
                for _,elt in ipairs(addr_parsed) do
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
        end, fun.tail(args))

        local function split_hdr_param(param, headers)
          for _,hh in ipairs(headers) do
            local nparam = {}
            for k,v in pairs(param) do
              if k ~= 'header' then
                nparam[k] = v
              end
            end

            nparam['header'] = hh
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
    lua_util.debugm(N, rspamd_config, 'Matched pattern %1 at pos %2', freemail_domains[number], pos)
    res = res + 1
  end

  if input then
    freemail_trie:match(input, trie_callback, true)
  end

  return res
end

local function gen_eval_rule(arg)
  local eval_funcs = {
    {'check_freemail_from', function(task)
        local from = task:get_from('mime')
        if from and from[1] then
          return freemail_search(string.lower(from[1]['addr']))
        end
        return 0
      end},
    {'check_freemail_replyto',
      function(task)
        return freemail_search(task:get_header('Reply-To'))
      end
    },
    {'check_freemail_header',
      function(task, remain)
        -- Remain here contains one or two args: header and regexp to match
        local larg = string.match(remain, "^%(%s*['\"]([^%s]+)['\"]%s*%)$")
        local re = nil
        if not larg then
          larg, re = string.match(remain, "^%(%s*['\"]([^%s]+)['\"]%s*,%s*['\"]([^%s]+)['\"]%s*%)$")
        end

        if larg then
          local h
          if larg == 'EnvelopeFrom' then
            h = task:get_from('smtp')
            if h then h = h[1]['addr'] end
          else
            h = task:get_header(larg)
          end
          if h then
            local hdr_freemail = freemail_search(string.lower(h))

            if hdr_freemail > 0 and re then
              local r = rspamd_regexp.create_cached(re)
              if r then
                if r:match(h) then
                  return 1
                end
                return 0
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
      function (task)
        local th = task:get_recipients('mime')
        if not th or #th == 0 then
          return 1
        end

        return 0
      end
    },
    {
      'check_relays_unparseable',
      function(task)
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
        local larg = string.match(remain, "^%(%s*['\"]([^%s]+)['\"]%s*%)$")

        if larg then
          if larg == 'mime_attachment' then
            local parts = task:get_parts()
            if parts then
              for _,p in ipairs(parts) do
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
    },
    {
      'check_from_in_blacklist',
      function(task)
        local from = task:get_from('mime')
        if ((from or E)[1] or E).addr then
          if sa_lists['from_blacklist'][string.lower(from[1]['addr'])] then
            return 1
          end
        end

        return 0
      end
    },
    {
      'check_from_in_whitelist',
      function(task)
        local from = task:get_from('mime')
        if ((from or E)[1] or E).addr then
          if sa_lists['from_whitelist'][string.lower(from[1]['addr'])] then
            return 1
          end
        end

        return 0
      end
    },
    {
      'check_from_in_default_whitelist',
      function(task)
        local from = task:get_from('mime')
        if ((from or E)[1] or E).addr then
          if sa_lists['from_def_whitelist'][string.lower(from[1]['addr'])] then
            return 1
          end
        end

        return 0
      end
    },
    {
      'check_to_in_blacklist',
      function(task)
        local rcpt = task:get_recipients('mime')
        if rcpt then
          for _,r in ipairs(rcpt) do
            if sa_lists['to_blacklist'][string.lower(r['addr'])] then
              return 1
            end
          end
        end

        return 0
      end
    },
    {
      'check_to_in_whitelist',
      function(task)
        local rcpt = task:get_recipients('mime')
        if rcpt then
          for _,r in ipairs(rcpt) do
            if sa_lists['to_whitelist'][string.lower(r['addr'])] then
              return 1
            end
          end
        end

        return 0
      end
    },
    {
      'html_tag_exists',
      function(task, remain)
        local tp = task:get_text_parts()

        for _,p in ipairs(tp) do
          if p:is_html() then
            local hc = p:get_html()

            if hc:has_tag(remain) then
              return 1
            end
          end
        end

        return 0
      end
    }
  }

  for _,f in ipairs(eval_funcs) do
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

  lua_util.debugm(N, rspamd_config, 'trying to parse SA function %1 with args %2',
    elts[1], elts[2])
  local substitutions = {
    {'^exists:',
      function(task) -- filter
        local hdrs_check
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

        for _,h in ipairs(hdrs_check) do
          if task:has_header(h) then
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
          rspamd_logger.errx(task, 'cannot find appropriate eval rule for function %1',
            arg)
        else
          return func(task)
        end

        return 0
      end
    },
  }

  for _,s in ipairs(substitutions) do
    if string.find(line, s[1]) then
      return s[2]
    end
  end

  return nil
end

local function words_to_re(words, start)
  return table.concat(fun.totable(fun.drop_n(start, words)), " ");
end

local function process_tflags(rule, flags)
  fun.each(function(flag)
    if flag == 'publish' then
      rule['publish'] = true
    elseif flag == 'multiple' then
      rule['multiple'] = true
    elseif string.match(flag, '^maxhits=(%d+)$') then
      rule['maxhits'] = tonumber(string.match(flag, '^maxhits=(%d+)$'))
    elseif flag == 'nice' then
      rule['nice'] = true
    end
  end, fun.drop_n(1, flags))

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
      lua_util.debugm(N, rspamd_config, 'found score for %1: %2', words[2], words[3])
      return tonumber(words[3])
    elseif #words == 6 then
      -- score rule <x1> <x2> <x3> <x4>
      -- we assume here that bayes and network are enabled and select <x4>
      lua_util.debugm(N, rspamd_config, 'found score for %1: %2', words[2], words[6])
      return tonumber(words[6])
    else
      rspamd_logger.errx(rspamd_config, 'invalid score for %1', words[2])
    end

    return 0
  end

  local skip_to_endif = false
  local if_nested = 0
  for l in f:lines() do
    (function ()
    l = lua_util.rspamd_str_trim(l)
    -- Replace bla=~/re/ with bla =~ /re/ (#2372)
    l = l:gsub('([^%s])%s*([=!]~)%s*([^%s])', '%1 %2 %3')

    if string.len(l) == 0 or string.sub(l, 1, 1) == '#' then
      return
    end

    -- Unbalanced if/endif
    if if_nested < 0 then if_nested = 0 end
    if skip_to_endif then
      if string.match(l, '^endif') then
        if_nested = if_nested - 1

        if if_nested == 0 then
          skip_to_endif = false
        end
      elseif string.match(l, '^if') then
        if_nested = if_nested + 1
      elseif string.match(l, '^else') then
        -- Else counterpart for if
        skip_to_endif = false
      end
      return
    else
      if string.match(l, '^ifplugin') then
        local ls = split(l)

        if not fun.any(function(pl)
            if pl == ls[2] then return true end
            return false
            end, known_plugins) then
          skip_to_endif = true
        end
        if_nested = if_nested + 1
      elseif string.match(l, '^if !plugin%(') then
         local pname = string.match(l, '^if !plugin%(([A-Za-z:]+)%)')
         if fun.any(function(pl)
           if pl == pname then return true end
           return false
         end, known_plugins) then
           skip_to_endif = true
         end
         if_nested = if_nested + 1
      elseif string.match(l, '^if') then
        -- Unknown if
        skip_to_endif = true
        if_nested = if_nested + 1
      elseif string.match(l, '^else') then
        -- Else counterpart for if
        skip_to_endif = true
      elseif string.match(l, '^endif') then
        if_nested = if_nested - 1
      end
    end

    -- Skip comments
    local words = fun.totable(fun.take_while(
      function(w) return string.sub(w, 1, 1) ~= '#' end,
      fun.filter(function(w)
          return w ~= "" end,
      fun.iter(split(l)))))

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
          local unset = string.match(string.sub(cur_rule['re_expr'], unset_comp),
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

        if cur_rule['unset'] then
          cur_rule['ordinary'] = false
        end

        if words[1] == 'mimeheader' then
          cur_rule['mime'] = true
        else
          cur_rule['mime'] = false
        end

        if cur_rule['re'] and cur_rule['symbol'] and
          (cur_rule['header'] or cur_rule['function']) then
          valid_rule = true
          cur_rule['re']:set_max_hits(1)
          if cur_rule['header'] and cur_rule['ordinary'] then
            for _,h in ipairs(cur_rule['header']) do
              if type(h) == 'string' then
                if cur_rule['mime'] then
                  rspamd_config:register_regexp({
                    re = cur_rule['re'],
                    type = 'mimeheader',
                    header = h,
                    pcre_only = is_pcre_only(cur_rule['symbol']),
                  })
                else
                  rspamd_config:register_regexp({
                    re = cur_rule['re'],
                    type = 'header',
                    header = h,
                    pcre_only = is_pcre_only(cur_rule['symbol']),
                  })
                end
              else
                h['mime'] = cur_rule['mime']
                if cur_rule['mime'] then
                  rspamd_config:register_regexp({
                    re = cur_rule['re'],
                    type = 'mimeheader',
                    header = h['header'],
                    pcre_only = is_pcre_only(cur_rule['symbol']),
                  })
                else
                  if h['raw'] then
                    rspamd_config:register_regexp({
                      re = cur_rule['re'],
                      type = 'rawheader',
                      header = h['header'],
                      pcre_only = is_pcre_only(cur_rule['symbol']),
                    })
                  else
                    rspamd_config:register_regexp({
                      re = cur_rule['re'],
                      type = 'header',
                      header = h['header'],
                      pcre_only = is_pcre_only(cur_rule['symbol']),
                    })
                  end
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
        cur_rule['type'] = 'sabody'
        cur_rule['re_expr'] = words_to_re(words, 2)
        cur_rule['re'] = rspamd_regexp.create(cur_rule['re_expr'])
        if cur_rule['re'] then

          rspamd_config:register_regexp({
            re = cur_rule['re'],
            type = 'sabody',
            pcre_only = is_pcre_only(cur_rule['symbol']),
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
    elseif words[1] == "rawbody" then
      -- body SYMBOL /regexp/
      if valid_rule then
        insert_cur_rule()
      end

      cur_rule['symbol'] = words[2]
      if words[3] and (string.sub(words[3], 1, 1) == '/'
          or string.sub(words[3], 1, 1) == 'm') then
        cur_rule['type'] = 'sarawbody'
        cur_rule['re_expr'] = words_to_re(words, 2)
        cur_rule['re'] = rspamd_regexp.create(cur_rule['re_expr'])
        if cur_rule['re'] then

          rspamd_config:register_regexp({
            re = cur_rule['re'],
            type = 'sarawbody',
            pcre_only = is_pcre_only(cur_rule['symbol']),
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
    elseif words[1] == "full" then
      -- body SYMBOL /regexp/
      if valid_rule then
        insert_cur_rule()
      end

      cur_rule['symbol'] = words[2]

      if words[3] and (string.sub(words[3], 1, 1) == '/'
          or string.sub(words[3], 1, 1) == 'm') then
        cur_rule['type'] = 'message'
        cur_rule['re_expr'] = words_to_re(words, 2)
        cur_rule['re'] = rspamd_regexp.create(cur_rule['re_expr'])
        cur_rule['raw'] = true
        if cur_rule['re'] then
          valid_rule = true
          rspamd_config:register_regexp({
            re = cur_rule['re'],
            type = 'body',
            pcre_only = is_pcre_only(cur_rule['symbol']),
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
      cur_rule['re'] = rspamd_regexp.create(cur_rule['re_expr'])
      if cur_rule['re'] and cur_rule['symbol'] then
        valid_rule = true
        rspamd_config:register_regexp({
          re = cur_rule['re'],
          type = 'url',
          pcre_only = is_pcre_only(cur_rule['symbol']),
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
      if cur_rule['meta'] and cur_rule['symbol']
        and cur_rule['meta'] ~= '0' then
          valid_rule = true
      end
    elseif words[1] == "describe" and valid_rule then
      cur_rule['description'] = words_to_re(words, 2)
    elseif words[1] == "score" then
      scores[words[2]] = parse_score(words)
    elseif words[1] == 'freemail_domains' then
      fun.each(function(dom)
          table.insert(freemail_domains, '@' .. dom)
        end, fun.drop_n(1, words))
    elseif words[1] == 'blacklist_from' then
      sa_lists['from_blacklist'][words[2]] = 1
      sa_lists['elts'] = sa_lists['elts'] + 1
    elseif words[1] == 'whitelist_from' then
      sa_lists['from_whitelist'][words[2]] = 1
      sa_lists['elts'] = sa_lists['elts'] + 1
    elseif words[1] == 'whitelist_to' then
      sa_lists['to_whitelist'][words[2]] = 1
      sa_lists['elts'] = sa_lists['elts'] + 1
    elseif words[1] == 'blacklist_to' then
      sa_lists['to_blacklist'][words[2]] = 1
      sa_lists['elts'] = sa_lists['elts'] + 1
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
      fun.each(function(r) table.insert(replace['rules'], r) end,
        fun.drop_n(1, words))
    end
    end)()
  end
  if valid_rule then
    insert_cur_rule()
  end
end

-- Now check all valid rules and add the according rspamd rules

local function calculate_score(sym, rule)
  if fun.all(function(c) return c == '_' end, fun.take_n(2, fun.iter(sym))) then
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
    fun.each(function(n, t)
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
    local sstr
    sstr = s
    fun.each(function(n, t)
      local rep = string.format("%s%s%s", pre, t, post)
      rep = string.gsub(rep, '%%', '%%%%')
      sstr = string.gsub(sstr, string.format("<%s>", n), rep)
    end, replace['tags'])

    return sstr
  end

  local s = replace_all_tags(str)


  if str ~= s then
    return true,s
  end

  return false,str
end

local function parse_atom(str)
  local atom = table.concat(fun.totable(fun.take_while(function(c)
    if string.find(', \t()><+!|&\n', c) then
      return false
    end
    return true
  end, fun.iter(str))), '')

  return atom
end

local function gen_process_atom_cb(result_name, task)
  return  function (atom)
    local atom_cb = atoms[atom]

    if atom_cb then
      local res = atom_cb(task, result_name)

      if not res then
        lua_util.debugm(N, task, 'metric: %s, atom: %s, NULL result', result_name, atom)
      elseif res > 0 then
        lua_util.debugm(N, task, 'metric: %s, atom: %s, result: %s', result_name, atom, res)
      end
      return res
    else
      -- This is likely external atom
      local real_sym = atom
      if symbols_replacements[atom] then
        real_sym = symbols_replacements[atom]
      end
      if task:has_symbol(real_sym, result_name) then
        lua_util.debugm(N, task, 'external atom: %s, result: 1, named_result: %s', real_sym, result_name)
        return 1
      end
      lua_util.debugm(N, task, 'external atom: %s, result: 0, , named_result: %s', real_sym, result_name)
    end
    return 0
  end
end

local function post_process()
  -- Replace rule tags
  local ntags = {}
  local function rec_replace_tags(tag, tagv)
    if ntags[tag] then return ntags[tag] end
    fun.each(function(n, t)
      if n ~= tag then
        local s, matches = string.gsub(tagv, string.format("<%s>", n), t)
        if matches > 0 then
          ntags[tag] = rec_replace_tags(tag, s)
        end
      end
    end, replace['tags'])

    if not ntags[tag] then ntags[tag] = tagv end
    return ntags[tag]
  end

  fun.each(function(n, t)
    rec_replace_tags(n, t)
  end, replace['tags'])
  fun.each(function(n, t)
    replace['tags'][n] = t
  end, ntags)

  fun.each(function(r)
    local rule = rules[r]

    if rule['re_expr'] and rule['re'] then
      local res, nexpr = apply_replacements(rule['re_expr'])
      if res then
        local nre = rspamd_regexp.create(nexpr)
        if not nre then
          rspamd_logger.errx(rspamd_config, 'cannot apply replacement for rule %1', r)
          --rule['re'] = nil
        else
          local old_max_hits = rule['re']:get_max_hits()
          lua_util.debugm(N, rspamd_config, 'replace %1 -> %2', r, nexpr)
          rspamd_config:replace_regexp({
            old_re = rule['re'],
            new_re = nre,
            pcre_only = is_pcre_only(rule['symbol']),
          })
          rule['re'] = nre
          rule['re_expr'] = nexpr
          nre:set_limit(match_limit)
          nre:set_max_hits(old_max_hits)
        end
      end
    end
  end, replace['rules'])

  fun.each(function(key, score)
    if rules[key] then
      rules[key]['score'] = score
    end
  end, scores)

  -- Header rules
  fun.each(function(k, r)
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
          rspamd_logger.errx(task, 're is missing for rule %1 (%2 header)', k,
            h['header'])
          return 0
        end

        local ret = process_regexp_opt(r.re, task, t, h.header, h.strong)

        if r['not'] then
          if ret ~= 0 then
            ret = 0
          else
            ret = 1
          end
        end

        return ret
      end

      -- Slow path
      fun.each(function(h)
        local hname = h['header']

        local hdr
        if h['mime'] then
          local parts = task:get_parts()
          for _, p in ipairs(parts) do
            local m_hdr = p:get_header_full(hname, h['strong'])

            if m_hdr then
              if not hdr then
                hdr = {}
              end
              for _, mh in ipairs(m_hdr) do
                table.insert(hdr, mh)
              end
            end
          end
        else
          hdr = task:get_header_full(hname, h['strong'])
        end

        if hdr then
          for _, rh in ipairs(hdr) do
            -- Subject for optimization
            local str
            if h['raw'] then
              str = rh['value']
              raw = true
            else
              str = rh['decoded']
            end
            if not str then return 0 end

            if h['function'] then
              str = h['function'](str)
            end

            if type(str) == 'string' then
              table.insert(check, str)
            else
              for _, c in ipairs(str) do
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

      local ret = 0
      for _, c in ipairs(check) do
        local match = sa_regexp_match(c, r['re'], raw, r)
        if (match > 0 and not r['not']) or (match == 0 and r['not']) then
          ret = 1
        end
      end

      return ret
    end
    if r['score'] then
      local real_score = r['score'] * calculate_score(k, r)
      if math.abs(real_score) > meta_score_alpha then
        add_sole_meta(k, r)
      end
    end
    atoms[k] = f
  end,
  fun.filter(function(_, r)
      return r['type'] == 'header' and r['header']
  end,
  rules))

  -- Custom function rules
  fun.each(function(k, r)
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
    atoms[k] = f
  end,
    fun.filter(function(_, r)
      return r['type'] == 'function' and r['function']
    end,
      rules))

  -- Parts rules
  fun.each(function(k, r)
    local f = function(task)
      if not r['re'] then
        rspamd_logger.errx(task, 're is missing for rule %1', k)
        return 0
      end

      local t = 'mime'
      if r['raw'] then t = 'rawmime' end

      return process_regexp_opt(r.re, task, t)
    end
    if r['score'] then
      local real_score = r['score'] * calculate_score(k, r)
      if math.abs(real_score) > meta_score_alpha then
        add_sole_meta(k, r)
      end
    end
    atoms[k] = f
  end,
  fun.filter(function(_, r)
      return r['type'] == 'part'
  end, rules))

  -- SA body rules
  fun.each(function(k, r)
    local f = function(task)
      if not r['re'] then
        rspamd_logger.errx(task, 're is missing for rule %1', k)
        return 0
      end

      local t = r['type']

      local ret = process_regexp_opt(r.re, task, t)
      return ret
    end
    if r['score'] then
      local real_score = r['score'] * calculate_score(k, r)
      if math.abs(real_score) > meta_score_alpha then
        add_sole_meta(k, r)
      end
    end
    atoms[k] = f
  end,
  fun.filter(function(_, r)
      return r['type'] == 'sabody' or r['type'] == 'message' or r['type'] == 'sarawbody'
  end, rules))

  -- URL rules
  fun.each(function(k, r)
    local f = function(task)
      if not r['re'] then
        rspamd_logger.errx(task, 're is missing for rule %1', k)
        return 0
      end

      return process_regexp_opt(r.re, task, 'url')
    end
    if r['score'] then
      local real_score = r['score'] * calculate_score(k, r)
      if math.abs(real_score) > meta_score_alpha then
        add_sole_meta(k, r)
      end
    end
    atoms[k] = f
  end,
    fun.filter(function(_, r)
      return r['type'] == 'uri'
    end,
      rules))
  -- Meta rules
  fun.each(function(k, r)
      local expression = nil
      -- Meta function callback
      -- Here are dragons!
      -- This function can be called from 2 DIFFERENT type of invocations:
      -- 1) Invocation from Rspamd itself where `res_name` will be nil
      -- 2) Invocation from other meta during expression:process_traced call
      -- So we need to distinguish that and return different stuff to be able to deal with atoms
      local meta_cb = function(task, res_name)
        lua_util.debugm(N, task, 'meta callback for %s; result name: %s', k, res_name)
        local cached = task:cache_get('sa_metas_processed')

        -- We avoid many task methods invocations here (likely)
        if not cached then
          cached = {}
          task:cache_set('sa_metas_processed', cached)
        end

        local already_processed = cached[k]

        -- Exclude elements that are named in the same way as the symbol itself
        local function exclude_sym_filter(sopt)
          return sopt ~= k
        end

        if not (already_processed and already_processed[res_name or 'default']) then
          -- Execute symbol
          local function exec_symbol(cur_res)
            local res,trace = expression:process_traced(gen_process_atom_cb(cur_res, task))
            lua_util.debugm(N, task, 'meta result for %s: %s; result name: %s', k, res, cur_res)
            if res > 0 then
              -- Symbol should be one shot to make it working properly
              task:insert_result_named(cur_res, k, res, fun.totable(fun.filter(exclude_sym_filter, trace)))
            end

            if not cached[k] then
              cached[k] = {}
            end

            cached[k][cur_res] = res
          end

          if not res_name then
            -- Invoke for all named results
            local named_results = task:get_all_named_results()
            for _,cur_res in ipairs(named_results) do
              exec_symbol(cur_res)
            end
          else
            -- Invoked from another meta
            exec_symbol(res_name)
            return cached[k][res_name] or 0
          end
        else
          -- We have cached the result
          local res = already_processed[res_name or 'default'] or 0
          lua_util.debugm(N, task, 'cached meta result for %s: %s; result name: %s',
              k, res, res_name)

          if res_name then
            return res
          end
        end

        -- No return if invoked directly from Rspamd as we use task:insert_result_named directly
      end

      expression = rspamd_expression.create(r['meta'], parse_atom, rspamd_config:get_mempool())
      if not expression then
        rspamd_logger.errx(rspamd_config, 'Cannot parse expression ' .. r['meta'])
      else

        if r['score'] then
          rspamd_config:set_metric_symbol{
            name = k, score = r['score'],
            description = r['description'],
            priority = scores_priority,
            one_shot = true
          }
          scores_added[k] = 1
          rspamd_config:register_symbol{
            name = k,
            weight = calculate_score(k, r),
            callback = meta_cb
          }
        else
          -- Add 0 score to avoid issues
          rspamd_config:register_symbol{
            name = k,
            weight = calculate_score(k, r),
            callback = meta_cb,
            score = 0,
          }
        end

        r['expression'] = expression

        if not atoms[k] then
          atoms[k] = meta_cb
        end
      end
    end,
    fun.filter(function(_, r)
        return r['type'] == 'meta'
      end,
      rules))

  -- Check meta rules for foreign symbols and register dependencies
  -- First direct dependencies:
  fun.each(function(k, r)
      if r['expression'] then
        local expr_atoms = r['expression']:atoms()

        for _,a in ipairs(expr_atoms) do
          if not atoms[a] then
            local rspamd_symbol = replace_symbol(a)
            if not external_deps[k] then
              external_deps[k] = {}
            end

            if not external_deps[k][rspamd_symbol] then
              rspamd_config:register_dependency(k, rspamd_symbol)
              external_deps[k][rspamd_symbol] = true
              lua_util.debugm(N, rspamd_config,
                'atom %1 is a direct foreign dependency, ' ..
                'register dependency for %2 on %3',
                a, k, rspamd_symbol)
            end
          end
        end
      end
    end,
    fun.filter(function(_, r)
      return r['type'] == 'meta'
    end,
    rules))

  -- ... And then indirect ones ...
  local nchanges
  repeat
  nchanges = 0
    fun.each(function(k, r)
      if r['expression'] then
        local expr_atoms = r['expression']:atoms()
        for _,a in ipairs(expr_atoms) do
          if type(external_deps[a]) == 'table' then
            for dep in pairs(external_deps[a]) do
              if not external_deps[k] then
                external_deps[k] = {}
              end
              if not external_deps[k][dep] then
                rspamd_config:register_dependency(k, dep)
                external_deps[k][dep] = true
                lua_util.debugm(N, rspamd_config,
                  'atom %1 is an indirect foreign dependency, ' ..
                  'register dependency for %2 on %3',
                  a, k, dep)
                  nchanges = nchanges + 1
              end
            end
          else
            local rspamd_symbol, replaced_symbol = replace_symbol(a)
            if replaced_symbol then
              external_deps[a] = {[rspamd_symbol] = true}
            else
              external_deps[a] = {}
            end
          end
        end
      end
    end,
    fun.filter(function(_, r)
      return r['type'] == 'meta'
    end,
    rules))
  until nchanges == 0

  -- Set missing symbols
  fun.each(function(key, score)
    if not scores_added[key] then
      rspamd_config:set_metric_symbol({
            name = key, score = score,
            priority = 2, flags = 'ignore'})
    end
  end, scores)

  -- Logging output
  if freemail_domains then
    freemail_trie = rspamd_trie.create(freemail_domains)
    rspamd_logger.infox(rspamd_config, 'loaded %1 freemail domains definitions',
      #freemail_domains)
  end
  rspamd_logger.infox(rspamd_config, 'loaded %1 blacklist/whitelist elements',
      sa_lists['elts'])
end

local has_rules = false

if type(section) == "table" then
  local keywords = {
    pcre_only = {'table', function(v) pcre_only_regexps = lua_util.list_to_hash(v) end},
    alpha = {'number', function(v) meta_score_alpha = tonumber(v) end},
    match_limit = {'number', function(v) match_limit = tonumber(v) end},
    scores_priority = {'number', function(v) scores_priority = tonumber(v) end},
  }

  for k, fn in pairs(section) do
    local kw = keywords[k]
    if kw and type(fn) == kw[1] then
      kw[2](fn)
    else
      -- SA rule file
      if type(fn) == 'table' then
        for _, elt in ipairs(fn) do
          local files = util.glob(elt)

          if not files or #files == 0 then
            rspamd_logger.errx(rspamd_config, "cannot find any files matching pattern %s", elt)
          else
            for _,matched in ipairs(files) do
              local f = io.open(matched, "r")
              if f then
                rspamd_logger.infox(rspamd_config, 'loading SA rules from %s', matched)
                process_sa_conf(f)
                has_rules = true
              else
                rspamd_logger.errx(rspamd_config, "cannot open %1", matched)
              end
            end
          end
        end
      else
        -- assume string
        local files = util.glob(fn)

        if not files or #files == 0 then
          rspamd_logger.errx(rspamd_config, "cannot find any files matching pattern %s", fn)
        else
          for _,matched in ipairs(files) do
            local f = io.open(matched, "r")
            if f then
              rspamd_logger.infox(rspamd_config, 'loading SA rules from %s', matched)
              process_sa_conf(f)
              has_rules = true
            else
              rspamd_logger.errx(rspamd_config, "cannot open %1", matched)
            end
          end
        end
      end
    end
  end
end

if has_rules then
  post_process()
else
  lua_util.disable_module(N, "config")
end
