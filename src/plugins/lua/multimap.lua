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

-- Multimap is rspamd module designed to define and operate with different maps

local rules = {}
local rspamd_logger = require "rspamd_logger"
local cdb = require "rspamd_cdb"
local util = require "rspamd_util"
local regexp = require "rspamd_regexp"
local rspamd_expression = require "rspamd_expression"
require "fun" ()

local urls = {}

local function ip_to_rbl(ip, rbl)
  return table.concat(ip:inversed_str_octets(), ".") .. '.' .. rbl
end

local function multimap_callback(task, rule)
  local pre_filter = rule['prefilter']

  -- Applies specific filter for input
  local function apply_filter(filter, input, rule)
    if filter == 'email:addr' or filter == 'email' then
      local addr = util.parse_mail_address(input)
      if addr and addr[1] then
        return addr[1]['addr']
      end
    elseif filter == 'email:user' then
      local addr = util.parse_mail_address(input)
      if addr and addr[1] then
        return addr[1]['user']
      end
    elseif filter == 'email:domain' then
      local addr = util.parse_mail_address(input)
      if addr and addr[1] then
        return addr[1]['domain']
      end
    elseif filter == 'email:name' then
      local addr = util.parse_mail_address(input)
      if addr and addr[1] then
        return addr[1]['name']
      end
    else
      -- regexp case
      if not rule['re_filter'] then
        local type,pat = string.match(filter, '(regexp:)(.+)')
        if type and pat then
          rule['re_filter'] = regexp.create(pat)
        end
      end

      if not rule['re_filter'] then
        rspamd_logger.errx(task, 'bad search filter: %s', filter)
      else
        local results = rule['re_filter']:search(input)
        if results then
          return results[1]
        end
      end
    end

    return input
  end

  local function match_element(r, value)
   if not value then
      return false
    end

    if r['cdb'] then
      local srch = value
      if r['type'] == 'ip' then
        srch = value:to_string()
      end

      ret = r['cdb']:lookup(srch)
    elseif r['radix'] then
      ret = r['radix']:get_key(value)
    elseif r['hash'] then
      ret = r['hash']:get_key(value)
    end

    return ret
  end

  -- Parse result in form: <symbol>:<score>|<symbol>|<score>
  local function parse_ret(ret)
    if ret and type(ret) == 'string' then
      local lpeg = require "lpeg"
      local number = {}

      local digit = lpeg.R("09")
      number.integer =
        (lpeg.S("+-") ^ -1) *
        (digit   ^  1)

      -- Matches: .6, .899, .9999873
      number.fractional =
        (lpeg.P(".")   ) *
        (digit ^ 1)

      -- Matches: 55.97, -90.8, .9
      number.decimal =
        (number.integer *              -- Integer
        (number.fractional ^ -1)) +    -- Fractional
        (lpeg.S("+-") * number.fractional)  -- Completely fractional number

      local sym_start = lpeg.R("az", "AZ") + lpeg.S("_")
      local sym_elt = sym_start + lpeg.R("09")
      local symbol = sym_start * sym_elt ^0
      local symbol_cap = lpeg.Cg(symbol, 'symbol')
      local score_cap = lpeg.Cg(number.decimal, 'score')
      local symscore_cap = (symbol_cap * lpeg.P(":") * score_cap)
      local grammar = symscore_cap + symbol_cap + score_cap
      local parser = lpeg.Ct(grammar)
      local tbl = parser:match(ret)

      if tbl then
        local sym = nil
        local score = 1.0

        if tbl['symbol'] then
          sym = tbl['symbol']
        end
        if tbl['score'] then
          score = tbl['score']
        end

        return true,sym,score
      else
        rspamd_logger.infox(task, 'cannot parse %s', ret)
        return true,nil,1.0
      end
    elseif type(ret) == 'boolean' then
      return ret,nil,0.0
    end

    return false,nil,0.0
  end

  -- Match a single value for against a single rule
  local function match_rule(r, value)
    local ret = false

    if r['filter'] then
      value = apply_filter(r['filter'], value, r)
    end

    ret = match_element(r, value)

    if ret then
      local res,symbol,score = parse_ret(ret)
      if symbol then
        if not r['symbols_set'][symbol] then
          rspamd_logger.infox(task, 'symbol %s is not registered for map %s, replace it with just %s',
            symbol, r['symbol'], r['symbol'])
          symbol = r['symbol']
        end
      else
        symbol = r['symbol']
      end
      task:insert_result(symbol, score)

      if pre_filter then
        task:set_pre_result(r['action'], 'Matched map: ' .. r['symbol'])
      end
    end

    return ret
  end

  -- Match list of values according to the field
  local function match_list(r, ls, fields)
    local ret = false
    if ls then
      if fields then
        each(function(e)
          local match = e[fields[1]]
          if match then
            if fields[2] then
              match = fields[2](match)
            end
            ret = match_rule(r, match)
          end
        end, ls)
      else
        each(function(e) ret = match_rule(r, e) end, ls)
      end
    end

    return ret
  end

  local function match_addr(r, addr)
    local ret = match_list(r, addr, {'addr'})

    if not ret then
      -- Try domain
      ret = match_list(r, addr, {'domain', function(d) return '@' .. d end})
    end
    if not ret then
      -- Try user
      ret =  match_list(r, addr, {'user', function(d) return d .. '@' end})
    end

    return ret
  end

  local function apply_hostname_filter(filter, hostname, r)
    if filter == 'tld' then
      local tld = util.get_tld(hostname)
      return tld
    else
      if not r['re_filter'] then
        local pat = string.match(filter, 'tld:regexp:(.+)')
        if not pat then
          rspamd_logger.errx(task, 'bad search filter: %s', filter)
          return
        end
        r['re_filter'] = regexp.create(pat)
        if not r['re_filter'] then
          rspamd_logger.errx(task, 'couldnt create regex: %s', pat)
          return
        end
      end
      local tld = util.get_tld(hostname)
      local res = r['re_filter']:search(tld)
      if res then
        return res[1]
      else
        return nil
      end
    end
  end

  local function apply_url_filter(filter, url, r)
    if filter == 'tld' then
      return url:get_tld()
    elseif filter == 'full' then
      return url:get_text()
    elseif filter == 'is_phished' then
      if url:is_phished() then
        return url:get_host()
      else
        return nil
      end
    elseif string.find(filter, 'tld:regexp:') then
      if not r['re_filter'] then
        local type,pat = string.match(filter, '(regexp:)(.+)')
        if type and pat then
          r['re_filter'] = regexp.create(pat)
        end
      end

      if not r['re_filter'] then
        rspamd_logger.errx(task, 'bad search filter: %s', filter)
      else
        local results = r['re_filter']:search(url:get_tld())
        if results then
          return results[1]
        else
          return nil
        end
      end
    elseif string.find(filter, 'full:regexp:') then
      if not r['re_filter'] then
        local type,pat = string.match(filter, '(regexp:)(.+)')
        if type and pat then
          r['re_filter'] = regexp.create(pat)
        end
      end

      if not r['re_filter'] then
        rspamd_logger.errx(task, 'bad search filter: %s', filter)
      else
        local results = r['re_filter']:search(url:get_text())
        if results then
          return results[1]
        else
          return nil
        end
      end
    elseif string.find(filter, 'regexp:') then
      if not r['re_filter'] then
        local type,pat = string.match(filter, '(regexp:)(.+)')
        if type and pat then
          r['re_filter'] = regexp.create(pat)
        end
      end

      if not r['re_filter'] then
        rspamd_logger.errx(task, 'bad search filter: %s', filter)
      else
        local results = r['re_filter']:search(url:get_host())
        if results then
          return results[1]
        else
          return nil
        end
      end
    end

    return url:get_host()
  end

  local function match_url(r, url)
    local value
    local ret = false

    if r['filter'] then
      value = apply_url_filter(r['filter'], url, r)
    else
      value = url:get_host()
    end

    ret = match_element(r, value)

    if ret then
      task:insert_result(r['symbol'], 1)

      if pre_filter then
        task:set_pre_result(r['action'], 'Matched map: ' .. r['symbol'])
      end
    end
  end

  local function match_hostname(r, hostname)
    local value
    local ret = false

    if r['filter'] then
      value = apply_hostname_filter(r['filter'], hostname, r)
    else
      value = hostname
    end

    ret = match_element(r, value)

    if ret then
      task:insert_result(r['symbol'], 1)

      if pre_filter then
        task:set_pre_result(r['action'], 'Matched map: ' .. r['symbol'])
      end
    end
  end

  local function apply_filename_filter(filter, fn, r)
    if filter == 'extension' or filter == 'ext' then
      return string.match(fn, '%.([^.]+)$')
    elseif string.find(filter, 'regexp:') then
      if not r['re_filter'] then
        local type,pat = string.match(filter, '(regexp:)(.+)')
        if type and pat then
          r['re_filter'] = regexp.create(pat)
        end
      end

      if not r['re_filter'] then
        rspamd_logger.errx(task, 'bad search filter: %s', filter)
      else
        local results = r['re_filter']:search(fn)
        if results then
          return results[1]
        else
          return nil
        end
      end
    end

    return fn
  end

  local function apply_content_filter(filter, r)
    if filter == 'body' then
      return {task:get_rawbody()}
    elseif filter == 'full' then
      return {task:get_content()}
    elseif filter == 'headers' then
      return {task:get_raw_headers()}
    elseif filter == 'text' then
      local ret = {}
      for i,p in ipairs(task:get_text_parts()) do
        table.insert(ret, p:get_content())
      end
      return ret
    elseif filter == 'rawtext' then
      local ret = {}
      for i,p in ipairs(task:get_text_parts()) do
        table.insert(ret, p:get_raw_content())
      end
      return ret
    elseif filter == 'oneline' then
      local ret = {}
      for i,p in ipairs(task:get_text_parts()) do
        table.insert(ret, p:get_content_oneline())
      end
      return ret
    else
      rspamd_logger.errx(task, 'bad search filter: %s', filter)
    end

    return {}
  end

  local function match_filename(r, fn)
    local value
    local ret = false

    if r['filter'] then
      value = apply_filename_filter(r['filter'], fn, r)
    else
      value = fn
    end

    ret = match_element(r, value)

    if ret then
      task:insert_result(r['symbol'], 1)

      if pre_filter then
        task:set_pre_result(r['action'], 'Matched map: ' .. r['symbol'])
      end
    end
  end

  local function match_content(r)
    local data = {}

    if r['filter'] then
      data = apply_content_filter(r['filter'], r)
    else
      data = {task:get_content()}
    end

    for i,v in ipairs(data) do
      ret = match_element(r, v)

      if ret then
        task:insert_result(r['symbol'], 1)

        if pre_filter then
          task:set_pre_result(r['action'], 'Matched map: ' .. r['symbol'])
        end
      end
    end
  end

  if rule['expression'] then
    local res,trace = rule['expression']:process_traced(task)

    if not res or res == 0 then
      rspamd_logger.debugx(task, 'condition is false for %s', rule['symbol'])
      return
    else
      rspamd_logger.debugx(task, 'condition is true for %s: %s', rule['symbol'],
        trace)
    end
  end

  local rt = rule['type']
  if rt == 'ip' or rt == 'dnsbl' then
    local ip = task:get_from_ip()
    if ip:is_valid() then
      if rt == 'ip' then
        match_rule(rule, ip)
      else
        local cb = function (resolver, to_resolve, results, err, rbl)
          if results then
            task:insert_result(rule['symbol'], 1, rule['map'])

            if pre_filter then
              task:set_pre_result(rule['action'], 'Matched map: ' .. rule['symbol'])
            end
          end
        end

        task:get_resolver():resolve_a({task = task,
          name = ip_to_rbl(ip, rule['map']),
          callback = cb,
        })
      end
    end
  elseif rt == 'header' then
    local hv = task:get_header_full(rule['header'])
    match_list(rule, hv, {'decoded'})
  elseif rt == 'rcpt' then
    if task:has_recipients('smtp') then
      local rcpts = task:get_recipients('smtp')
      match_addr(rule, rcpts)
    end
  elseif rt == 'from' then
    if task:has_from('smtp') then
      local from = task:get_from('smtp')
      match_addr(rule, from)
    end
  elseif rt == 'url' then
    if task:has_urls() then
      local urls = task:get_urls()
      for i,url in ipairs(urls) do
        match_url(rule, url)
      end
    end
  elseif rt == 'filename' then
    local parts = task:get_parts()
    for i,p in ipairs(parts) do
      if p:is_archive() then
        local fnames = p:get_archive():get_files()

        for ii,fn in ipairs(fnames) do
          match_filename(rule, fn)
        end
      end

      local fn = p:get_filename()
      if fn then
        match_filename(rule, fn)
      end
    end
  elseif rt == 'content' then
    match_content(rule)
  elseif rt == 'hostname' then
    local hostname = task:get_hostname()
    if hostname ~= 'unknown' then
      match_hostname(rule, hostname)
    end
  end
end

local function gen_multimap_callback(rule)
  return function(task)
    multimap_callback(task, rule)
  end
end

local function add_multimap_rule(key, newrule)
  local ret = false
  if newrule['url'] and not newrule['map'] then
    newrule['map'] = newrule['url']
  end
  if not newrule['map'] then
    rspamd_logger.errx(rspamd_config, 'incomplete rule, missing map')
    return nil
  end
  if not newrule['symbol'] and key then
    newrule['symbol'] = key
  elseif not newrule['symbol'] then
    rspamd_logger.errx(rspamd_config, 'incomplete rule, missing symbol')
    return nil
  end
  if not newrule['description'] then
    newrule['description'] = string.format('multimap, type %s: %s', newrule['type'],
      newrule['symbol'])
  end
  -- Check cdb flag
  if string.find(newrule['map'], '^cdb://.*$') then
    local test = cdb.create(newrule['map'])
    newrule['cdb'] = cdb.create(newrule['map'])
    if newrule['cdb'] then
      return newrule
    else
      rspamd_logger.warnx(rspamd_config, 'Cannot add rule: map doesn\'t exists: %1',
          newrule['map'])
    end
  else
    local map = urls[newrule['map']]
    if map and map['type'] == newrule['type']
        and map['regexp'] == newrule['regexp'] then
      if newrule['type'] == 'ip' then
        newrule['radix'] = map['map']
      else
        newrule['hash'] = map['map']
      end
      rspamd_logger.infox(rspamd_config, 'reuse url for %s: "%s"',
            newrule['symbol'], newrule['map'])
      ret = true
    else
      if newrule['type'] == 'ip' then
        newrule['radix'] = rspamd_config:add_map ({
          url = newrule['map'],
          description = newrule['description'],
          type = 'radix'
        })
        if newrule['radix'] then
          ret = true
          urls[newrule['map']] = {
            type = 'ip',
            map = newrule['radix'],
            regexp = false
          }
        else
          rspamd_logger.warnx(rspamd_config, 'Cannot add rule: map doesn\'t exists: %1',
            newrule['map'])
        end
      elseif newrule['type'] == 'header'
        or newrule['type'] == 'rcpt'
        or newrule['type'] == 'from'
        or newrule['type'] == 'filename'
        or newrule['type'] == 'url'
        or newrule['type'] == 'content'
        or newrule['type'] == 'hostname' then
        if newrule['regexp'] then
          newrule['hash'] = rspamd_config:add_map ({
            url = newrule['map'],
            description = newrule['description'],
            type = 'regexp'
          })
        else
          newrule['hash'] = rspamd_config:add_map ({
            url = newrule['map'],
            description = newrule['description'],
            type = 'hash'
          })
        end
        if newrule['hash'] then
          ret = true
          urls[newrule['map']] = {
            type = newrule['type'],
            map = newrule['hash'],
            regexp = newrule['regexp']
          }
        else
          rspamd_logger.warnx(rspamd_config, 'Cannot add rule: map doesn\'t exists: %1',
            newrule['map'])
        end
      elseif newrule['type'] == 'dnsbl' then
        ret = true
      end
    end
  end

  if newrule['action'] then
    newrule['prefilter'] = true
  else
    newrule['prefilter'] = false
  end

  if ret then
    if newrule['require_symbols'] and not newrule['prefilter'] then
      local atoms = {}

      local function parse_atom(str)
        local atom = table.concat(totable(take_while(function(c)
          if string.find(', \t()><+!|&\n', c) then
            return false
          end
          return true
        end, iter(str))), '')
        table.insert(atoms, atom)
        return atom
      end

      local function process_atom(atom, task)
        local ret = task:has_symbol(atom)
        rspamd_logger.debugx('check for symbol %s: %s', atom, ret)

        if ret then
          return 1
        end

        return 0
      end

      local expression = rspamd_expression.create(newrule['require_symbols'],
        {parse_atom, process_atom}, rspamd_config:get_mempool())
      if expression then
        newrule['expression'] = expression

        each(function(v)
          rspamd_logger.debugx(rspamd_config, 'add dependency %s -> %s',
            newrule['symbol'], v)
          rspamd_config:register_dependency(newrule['symbol'], v)
        end, atoms)
      end
    end
    return newrule
  end

  return nil
end

-- Registration
local opts =  rspamd_config:get_all_opt('multimap')
if opts and type(opts) == 'table' then
  for k,m in pairs(opts) do
    if type(m) == 'table' then
      local rule = add_multimap_rule(k, m)
      if not rule then
        rspamd_logger.errx(rspamd_config, 'cannot add rule: "'..k..'"')
      else
        table.insert(rules, rule)
      end
    else
      rspamd_logger.errx(rspamd_config, 'parameter ' .. k .. ' is invalid, must be an object')
    end
  end
  -- add fake symbol to check all maps inside a single callback
  if any(function(r) return not r['prefilter'] end, rules) then
    for i,rule in ipairs(rules) do
      local id = rspamd_config:register_symbol({
        type = 'normal',
        name = rule['symbol'],
        callback = gen_multimap_callback(rule),
      })
      if rule['symbols'] then
        -- Find allowed symbols by this map
        rule['symbols_set'] = {}
        each(function(s)
          rspamd_config:register_symbol({
            type = 'virtual',
            name = s,
            parent = id
          })
          rule['symbols_set'][s] = 1
        end, rule['symbols'])
      end
      if rule['score'] then
        -- Register metric symbol
        local description = 'multimap symbol'
        local group = 'multimap'
        if rule['description'] then
          description = rule['description']
        end
        if rule['group'] then
          group = rule['group']
        end
        rspamd_config:set_metric_symbol({
            name = rule['symbol'],
            score = rule['score'],
            description = description,
            group = group
        })
      end
    end
  end

  each(function(r)
    rspamd_config:register_symbol({
      type = 'prefilter',
      name = r['symbol'],
      callback = gen_multimap_callback(r),
    })
  end,
  filter(function(r) return r['prefilter'] end, rules))
end
