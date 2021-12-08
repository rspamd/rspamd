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

-- Multimap is rspamd module designed to define and operate with different maps

local rules = {}
local rspamd_logger = require "rspamd_logger"
local rspamd_util = require "rspamd_util"
local rspamd_regexp = require "rspamd_regexp"
local rspamd_expression = require "rspamd_expression"
local rspamd_ip = require "rspamd_ip"
local lua_util = require "lua_util"
local lua_selectors = require "lua_selectors"
local lua_maps = require "lua_maps"
local redis_params
local fun = require "fun"
local N = 'multimap'

local value_types = {
  ip = {
    get_value = function(ip) return ip:to_string() end,
  },
  from = {
    get_value = function(val) return val end,
  },
  helo = {
    get_value = function(val) return val end,
  },
  header = {
    get_value = function(val) return val end,
  },
  rcpt = {
    get_value = function(val) return val end,
  },
  user = {
    get_value = function(val) return val end,
  },
  url = {
    get_value = function(val) return val end,
  },
  dnsbl = {
    get_value = function(ip) return ip:to_string() end,
  },
  filename = {
    get_value = function(val) return val end,
  },
  content = {
    get_value = function() return nil end,
  },
  hostname = {
    get_value = function(val) return val end,
  },
  asn = {
    get_value = function(val) return val end,
  },
  country = {
    get_value = function(val) return val end,
  },
  received = {
    get_value = function(val) return val end,
  },
  mempool = {
    get_value = function(val) return val end,
  },
  selector = {
    get_value = function(val) return val end,
  },
  symbol_options = {
    get_value = function(val) return val end,
  },
}

local function ip_to_rbl(ip, rbl)
  return table.concat(ip:inversed_str_octets(), ".") .. '.' .. rbl
end

local function apply_hostname_filter(task, filter, hostname, r)
  if filter == 'tld' then
    local tld = rspamd_util.get_tld(hostname)
    return tld
  elseif filter == 'top' then
    local tld = rspamd_util.get_tld(hostname)
    return tld:match('[^.]*$') or tld
  else
    if not r['re_filter'] then
      local pat = string.match(filter, 'tld:regexp:(.+)')
      if not pat then
        rspamd_logger.errx(task, 'bad search filter: %s', filter)
        return
      end
      r['re_filter'] = rspamd_regexp.create_cached(pat)
      if not r['re_filter'] then
        rspamd_logger.errx(task, 'couldnt create regex: %s', pat)
        return
      end
    end
    local tld = rspamd_util.get_tld(hostname)
    local res = r['re_filter']:search(tld)
    if res then
      return res[1]
    else
      return nil
    end
  end
end

local function apply_url_filter(task, filter, url, r)
  if not filter then
    return url:get_host()
  end

  if filter == 'tld' then
    return url:get_tld()
  elseif filter == 'top' then
    local tld = url:get_tld()
    return tld:match('[^.]*$') or tld
  elseif filter == 'full' then
    return url:get_text()
  elseif filter == 'is_phished' then
    if url:is_phished() then
      return url:get_host()
    else
      return nil
    end
  elseif filter == 'is_redirected' then
    if url:is_redirected() then
      return url:get_host()
    else
      return nil
    end
  elseif filter == 'is_obscured' then
    if url:is_obscured() then
      return url:get_host()
    else
      return nil
    end
  elseif filter == 'path' then
    return url:get_path()
  elseif filter == 'query' then
    return url:get_query()
  elseif string.find(filter, 'tag:') then
    local tags = url:get_tags()
    local want_tag = string.match(filter, 'tag:(.*)')
    for _, t in ipairs(tags) do
      if t == want_tag then
        return url:get_host()
      end
    end
    return nil
  elseif string.find(filter, 'tld:regexp:') then
    if not r['re_filter'] then
      local type,pat = string.match(filter, '(regexp:)(.+)')
      if type and pat then
        r['re_filter'] = rspamd_regexp.create_cached(pat)
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
        r['re_filter'] = rspamd_regexp.create_cached(pat)
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
        r['re_filter'] = rspamd_regexp.create_cached(pat)
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
  elseif string.find(filter, '^template:') then
    if not r['template'] then
      r['template'] = string.match(filter, '^template:(.+)')
    end

    if r['template'] then
      return lua_util.template(r['template'], url:to_table())
    end
  end

  return url:get_host()
end

local function apply_addr_filter(task, filter, input, rule)
  if filter == 'email:addr' or filter == 'email' then
    local addr = rspamd_util.parse_mail_address(input, task:get_mempool(), 1024)
    if addr and addr[1] then
      return fun.totable(fun.map(function(a) return a.addr end, addr))
    end
  elseif filter == 'email:user' then
    local addr = rspamd_util.parse_mail_address(input, task:get_mempool(), 1024)
    if addr and addr[1] then
      return fun.totable(fun.map(function(a) return a.user end, addr))
    end
  elseif filter == 'email:domain' then
    local addr = rspamd_util.parse_mail_address(input, task:get_mempool(), 1024)
    if addr and addr[1] then
      return fun.totable(fun.map(function(a) return a.domain end, addr))
    end
  elseif filter == 'email:domain:tld' then
    local addr = rspamd_util.parse_mail_address(input, task:get_mempool(), 1024)
    if addr and addr[1] then
      return fun.totable(fun.map(function(a) return rspamd_util.get_tld(a.domain) end, addr))
    end
  elseif filter == 'email:name' then
    local addr = rspamd_util.parse_mail_address(input, task:get_mempool(), 1024)
    if addr and addr[1] then
      return fun.totable(fun.map(function(a) return a.name end, addr))
    end
  elseif filter == 'ip_addr' then
    local ip_addr = rspamd_ip.from_string(input)

    if ip_addr and ip_addr:is_valid() then
      return ip_addr
    end
  else
    -- regexp case
    if not rule['re_filter'] then
      local type,pat = string.match(filter, '(regexp:)(.+)')
      if type and pat then
        rule['re_filter'] = rspamd_regexp.create_cached(pat)
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
local function apply_filename_filter(task, filter, fn, r)
  if filter == 'extension' or filter == 'ext' then
    return string.match(fn, '%.([^.]+)$')
  elseif string.find(filter, 'regexp:') then
    if not r['re_filter'] then
      local type,pat = string.match(filter, '(regexp:)(.+)')
      if type and pat then
        r['re_filter'] = rspamd_regexp.create_cached(pat)
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

local function apply_regexp_filter(task, filter, fn, r)
  if string.find(filter, 'regexp:') then
    if not r['re_filter'] then
      local type,pat = string.match(filter, '(regexp:)(.+)')
      if type and pat then
        r['re_filter'] = rspamd_regexp.create_cached(pat)
      end
    end

    if not r['re_filter'] then
      rspamd_logger.errx(task, 'bad search filter: %s', filter)
    else
      local results = r['re_filter']:search(fn, false, true)
      if results then
        return results[1][2]
      else
        return nil
      end
    end
  end

  return fn
end

local function apply_content_filter(task, filter)
  if filter == 'body' then
    return {task:get_rawbody()}
  elseif filter == 'full' then
    return {task:get_content()}
  elseif filter == 'headers' then
    return {task:get_raw_headers()}
  elseif filter == 'text' then
    local ret = {}
    for _,p in ipairs(task:get_text_parts()) do
      table.insert(ret, p:get_content())
    end
    return ret
  elseif filter == 'rawtext' then
    local ret = {}
    for _,p in ipairs(task:get_text_parts()) do
      table.insert(ret, p:get_raw_content())
    end
    return ret
  elseif filter == 'oneline' then
    local ret = {}
    for _,p in ipairs(task:get_text_parts()) do
      table.insert(ret, p:get_content_oneline())
    end
    return ret
  else
    rspamd_logger.errx(task, 'bad search filter: %s', filter)
  end

  return {}
end

local multimap_filters = {
  from = apply_addr_filter,
  rcpt = apply_addr_filter,
  helo = apply_hostname_filter,
  symbol_options = apply_regexp_filter,
  header = apply_addr_filter,
  url = apply_url_filter,
  filename = apply_filename_filter,
  mempool = apply_regexp_filter,
  selector = apply_regexp_filter,
  hostname = apply_hostname_filter,
  --content = apply_content_filter, -- Content filters are special :(
}

local multimap_grammar

local function multimap_query_redis(key, task, value, callback)
  local cmd = 'HGET'
  if type(value) == 'userdata' and value.class == 'rspamd{ip}' then
    cmd = 'HMGET'
  end

  local srch = {key}

  -- Insert all ips for some mask :(
  if type(value) == 'userdata' and value.class == 'rspamd{ip}' then
    srch[#srch + 1] = tostring(value)
    -- IPv6 case
    local maxbits = 128
    local minbits = 64
    if value:get_version() == 4 then
      maxbits = 32
      minbits = 8
    end
    for i=maxbits,minbits,-1 do
      local nip = value:apply_mask(i):tostring() .. "/" .. i
      srch[#srch + 1] = nip
    end
  else
    srch[#srch + 1] = value
  end

  local function redis_map_cb(err, data)
    lua_util.debugm(N, task, 'got reply from Redis when trying to get key %s: err=%s, data=%s',
        key, err, data)
    if not err and type(data) ~= 'userdata' then
      callback(data)
    end
  end

  return rspamd_redis_make_request(task,
      redis_params, -- connect params
      key, -- hash key
      false, -- is write
      redis_map_cb, --callback
      cmd, -- command
      srch -- arguments
  )
end

local function multimap_callback(task, rule)
  local pre_filter = rule['prefilter']

  local function match_element(r, value, callback)
    if not value then
      return false
    end

    lua_util.debugm(N, task, 'check value %s for multimap %s', value,
        rule.symbol)

    local ret = false

    if r.redis_key then
      -- Deal with hash name here: it can be either plain string or a selector
      if type(r.redis_key) == 'string' then
        ret = multimap_query_redis(r.redis_key, task, value, callback)
      else
        -- Here we have a selector
        local results = r.redis_key(task)

        -- Here we need to spill this function into multiple queries
        if type(results) == 'table' then
          for _,res in ipairs(results) do
            ret = multimap_query_redis(res, task, value, callback)

            if not ret then
              break
            end
          end
        else
          ret = multimap_query_redis(results, task, value, callback)
        end
      end

      return ret
    elseif r.radix then
      ret = r.radix:get_key(value)
    elseif r.hash then
      if type(value) == 'userdata' then
        if value.class == 'rspamd{ip}' then
          value = value:tostring()
        end
      end
      ret = r.hash:get_key(value)
    end

    lua_util.debugm(N, task, 'found return "%s" for multimap %s', ret,
    rule.symbol)

    if ret then
      if type(ret) == 'table' then
        for _,elt in ipairs(ret) do
          callback(elt)
        end

        ret = true
      else
        callback(ret)
      end
    end

    return ret
  end

  -- Parse result in form: <symbol>:<score>|<symbol>|<score>
  local function parse_ret(parse_rule, p_ret)
    if p_ret and type(p_ret) == 'string' then
      local lpeg = require "lpeg"

      if not multimap_grammar then
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
        multimap_grammar = lpeg.Ct(grammar)
      end
      local tbl = multimap_grammar:match(p_ret)

      if tbl then
        local sym
        local score = 1.0

        if tbl['symbol'] then
          sym = tbl['symbol']
        end
        if tbl['score'] then
          score = tbl['score']
        end

        return true,sym,score
      else
        if p_ret ~= '' then
          rspamd_logger.infox(task, '%s: cannot parse string "%s"',
              parse_rule.symbol, p_ret)
        end

        return true,nil,1.0
      end
    elseif type(p_ret) == 'boolean' then
      return p_ret,nil,1.0
    end

    return false,nil,0.0
  end

  local function insert_results(result, opt)
    local _,symbol,score = parse_ret(rule, result)
    local forced = false
    if symbol then
      if rule.symbols_set then
        if not rule.symbols_set[symbol] then
          rspamd_logger.infox(task, 'symbol %s is not registered for map %s, ' ..
              'replace it with just %s',
              symbol, rule.symbol, rule.symbol)
          symbol = rule.symbol
        end
      elseif rule.disable_multisymbol then
        symbol = rule.symbol
        if type(opt) == 'table' then
          table.insert(opt, result)
        elseif type(opt) ~= nil then
          opt = {opt,result}
        else
          opt = {result}
        end
      else
        forced = true
      end
    else
      symbol = rule.symbol
    end

    if opt then
      if type(opt) == 'table' then
        task:insert_result(forced, symbol, score, fun.totable(fun.map(tostring, opt)))
      else
        task:insert_result(forced, symbol, score, tostring(opt))
      end

    else
      task:insert_result(forced, symbol, score)
    end

    if pre_filter then
      local message = rule.message
      if rule.message_func then
        message = rule.message_func(task, rule.symbol, opt)
      end
      if message then
        task:set_pre_result(rule.action, message, N)
      else
        task:set_pre_result(rule.action, 'Matched map: ' .. rule.symbol, N)
      end
    end
  end

  -- Match a single value for against a single rule
  local function match_rule(r, value)
    local function rule_callback(result)
      if result then
        if type(result) == 'table' then
          for _,rs in ipairs(result) do
            if type(rs) ~= 'userdata' then
              rule_callback(rs)
            end
          end
          return
        end
        local opt = value_types[r['type']].get_value(value)
        insert_results(result, opt)
      end
    end

    if r.filter or r.type == 'url' then
      local fn = multimap_filters[r.type]

      if fn then

        local filtered_value = fn(task, r.filter, value, r)
        lua_util.debugm(N, task, 'apply filter %s for rule %s: %s -> %s',
            r.filter, r.symbol, value, filtered_value)
        value = filtered_value
      end
    end

    if type(value) == 'table' then
      fun.each(function(elt) match_element(r, elt, rule_callback) end, value)
    else
      match_element(r, value, rule_callback)
    end
  end

  -- Match list of values according to the field
  local function match_list(r, ls, fields)
    if ls then
      if fields then
        fun.each(function(e)
          local match = e[fields[1]]
          if match then
            if fields[2] then
              match = fields[2](match)
            end
            match_rule(r, match)
          end
        end, ls)
      else
        fun.each(function(e) match_rule(r, e) end, ls)
      end
    end
  end

  local function match_addr(r, addr)
    match_list(r, addr, {'addr'})

    if not r.filter then
      match_list(r, addr, {'domain'})
      match_list(r, addr, {'user'})
    end
  end

  local function match_url(r, url)
    match_rule(r, url)
  end

  local function match_hostname(r, hostname)
    match_rule(r, hostname)
  end

  local function match_filename(r, fn)
    match_rule(r, fn)
  end

  local function match_received_header(r, pos, total, h)
    local use_tld = false
    local filter = r['filter'] or 'real_ip'
    if filter:match('^tld:') then
      filter = filter:sub(5)
      use_tld = true
    end
    local v = h[filter]
    if v then
      local min_pos = tonumber(r['min_pos'])
      local max_pos = tonumber(r['max_pos'])
      if min_pos then
        if min_pos < 0 then
          if min_pos == -1 then
            if (pos ~= total) then
              return
            end
          else
            if pos <= (total - (min_pos*-1)) then
              return
            end
          end
        elseif pos < min_pos then
          return
        end
      end
      if max_pos then
        if max_pos < -1 then
          if (total - (max_pos*-1)) >= pos then
            return
          end
        elseif max_pos > 0 then
          if pos > max_pos then
            return
          end
        end
      end
      local match_flags = r['flags']
      local nmatch_flags = r['nflags']
      if match_flags or nmatch_flags then
        local got_flags = h['flags']
        if match_flags then
          for _, flag in ipairs(match_flags) do
            if not got_flags[flag] then return end
          end
        end
        if nmatch_flags then
          for _, flag in ipairs(nmatch_flags) do
            if got_flags[flag] then return end
          end
        end
      end
      if filter == 'real_ip' or filter == 'from_ip' then
        if type(v) == 'string' then
          v = rspamd_ip.from_string(v)
        end
        if v and v:is_valid() then
          match_rule(r, v)
        end
      else
        if use_tld and type(v) == 'string' then
          v = rspamd_util.get_tld(v)
        end
        match_rule(r, v)
      end
    end
  end

  local function match_content(r)
    local data

    if r['filter'] then
      data = apply_content_filter(task, r['filter'], r)
    else
      data = {task:get_content()}
    end

    for _,v in ipairs(data) do
      match_rule(r, v)
    end
  end

  if rule.expression and not rule.combined then
    local res,trace = rule['expression']:process_traced(task)

    if not res or res == 0 then
      lua_util.debugm(N, task, 'condition is false for %s',
          rule.symbol)
      return
    else
      lua_util.debugm(N, task, 'condition is true for %s: %s',
          rule.symbol,
          trace)
    end
  end

  local process_rule_funcs = {
    ip = function()
      local ip = task:get_from_ip()
      if ip and ip:is_valid() then
        match_rule(rule, ip)
      end
    end,
    dnsbl = function()
      local ip = task:get_from_ip()
      if ip and ip:is_valid() then
        local to_resolve = ip_to_rbl(ip, rule['map'])
        local function dns_cb(_, _, results, err)
          lua_util.debugm(N, rspamd_config,
              'resolve() finished: results=%1, err=%2, to_resolve=%3',
              results, err, to_resolve)

          if err and
              (err ~= 'requested record is not found' and
                  err ~= 'no records with this name') then
            rspamd_logger.errx(task, 'error looking up %s: %s', to_resolve, results)
          elseif results then
            task:insert_result(rule['symbol'], 1, rule['map'])
            if pre_filter then
              task:set_pre_result(rule['action'],
                  'Matched map: ' .. rule['symbol'], N)
            end
          end
        end

        task:get_resolver():resolve_a({
          task= task,
          name = to_resolve,
          callback = dns_cb,
          forced = true
        })
      end
    end,
    header = function()
      if type(rule['header']) == 'table' then
        for _,rh in ipairs(rule['header']) do
          local hv = task:get_header_full(rh)
          match_list(rule, hv, {'decoded'})
        end
      else
        local hv = task:get_header_full(rule['header'])
        match_list(rule, hv, {'decoded'})
      end
    end,
    rcpt = function()
      if task:has_recipients('smtp') then
        local rcpts = task:get_recipients('smtp')
        match_addr(rule, rcpts)
      elseif task:has_recipients('mime') then
        local rcpts = task:get_recipients('mime')
        match_addr(rule, rcpts)
      end
    end,
    from = function()
      if task:has_from('smtp') then
        local from = task:get_from('smtp')
        match_addr(rule, from)
      elseif task:has_from('mime') then
        local from = task:get_from('mime')
        match_addr(rule, from)
      end
    end,
    helo = function()
      local helo = task:get_helo()
      if helo then
        match_hostname(rule, helo)
      end
    end,
    url = function()
      if task:has_urls() then
        local msg_urls = task:get_urls()

        for _,url in ipairs(msg_urls) do
          match_url(rule, url)
        end
      end
    end,
    user = function()
      local user = task:get_user()
      if user then
        match_rule(rule, user)
      end
    end,
    filename = function()
      local parts = task:get_parts()

      local function filter_parts(p)
        return p:is_attachment() or (not p:is_text()) and (not p:is_multipart())
      end

      local function filter_archive(p)
        local ext = p:get_detected_ext()
        local det_type = 'unknown'

        if ext then
          local lua_magic_types = require "lua_magic/types"
          local det_t = lua_magic_types[ext]

          if det_t then
            det_type = det_t.type
          end
        end

        return p:is_archive() and det_type == 'archive' and not rule.skip_archives
      end

      for _,p in fun.iter(fun.filter(filter_parts, parts)) do
        if filter_archive(p) then
          local fnames = p:get_archive():get_files(1000)

          for _,fn in ipairs(fnames) do
            match_filename(rule, fn)
          end
        end

        local fn = p:get_filename()
        if fn then
          match_filename(rule, fn)
        end
        -- Also deal with detected content type
        if not rule.skip_detected then
          local ext = p:get_detected_ext()

          if ext then
            local fake_fname = string.format('detected.%s', ext)
            lua_util.debugm(N, task, 'detected filename %s',
                fake_fname)
            match_filename(rule, fake_fname)
          end
        end
      end
    end,

    content = function()
      match_content(rule)
    end,
    hostname = function()
      local hostname = task:get_hostname()
      if hostname then
        match_hostname(rule, hostname)
      end
    end,
    asn = function()
      local asn = task:get_mempool():get_variable('asn')
      if asn then
        match_rule(rule, asn)
      end
    end,
    country = function()
      local country = task:get_mempool():get_variable('country')
      if country then
        match_rule(rule, country)
      end
    end,
    mempool = function()
      local var = task:get_mempool():get_variable(rule['variable'])
      if var then
        match_rule(rule, var)
      end
    end,
    symbol_options = function()
      local sym = task:get_symbol(rule['target_symbol'])
      if sym and sym[1].options then
        for _, o in ipairs(sym[1].options) do
          match_rule(rule, o)
        end
      end
    end,
    received = function()
      local hdrs = task:get_received_headers()
      if hdrs and hdrs[1] then
        if not rule['artificial'] then
          hdrs = fun.filter(function(h)
            return not h['flags']['artificial']
          end, hdrs):totable()
        end
        for pos, h in ipairs(hdrs) do
          match_received_header(rule, pos, #hdrs, h)
        end
      end
    end,
    selector = function()
      local elts = rule.selector(task)

      if elts then
        if type(elts) == 'table' then
          for _,elt in ipairs(elts) do
            match_rule(rule, elt)
          end
        else
          match_rule(rule, elts)
        end
      end
    end,
    combined = function()
      local ret,trace = rule.combined:process(task)
      if ret and ret ~= 0 then
        for n,t in pairs(trace) do
          insert_results(t.value, string.format("%s=%s",
              n, t.matched))
        end
      end
    end,
  }

  local rt = rule.type
  local process_func = process_rule_funcs[rt]
  if process_func then
    process_func()
  else
    rspamd_logger.errx(task, 'Unrecognised rule type: %s', rt)
  end
end

local function gen_multimap_callback(rule)
  return function(task)
    multimap_callback(task, rule)
  end
end

local function add_multimap_rule(key, newrule)
  local ret = false

  local function multimap_load_hash(rule)
    if rule['regexp'] then
      if rule['multi'] then
        rule.hash = lua_maps.map_add_from_ucl(rule.map, 'regexp_multi',
            rule.description)
      else
        rule.hash = lua_maps.map_add_from_ucl(rule.map, 'regexp',
            rule.description)
      end
    elseif rule['glob'] then
      if rule['multi'] then
        rule.hash = lua_maps.map_add_from_ucl(rule.map, 'glob_multi',
            rule.description)
      else
        rule.hash = lua_maps.map_add_from_ucl(rule.map, 'glob',
            rule.description)
      end
    else
      rule.hash = lua_maps.map_add_from_ucl(rule.map, 'hash',
          rule.description)
    end
  end

  local known_generic_types = {
    header = true,
    rcpt = true,
    from = true,
    helo = true,
    symbol_options = true,
    filename = true,
    url = true,
    user = true,
    content = true,
    hostname = true,
    asn = true,
    country = true,
    mempool = true,
    selector = true,
    combined = true
  }

  if newrule['message_func'] then
    newrule['message_func'] = assert(load(newrule['message_func']))()
  end
  if newrule['url'] and not newrule['map'] then
    newrule['map'] = newrule['url']
  end
  if not (newrule.map or newrule.rules)  then
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
  if newrule['type'] == 'mempool' and not newrule['variable'] then
    rspamd_logger.errx(rspamd_config, 'mempool map requires variable')
    return nil
  end
  if newrule['type'] == 'selector' then
    if not newrule['selector'] then
      rspamd_logger.errx(rspamd_config, 'selector map requires selector definition')
      return nil
    else
      local selector = lua_selectors.create_selector_closure(
          rspamd_config, newrule['selector'], newrule['delimiter'] or "")

      if not selector then
        rspamd_logger.errx(rspamd_config, 'selector map has invalid selector: "%s", symbol: %s',
            newrule['selector'], newrule['symbol'])
        return nil
      end

      newrule.selector = selector
    end
  end
  if type(newrule['map']) == 'string' and
      string.find(newrule['map'], '^redis://.*$') then
    if not redis_params then
      rspamd_logger.infox(rspamd_config, 'no redis servers are specified, ' ..
          'cannot add redis map %s: %s', newrule['symbol'], newrule['map'])
      return nil
    end

    newrule['redis_key'] = string.match(newrule['map'], '^redis://(.*)$')

    if newrule['redis_key'] then
      ret = true
    end
  elseif type(newrule['map']) == 'string' and
      string.find(newrule['map'], '^redis%+selector://.*$') then
    if not redis_params then
      rspamd_logger.infox(rspamd_config, 'no redis servers are specified, ' ..
          'cannot add redis map %s: %s', newrule['symbol'], newrule['map'])
      return nil
    end

    local selector_str = string.match(newrule['map'], '^redis%+selector://(.*)$')
    local selector = lua_selectors.create_selector_closure(
        rspamd_config, selector_str, newrule['delimiter'] or "")

    if not selector then
      rspamd_logger.errx(rspamd_config, 'redis selector map has invalid selector: "%s", symbol: %s',
          selector_str, newrule['symbol'])
      return nil
    end

    newrule['redis_key'] = selector
    ret = true
  elseif newrule.type == 'combined' then
    local lua_maps_expressions = require "lua_maps_expressions"
    newrule.combined = lua_maps_expressions.create(rspamd_config,
        {
          rules = newrule.rules,
          expression = newrule.expression
        }, N, 'Combined map for ' .. newrule.symbol)
    if not newrule.combined then
      rspamd_logger.errx(rspamd_config, 'cannot add combined map for %s', newrule.symbol)
    else
      ret = true
    end
  else
    if newrule['type'] == 'ip' then
      newrule['radix'] = lua_maps.map_add_from_ucl(newrule.map, 'radix',
          newrule.description)
      if newrule['radix'] then
        ret = true
      else
        rspamd_logger.warnx(rspamd_config, 'Cannot add rule: map doesn\'t exists: %1',
            newrule['map'])
      end
    elseif newrule['type'] == 'received' then
      if type(newrule['flags']) == 'table' and newrule['flags'][1] then
        newrule['flags'] = newrule['flags']
      elseif type(newrule['flags']) == 'string' then
        newrule['flags'] = {newrule['flags']}
      end
      if type(newrule['nflags']) == 'table' and newrule['nflags'][1] then
        newrule['nflags'] = newrule['nflags']
      elseif type(newrule['nflags']) == 'string' then
        newrule['nflags'] = {newrule['nflags']}
      end
      local filter = newrule['filter'] or 'real_ip'
      if filter == 'real_ip' or filter == 'from_ip' then
        newrule['radix'] = lua_maps.map_add_from_ucl(newrule.map, 'radix',
            newrule.description)
        if newrule['radix'] then
          ret = true
        end
      else
        multimap_load_hash(newrule)

        if newrule['hash'] then
          ret = true
        else
          rspamd_logger.warnx(rspamd_config, 'Cannot add rule: map doesn\'t exists: %1',
              newrule['map'])
        end
      end
    elseif known_generic_types[newrule.type] then

      if newrule.filter == 'ip_addr' then
        newrule['radix'] = lua_maps.map_add_from_ucl(newrule.map, 'radix',
            newrule.description)
      elseif not newrule.combined then
        multimap_load_hash(newrule)
      end

      if newrule.hash or newrule.radix then
        ret = true
      else
        rspamd_logger.warnx(rspamd_config, 'Cannot add rule: map doesn\'t exists: %1',
            newrule['map'])
      end
    elseif newrule['type'] == 'dnsbl' then
      ret = true
    end
  end

  if newrule['action'] then
    newrule['prefilter'] = true
  else
    newrule['prefilter'] = false
  end

  if ret then
    if newrule['type'] == 'symbol_options' then
      rspamd_config:register_dependency(newrule['symbol'], newrule['target_symbol'])
    end
    if newrule['require_symbols'] and not newrule['prefilter'] then
      local atoms = {}

      local function parse_atom(str)
        local atom = table.concat(fun.totable(fun.take_while(function(c)
          if string.find(', \t()><+!|&\n', c) then
            return false
          end
          return true
        end, fun.iter(str))), '')
        table.insert(atoms, atom)
        return atom
      end

      local function process_atom(atom, task)
        local f_ret = task:has_symbol(atom)
        lua_util.debugm(N, rspamd_config, 'check for symbol %s: %s', atom, f_ret)

        if f_ret then
          return 1
        end

        return 0
      end

      local expression = rspamd_expression.create(newrule['require_symbols'],
          {parse_atom, process_atom}, rspamd_config:get_mempool())
      if expression then
        newrule['expression'] = expression

        fun.each(function(v)
          lua_util.debugm(N, rspamd_config, 'add dependency %s -> %s',
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
local opts = rspamd_config:get_all_opt(N)
if opts and type(opts) == 'table' then
  redis_params = rspamd_parse_redis_server(N)
  for k,m in pairs(opts) do
    if type(m) == 'table' and m['type'] then
      local rule = add_multimap_rule(k, m)
      if not rule then
        rspamd_logger.errx(rspamd_config, 'cannot add rule: "'..k..'"')
      else
        rspamd_logger.infox(rspamd_config, 'added multimap rule: %s (%s)',
            k, rule.type)
        table.insert(rules, rule)
      end
    end
  end
  -- add fake symbol to check all maps inside a single callback
  fun.each(function(rule)
    local id = rspamd_config:register_symbol({
      type = 'normal',
      name = rule['symbol'],
      callback = gen_multimap_callback(rule),
    })
    if rule['symbols'] then
      -- Find allowed symbols by this map
      rule['symbols_set'] = {}
      fun.each(function(s)
        rspamd_config:register_symbol({
          type = 'virtual',
          name = s,
          parent = id,
          score = 0, -- Default score
        })
        rule['symbols_set'][s] = 1
      end, rule['symbols'])
    end
    if not rule.score then
      rspamd_logger.infox(rspamd_config, 'set default score 0 for multimap rule %s', rule.symbol)
      rule.score = 0
    end
    if rule.score then
      -- Register metric symbol
      rule.name = rule.symbol
      rule.description = rule.description or 'multimap symbol'
      rule.group = rule.group or N

      local tmp_flags
      tmp_flags = rule.flags

      if rule.type == 'received' and rule.flags then
        -- XXX: hack to allow received flags/nflags
        -- See issue #3526 on GH
        rule.flags = nil
      end

      -- XXX: for combined maps we use trace, so flags must include one_shot to avoid scores multiplication
      if rule.combined and not rule.flags then
        rule.flags = 'one_shot'
      end
      rspamd_config:set_metric_symbol(rule)
      rule.flags = tmp_flags
    end
  end, fun.filter(function(r) return not r['prefilter'] end, rules))

  -- prefilter symbils
  fun.each(function(rule)
    rspamd_config:register_symbol({
      type = 'prefilter',
      name = rule['symbol'],
      score = rule.score or 0,
      callback = gen_multimap_callback(rule),
    })
  end, fun.filter(function(r) return r['prefilter'] end, rules))

  if #rules == 0 then
    lua_util.disable_module(N, "config")
  end
end
