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
local _ = require "fun"
--local dumper = require 'pl.pretty'.dump

local function ip_to_rbl(ip, rbl)
  return table.concat(ip:inversed_str_octets(), ".") .. '.' .. rbl
end

local function multimap_callback(task, pre_filter)
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
      if not rule['regexp'] then
        local type,pat = string.match(filter, '(regexp:)(.+)')
        if type and pat then
          rule['regexp'] = regexp.create(pat)
        end
      end

      if not rule['regexp'] then
        rspamd_logger.errx(task, 'bad search filter: %s', filter)
      else
        local results = rule['regexp']:search(input)
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

  -- Match a single value for against a single rule
  local function match_rule(r, value)
    local ret = false

    if r['filter'] then
      value = apply_filter(r['filter'], value, r)
    end

    ret = match_element(r, value)

    if ret then
      task:insert_result(r['symbol'], 1)

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
        _.each(function(e)
          local match = e[fields[1]]
          if match then
            if fields[2] then
              match = fields[2](match)
            end
            ret = match_rule(r, match)
          end
        end, ls)
      else
        _.each(function(e) ret = match_rule(r, e) end, ls)
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

  -- IP rules
  local ip = task:get_from_ip()
  if ip:is_valid() then
    _.each(function(r) match_rule(r, ip) end,
      _.filter(function(r)
        return pre_filter == r['prefilter'] and r['type'] == 'ip'
      end, rules))
  end

  -- Header rules
  _.each(function(r)
    local hv = task:get_header_full(r['header'])
    match_list(r, hv, {'decoded'})
  end,
  _.filter(function(r)
    return pre_filter == r['prefilter'] and r['type'] == 'header'
  end, rules))

  -- Rcpt rules
  if task:has_recipients() then
    local rcpts = task:get_recipients()
    _.each(function(r)
      match_addr(r, rcpts)
    end,
    _.filter(function(r)
      return pre_filter == r['prefilter'] and r['type'] == 'rcpt'
    end, rules))
  end

  -- From rules
  if task:has_from() then
    local from = task:get_from()
    if from then
      _.each(function(r)
        match_addr(r, from)
      end,
      _.filter(function(r)
        return pre_filter == r['prefilter'] and r['type'] == 'from'
      end, rules))
    end
  end
  -- URL rules
  if task:has_urls() then
    local urls = task:get_urls()
    for i,url in ipairs(urls) do
      _.each(function(r)
        match_url(r, url)
      end,
      _.filter(function(r)
        return pre_filter == r['prefilter'] and r['type'] == 'url'
      end, rules))
    end
  end

  -- RBL rules
  if ip:is_valid() then
    _.each(function(r)
        local cb = function (resolver, to_resolve, results, err, rbl)
          if results then
            task:insert_result(r['symbol'], 1, r['map'])

            if pre_filter then
              task:set_pre_result(r['action'], 'Matched map: ' .. r['symbol'])
            end
          end
        end

        task:get_resolver():resolve_a({task = task,
          name = ip_to_rbl(ip, r['map']),
          callback = cb,
          })
      end,
    _.filter(function(r)
      return pre_filter == r['prefilter'] and r['type'] == 'dnsbl'
    end, rules))
  end
end

local function multimap_filter_callback(task)
  multimap_callback(task, false)
end

local function multimap_prefilter_callback(task)
  multimap_callback(task, true)
end

local function add_multimap_rule(key, newrule)
  local ret = false
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
    if newrule['type'] == 'ip' then
      newrule['radix'] = rspamd_config:add_radix_map (newrule['map'],
        newrule['description'])
      if newrule['radix'] then
        ret = true
      else
        rspamd_logger.warnx(rspamd_config, 'Cannot add rule: map doesn\'t exists: %1',
            newrule['map'])
      end
    elseif newrule['type'] == 'header'
        or newrule['type'] == 'rcpt'
        or newrule['type'] == 'from'
        or newrule['type'] == 'url' then
      newrule['hash'] = rspamd_config:add_hash_map (newrule['map'], newrule['description'])
      if newrule['hash'] then
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
  if _.any(function(r) return not r['prefilter'] end, rules) then
    local id = rspamd_config:register_callback_symbol_priority(1.0, -1,
      multimap_filter_callback)
    for i,rule in ipairs(rules) do
      rspamd_config:register_virtual_symbol(rule['symbol'], 1.0, id)
    end
  end

  if _.any(function(r) return r['prefilter'] end, rules) then
    rspamd_config:register_pre_filter(multimap_prefilter_callback)
  end
end
