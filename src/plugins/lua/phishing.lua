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

local rspamd_logger = require "rspamd_logger"
local util = require "rspamd_util"
local lua_util = require "lua_util"
local lua_maps = require "lua_maps"

-- Phishing detection interface for selecting phished urls and inserting corresponding symbol
--
--
local N = 'phishing'
local symbol = 'PHISHED_URL'
local generic_service_symbol = 'PHISHED_GENERIC_SERVICE'
local openphish_symbol = 'PHISHED_OPENPHISH'
local phishtank_symbol = 'PHISHED_PHISHTANK'
local generic_service_name = 'generic service'
local domains = nil
local strict_domains = {}
local exceptions_maps = {}
local generic_service_map = nil
local openphish_map = 'https://www.openphish.com/feed.txt'
local phishtank_suffix = 'phishtank.rspamd.com'
-- Not enabled by default as their feed is quite large
local openphish_premium = false
-- Published via DNS
local phishtank_enabled = false
local generic_service_hash
local openphish_hash
local generic_service_data = {}
local openphish_data = {}


local opts = rspamd_config:get_all_opt(N)
if not (opts and type(opts) == 'table') then
  rspamd_logger.infox(rspamd_config, 'Module is unconfigured')
  return
end

local function phishing_cb(task)
  local function check_phishing_map(map, url, phish_symbol)
    local host = url:get_host()

    if host then
      local elt = map[host]
      local found_path = false
      local found_query = false
      local data = nil

      if elt then
        local path = url:get_path()
        local query = url:get_query()

        if path then
          for _,d in ipairs(elt) do
            if d['path'] == path then
              found_path = true
              data = d['data']

              if query and d['query'] and query == d['query'] then
                found_query = true
              elseif not d['query'] then
                found_query = true
              end
            end
          end
        else
          for _,d in ipairs(elt) do
            if not d['path'] then
              found_path = true
            end

            if query and d['query'] and query == d['query'] then
              found_query = true
            elseif not d['query'] then
              found_query = true
            end
          end
        end

        if found_path then
          local args

          if type(data) == 'table' then
            args = {
              data['tld'],
              data['sector'],
              data['brand'],
            }
          elseif type(data) == 'string' then
            args = data
          else
            args = host
          end

          if found_query then
            -- Query + path match
            task:insert_result(phish_symbol, 1.0, args)
          else
            -- Host + path match
            if path then
              task:insert_result(phish_symbol, 0.3, args)
            end
            -- No path, no symbol
          end
        else
          if url:is_phished() then
            -- Only host matches
            task:insert_result(phish_symbol, 0.1, host)
          end
        end
      end
    end
  end

  local function check_phishing_dns(dns_suffix, url, phish_symbol)
    local function compose_dns_query(elts)
      local cr = require "rspamd_cryptobox_hash"
      local h = cr.create()
      for _,elt in ipairs(elts) do h:update(elt) end
      return string.format("%s.%s", h:base32():sub(1, 32), dns_suffix)
    end
    local r = task:get_resolver()
    local host = url:get_host()
    local path = url:get_path()
    local query = url:get_query()

    if host and path then
      local function host_host_path_cb(_, _, results, err)
        if not err and results then
          if not query then
            task:insert_result(phish_symbol, 1.0, results)
          else
            task:insert_result(phish_symbol, 0.3, results)
          end
        end
      end

      local to_resolve_hp = compose_dns_query({host, path})
      rspamd_logger.debugm(N, task, 'try to resolve {%s, %s} -> %s',
          host, path, to_resolve_hp)
      r:resolve_txt({
        task = task,
        name = to_resolve_hp,
        callback = host_host_path_cb})


      if query then
        local function host_host_path_query_cb(_, _, results, err)
          if not err and results then
            task:insert_result(phish_symbol, 1.0, results)
          end
        end

        local to_resolve_hpq = compose_dns_query({host, path, query})
        rspamd_logger.debugm(N, task, 'try to resolve {%s, %s, %s} -> %s',
            host, path, query, to_resolve_hpq)
        r:resolve_txt({
          task = task,
          name = to_resolve_hpq,
          callback = host_host_path_query_cb})
      end

    end
  end

  -- Process all urls
  local dmarc_dom
  local dsym = task:get_symbol('DMARC_POLICY_ALLOW')
  if dsym then
    dsym = dsym[1] -- legacy stuff, need to take the first element
    if dsym.options then
      dmarc_dom = dsym.options[1]
    end
  end

  local urls = task:get_urls() or {}
  for _,url in ipairs(urls) do
    local function do_loop_iter() -- to emulate continue
      if generic_service_hash then
        check_phishing_map(generic_service_data, url, generic_service_symbol)
      end

      if openphish_hash then
        check_phishing_map(openphish_data, url, openphish_symbol)
      end

      if phishtank_enabled then
        check_phishing_dns(phishtank_suffix, url, phishtank_symbol)
      end

      if url:is_phished() and not url:is_redirected() then
        local purl = url:get_phished()

        if not purl then
          return
        end

        local tld = url:get_tld()
        local ptld = purl:get_tld()

        if not ptld or not tld then
          return
        end

        if dmarc_dom and tld == dmarc_dom then
          lua_util.debugm(N, 'exclude phishing from %s -> %s by dmarc domain', tld,
                  ptld)
          return
        end

        -- Now we can safely remove the last dot component if it is the same
        local b,_ = string.find(tld, '%.[^%.]+$')
        local b1,_ = string.find(ptld, '%.[^%.]+$')

        local stripped_tld,stripped_ptld = tld, ptld
        if b1 and b then
          if string.sub(tld, b) == string.sub(ptld, b1) then
            stripped_ptld = string.gsub(ptld, '%.[^%.]+$', '')
            stripped_tld = string.gsub(tld, '%.[^%.]+$', '')
          end

          if #ptld == 0 or #tld == 0 then
            return false
          end
        end

        local weight = 1.0
        local spoofed,why = util.is_utf_spoofed(tld, ptld)
        if spoofed then
          lua_util.debugm(N, task, "confusable: %1 -> %2: %3", tld, ptld, why)
          weight = 1.0
        else
          local dist = util.levenshtein_distance(stripped_tld, stripped_ptld, 2)
          dist = 2 * dist / (#stripped_tld + #stripped_ptld)

          if dist > 0.3 and dist <= 1.0 then
            -- Use distance to penalize the total weight
            weight = util.tanh(3 * (1 - dist + 0.1))
          elseif dist > 1 then
            -- We also check if two labels are in the same ascii/non-ascii representation
            local a1, a2 = false,false

            if string.match(tld, '^[\001-\127]*$') then a1 = true end
            if string.match(ptld, '^[\001-\127]*$') then a2 = true end

            if a1 ~= a2 then
              weight = 1
              lua_util.debugm(N, task, "confusable: %1 -> %2: different characters",
                      tld, ptld, why)
            else
              -- We have totally different strings in tld, so penalize it somehow
              weight = 0.5
            end
          end

          lua_util.debugm(N, task, "distance: %1 -> %2: %3", tld, ptld, dist)
        end

        local function is_url_in_map(map, furl)
          for _,dn in ipairs({furl:get_tld(), furl:get_host()}) do
            if map:get_key(dn) then
              return true,dn
            end
          end

          return false
        end
        local function found_in_map(map, furl, sweight)
          if not furl then furl = url end
          if not sweight then sweight = weight end
          if #map > 0 then
            for _,rule in ipairs(map) do
              local found,dn = is_url_in_map(rule.map, furl)
              if found then
                task:insert_result(rule.symbol, sweight, ptld .. '->' .. dn)
                return true
              end
            end
          end
        end

        if not found_in_map(exceptions_maps) then
          if not found_in_map(strict_domains, purl, 1.0) then
            if domains then
              if is_url_in_map(domains, purl) then
                task:insert_result(symbol, weight, ptld .. '->' .. tld)
              end
            else
              task:insert_result(symbol, weight, ptld .. '->' .. tld)
            end
          end
        end
      end
    end

    do_loop_iter()
  end
end

local function phishing_map(mapname, phishmap, id)
  if opts[mapname] then
    local xd
    if type(opts[mapname]) == 'table' then
      xd = opts[mapname]
    else
      rspamd_logger.errx(rspamd_config, 'invalid exception table')
    end


    for sym,map_data in pairs(xd) do
      local rmap = lua_maps.map_add_from_ucl (map_data, 'set',
              'Phishing ' .. mapname .. ' map')
      if rmap then
        rspamd_config:register_virtual_symbol(sym, 1, id)
        local rule = {symbol = sym, map = rmap}
        table.insert(phishmap, rule)
      else
        rspamd_logger.infox(rspamd_config, 'cannot add map for symbol: %s', sym)
      end
    end
  end
end

local function rspamd_str_split_fun(s, sep, func)
  local lpeg = require "lpeg"
  sep = lpeg.P(sep)
  local elem = lpeg.P((1 - sep)^0 / func)
  local p = lpeg.P(elem * (sep * elem)^0)
  return p:match(s)
end

local function insert_url_from_string(pool, tbl, str, data)
  local rspamd_url = require "rspamd_url"

  local u = rspamd_url.create(pool, str)

  if u then
    local host = u:get_host()
    if host then
      local elt = {
        data = data,
        path = u:get_path(),
        query = u:get_query()
      }

      if tbl[host] then
        table.insert(tbl[host], elt)
      else
        tbl[host] = {elt}
      end

      return true
    end
  end

  return false
end

local function generic_service_plain_cb(string)
  local nelts = 0
  local new_data = {}
  local rspamd_mempool = require "rspamd_mempool"
  local pool = rspamd_mempool.create()

  local function generic_service_elt_parser(cap)
    if insert_url_from_string(pool, new_data, cap, nil) then
      nelts = nelts + 1
    end
  end

  rspamd_str_split_fun(string, '\n', generic_service_elt_parser)

  generic_service_data = new_data
  rspamd_logger.infox(generic_service_hash, "parsed %s elements from %s feed",
    nelts, generic_service_name)
  pool:destroy()
end

local function openphish_json_cb(string)
  local ucl = require "ucl"
  local rspamd_mempool = require "rspamd_mempool"
  local nelts = 0
  local new_json_map = {}
  local valid = true

  local pool = rspamd_mempool.create()

  local function openphish_elt_parser(cap)
    if valid then
      local parser = ucl.parser()
      local res,err = parser:parse_string(cap)
      if not res then
        valid = false
        rspamd_logger.warnx(openphish_hash, 'cannot parse openphish map: ' .. err)
      else
        local obj = parser:get_object()

        if obj['url'] then
          if insert_url_from_string(pool, new_json_map, obj['url'], obj) then
            nelts = nelts + 1
          end
        end
      end
    end
  end

  rspamd_str_split_fun(string, '\n', openphish_elt_parser)

  if valid then
    openphish_data = new_json_map
    rspamd_logger.infox(openphish_hash, "parsed %s elements from openphish feed",
      nelts)
  end

  pool:destroy()
end

local function openphish_plain_cb(s)
  local nelts = 0
  local new_data = {}
  local rspamd_mempool = require "rspamd_mempool"
  local pool = rspamd_mempool.create()

  local function openphish_elt_parser(cap)
    if insert_url_from_string(pool, new_data, cap, nil) then
      nelts = nelts + 1
    end
  end

  rspamd_str_split_fun(s, '\n', openphish_elt_parser)

  openphish_data = new_data
  rspamd_logger.infox(openphish_hash, "parsed %s elements from openphish feed",
    nelts)
  pool:destroy()
end

if opts then
  local id
  if opts['symbol'] then
    symbol = opts['symbol']
    -- Register symbol's callback
    id = rspamd_config:register_symbol({
      name = symbol,
      callback = phishing_cb
    })

    -- To exclude from domains for dmarc verified messages
    rspamd_config:register_dependency(symbol, 'DMARC_CHECK')

    if opts['generic_service_symbol'] then
      generic_service_symbol = opts['generic_service_symbol']
    end
    if opts['generic_service_map'] then
      generic_service_map = opts['generic_service_map']
    end
    if opts['generic_service_url'] then
      generic_service_map = opts['generic_service_url']
    end
    if opts['generic_service_name'] then
      generic_service_name = opts['generic_service_name']
    end

    if opts['generic_service_enabled'] then
      generic_service_hash = rspamd_config:add_map({
          type = 'callback',
          url = generic_service_map,
          callback = generic_service_plain_cb,
          description = 'Generic feed'
        })
    end

    if opts['openphish_map'] then
      openphish_map = opts['openphish_map']
    end
    if opts['openphish_url'] then
      openphish_map = opts['openphish_url']
    end

    if opts['openphish_premium'] then
      openphish_premium = true
    end

    if opts['openphish_enabled'] then
      if not openphish_premium then
        openphish_hash = rspamd_config:add_map({
          type = 'callback',
          url = openphish_map,
          callback = openphish_plain_cb,
          description = 'Open phishing feed map (see https://www.openphish.com for details)',
          opaque_data = true,
        })
      else
        openphish_hash = rspamd_config:add_map({
            type = 'callback',
            url = openphish_map,
            callback = openphish_json_cb,
            opaque_data = true,
            description = 'Open phishing premium feed map (see https://www.openphish.com for details)'
          })
      end
    end

    if opts['phishtank_enabled'] then
      phishtank_enabled = true
      if opts['phishtank_suffix'] then
        phishtank_suffix = opts['phishtank_suffix']
      end
    end

    rspamd_config:register_symbol({
      type = 'virtual',
      parent = id,
      name = generic_service_symbol,
    })

    rspamd_config:register_symbol({
      type = 'virtual',
      parent = id,
      name = openphish_symbol,
    })

    rspamd_config:register_symbol({
      type = 'virtual',
      parent = id,
      name = phishtank_symbol,
    })
  end
  if opts['domains'] and type(opts['domains']) == 'string' then
    domains = lua_maps.map_add_from_ucl(opts['domains'], 'set',
            'Phishing domains')
  end
  phishing_map('strict_domains', strict_domains, id)
  phishing_map('exceptions', exceptions_maps, id)
end
