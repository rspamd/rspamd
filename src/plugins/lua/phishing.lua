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

-- Phishing detection interface for selecting phished urls and inserting corresponding symbol
--
--
local N = 'phishing'
local symbol = 'PHISHED_URL'
local openphish_symbol = 'PHISHED_OPENPHISH'
local phishtank_symbol = 'PHISHED_PHISHTANK'
local domains = nil
local strict_domains = {}
local redirector_domains = {}
local openphish_map = 'https://www.openphish.com/feed.txt'
local phishtank_map = 'http://data.phishtank.com/data/online-valid.json'
-- Not enabled by default as their feed is quite large
local openphish_premium = false
local openphish_hash
local phishtank_hash
local openphish_data = {}
local phishtank_data = {}
local rspamd_logger = require "rspamd_logger"
local util = require "rspamd_util"
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

  local urls = task:get_urls()

  if urls then
    for _,url in ipairs(urls) do
      if openphish_hash then
        check_phishing_map(openphish_data, url, openphish_symbol)
      end

      if phishtank_hash then
        check_phishing_map(phishtank_data, url, phishtank_symbol)
      end

      if url:is_phished() and not url:is_redirected() then
        local purl = url:get_phished()
        local tld = url:get_tld()
        local ptld = purl:get_tld()

        if not ptld or not tld then
          return
        end

        -- Now we can safely remove the last dot component if it is the same
        local b,_ = string.find(tld, '%.[^%.]+$')
        local b1,_ = string.find(ptld, '%.[^%.]+$')

        if b1 and b then
          if string.sub(tld, b) == string.sub(ptld, b1) then
            ptld = string.gsub(ptld, '%.[^%.]+$', '')
            tld = string.gsub(tld, '%.[^%.]+$', '')
          end

          if #ptld == 0 or #tld == 0 then
            return false
          end
        end

        local weight = 1.0
        local spoofed,why = util.is_utf_spoofed(tld, ptld)
        if spoofed then
          rspamd_logger.debugm(N, task, "confusable: %1 -> %2: %3", tld, ptld, why)
          weight = 1.0
        else
          local dist = util.levenshtein_distance(tld, ptld, 2)
          dist = 2 * dist / (#tld + #ptld)

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
              rspamd_logger.debugm(N, task, "confusable: %1 -> %2: different characters",
                tld, ptld, why)
            else
              -- We have totally different strings in tld, so penalize it significantly
              if dist > 2 then dist = 2 end
              weight = util.tanh((2 - dist) * 0.5)
            end
          end

          rspamd_logger.debugm(N, task, "distance: %1 -> %2: %3", tld, ptld, dist)
        end

        local function found_in_map(map, furl, sweight)
          if not furl then furl = url end
          if not sweight then sweight = weight end
          if #map > 0 then
            for _,rule in ipairs(map) do
                for _,dn in ipairs({furl:get_tld(), furl:get_host()}) do
                  if rule['map']:get_key(dn) then
                    task:insert_result(rule['symbol'], sweight, ptld .. '->' .. dn)
                    return true
                  end
                end
            end
          end
        end

        if not found_in_map(redirector_domains) then
          if not found_in_map(strict_domains, purl, 1.0) then
            if domains then
              if domains:get_key(ptld) then
                task:insert_result(symbol, weight, ptld .. '->' .. tld)
              end
            else
              task:insert_result(symbol, weight, ptld .. '->' .. tld)
            end
          end
        end
      end
    end
  end
end

local function phishing_map(mapname, phishmap, id)
  if opts[mapname] then
    local xd = {}
    if type(opts[mapname]) == 'table' then
      xd = opts[mapname]
    else
      xd[1] = opts[mapname]
    end
    for _,d in ipairs(xd) do
      local s = string.find(d, ':[^:]+$')
      if s then
        local sym = string.sub(d, s + 1, -1)
        local map = string.sub(d, 1, s - 1)
        rspamd_config:register_virtual_symbol(sym, 1, id)
        local rmap = rspamd_config:add_map ({
          type = 'set',
          url = map,
          description = 'Phishing ' .. mapname .. ' map',
        })
        if rmap then
          local rule = {symbol = sym, map = rmap}
          table.insert(phishmap, rule)
        else
          rspamd_logger.infox(rspamd_config, 'cannot add map: ' .. map .. ' for symbol: ' .. sym)
        end
      else
        rspamd_logger.infox(rspamd_config, mapname .. ' option must be in format <map>:<symbol>')
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

local function openphish_plain_cb(string)
  local nelts = 0
  local new_data = {}
  local rspamd_mempool = require "rspamd_mempool"
  local pool = rspamd_mempool.create()

  local function openphish_elt_parser(cap)
    if insert_url_from_string(pool, new_data, cap, nil) then
      nelts = nelts + 1
    end
  end

  rspamd_str_split_fun(string, '\n', openphish_elt_parser)

  openphish_data = new_data
  rspamd_logger.infox(openphish_hash, "parsed %s elements from openphish feed",
    nelts)
  pool:destroy()
end

local function phishtank_json_cb(string)
  local ucl = require "ucl"
  local nelts = 0
  local new_data = {}
  local valid = true
  local parser = ucl.parser()
  local res,err = parser:parse_string(string)
  local rspamd_mempool = require "rspamd_mempool"
  local pool = rspamd_mempool.create()

  if not res then
    valid = false
    rspamd_logger.warnx(phishtank_hash, 'cannot parse openphish map: ' .. err)
  else
    local obj = parser:get_object()

    for _,elt in ipairs(obj) do
      if elt['url'] then
        if insert_url_from_string(pool, new_data, elt['url'],
          elt['phish_detail_url']) then
          nelts = nelts + 1
        end
      end
    end
  end

  if valid then
    phishtank_data = new_data
    rspamd_logger.infox(phishtank_hash, "parsed %s elements from phishtank feed",
      nelts)
  end


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
          description = 'Open phishing feed map (see https://www.openphish.com for details)'
        })
      else
        openphish_hash = rspamd_config:add_map({
            type = 'callback',
            url = openphish_map,
            callback = openphish_json_cb,
            description = 'Open phishing premium feed map (see https://www.openphish.com for details)'
          })
      end
    end

    if opts['phishtank_map'] then
      phishtank_map = opts['phishtank_map']
    end
    if opts['phishtank_url'] then
      phishtank_map = opts['phishtank_url']
    end

    if opts['phishtank_enabled'] then
      phishtank_hash = rspamd_config:add_map({
          type = 'callback',
          url = phishtank_map,
          callback = phishtank_json_cb,
          description = 'Phishtank feed (see https://www.phishtank.com for details)'
        })
    end

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
    domains = rspamd_config:add_map({
      url = opts['domains'],
      type = 'set',
      description = 'Phishing domains'
    })
  end
  phishing_map('strict_domains', strict_domains, id)
  phishing_map('redirector_domains', redirector_domains, id)
end
