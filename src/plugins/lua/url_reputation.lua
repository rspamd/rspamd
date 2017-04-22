--[[
Copyright (c) 2016-2017, Vsevolod Stakhov <vsevolod@highsecure.ru>
Copyright (c) 2017, Andrew Lewis <nerf@judo.za.org>

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

-- A plugin that restores/persists URL tags & calculates reputation

local E = {}
local N = 'url_reputation'

local whitelist, redis_params, redis_incr_script_sha
local settings = {
  expire = 86400, -- 1 day
  key_prefix = 'Ur.',
  symbols = {
    white = 'URL_REPUTATION_WHITE',
    black = 'URL_REPUTATION_BLACK',
    grey = 'URL_REPUTATION_GREY',
    neutral = 'URL_REPUTATION_NEUTRAL',
  },
  foreign_symbols = {
    dmarc = 'DMARC_POLICY_ALLOW',
    dkim = 'R_DKIM_ALLOW',
    spf = 'R_SPF_ALLOW',
  },
  ignore_surbl = {
    URIBL_BLOCKED = true,
    DBL_PROHIBIT = true,
    SURBL_BLOCKED = true,
  },
  -- how many messages to score reputation
  threshold = 5,
  -- set reputation for only so many TLDs
  update_limit = 1,
  -- query dynamic reputation for up to so many TLDs
  query_limit = 100,
  -- try find most relevant URL
  relevance = true,
}

local scale = {
  'white', -- 1
  'neutral', -- 2
  'grey', -- 3
  'black', -- 4
}

local rspamd_logger = require "rspamd_logger"
local rspamd_util = require "rspamd_util"

-- This function is used for taskless redis requests (to load scripts)
local function redis_make_request(ev_base, cfg, key, is_write, callback, command, args)
  if not ev_base or not redis_params or not callback or not command then
    return false,nil,nil
  end

  local addr
  local rspamd_redis = require "rspamd_redis"

  if key then
    if is_write then
      addr = redis_params['write_servers']:get_upstream_by_hash(key)
    else
      addr = redis_params['read_servers']:get_upstream_by_hash(key)
    end
  else
    if is_write then
      addr = redis_params['write_servers']:get_upstream_master_slave(key)
    else
      addr = redis_params['read_servers']:get_upstream_round_robin(key)
    end
  end

  if not addr then
    rspamd_logger.errx(cfg, 'cannot select server to make redis request')
  end

  local options = {
    ev_base = ev_base,
    config = cfg,
    callback = callback,
    host = addr:get_addr(),
    timeout = redis_params['timeout'],
    cmd = command,
    args = args
  }

  if redis_params['password'] then
    options['password'] = redis_params['password']
  end

  if redis_params['db'] then
    options['dbname'] = redis_params['db']
  end

  local ret,conn = rspamd_redis.make_request(options)
  if not ret then
    rspamd_logger.errx('cannot execute redis request')
  end
  return ret,conn,addr
end

local redis_incr_script = [[
for _, k in ipairs(KEYS) do
  redis.call('INCR', k)
end
]]

-- Function to load the script
local function load_scripts(cfg, ev_base)
  local function redis_incr_script_cb(err, data)
    if err then
      rspamd_logger.errx(cfg, 'Increment script loading failed: ' .. err)
    else
      redis_incr_script_sha = tostring(data)
    end
  end
  redis_make_request(ev_base,
    rspamd_config,
    nil,
    true, -- is write
    redis_incr_script_cb, --callback
    'SCRIPT', -- command
    {'LOAD', redis_incr_script}
  )
end

-- Calculates URL reputation
local function url_reputation_check(task)

  local tags = {}
  local tlds = {}
  local tld_count = 0
  local reputation = 2
  local which
  local confidence

  -- Insert symbol
  local function insert_results()
    if which and confidence then
      task:insert_result(settings.symbols[scale[reputation]], confidence, which)
    end
  end

  -- Calculate reputation
  local function dynamic_reputation()

    local subset = {}
    local keys = {}

    -- Spit out log if INCR fails
    local function redis_incr_cb(err)
      if err then
        rspamd_logger.errx(task, 'couldnt increment reputation: %s', err)
        if string.match(err, 'NOSCRIPT') then
          load_scripts(rspamd_config, task:get_ev_base())
        end
      end
    end

    local function rep_get_cb(err, data)
      -- Abort if we couldn't query redis for reputation info
      if err then
        rspamd_logger.errx(task, 'couldnt get dynamic reputation: %s', err)
        return
      end

      -- Try find worst reputation domain and set reputation accordingly
      local i, x, highest = 1, 1, 0
      while(data[i]) do
        if type(data[i]) == 'string' then
          local scores = {}
          scores.total = tonumber(data[i])
          if scores.total >= settings.threshold then
            local highest_k
            scores.white = tonumber(data[i+1])
            scores.black = tonumber(data[i+2])
            scores.grey = tonumber(data[i+3])
            scores.neutral = tonumber(data[i+4])
            for k, v in pairs(scores) do
              if (v > highest) then
                highest_k = k
                highest = v
              end
            end
            if highest_k == 'black' then
              reputation = 4
              which = subset[x]
              confidence = scores.black / scores.total
            elseif highest_k == 'grey' and reputation ~= 4 then
              reputation = 3
              which = subset[x]
              confidence = scores.grey / scores.total
            elseif highest_k == 'white' and reputation == 2 then
              reputation = 1
              which = subset[x]
              confidence = scores.white / scores.total
            elseif highest_k == 'neutral' and reputation <= 2 then
              reputation = 2
              which = subset[x]
              confidence = scores.neutral / scores.total
            end
          end
        end
        i = i + 5
        x = x + 1
      end
      local rk
      if which then
        -- Update reputation for guilty domain only
        rk = {
          redis_incr_script_sha,
          2,
          settings.key_prefix .. which .. '_total',
          settings.key_prefix .. which .. '_' .. scale[reputation],
        }
      else
        -- No reputation found, pick some URLs
        local most_relevant
        if tld_count == 1 then
          most_relevant = next(tlds)
        end
        if settings.relevance then
          if not most_relevant then
            local dmarc = ((task:get_symbol(settings.foreign_symbols['dmarc']) or E)[1] or E).options
            local dkim = ((task:get_symbol(settings.foreign_symbols['dkim']) or E)[1] or E).options
            local spf = task:get_symbol(settings.foreign_symbols['spf'])
            local hostname = task:get_hostname()
            if hostname then
              hostname = rspamd_util.get_tld(hostname)
            end
            if spf then
              local from = task:get_from(1)
              if ((from or E)[1] or E).domain then
                spf = rspamd_util.get_tld(from[1]['domain'])
              else
                local helo = task:get_helo()
                if helo then
                  spf = rspamd_util.get_tld(helo)
                end
              end
            end
            for _, t in ipairs(tlds) do
              if t == dmarc then
                most_relevant = t
                break
              elseif t == dkim then
                most_relevant = t
                break
              elseif t == spf then
                most_relevant = t
                break
              elseif t == hostname then
                most_relevant = t
                break
              end
            end
            if not most_relevant and reputation >= 3 then
              -- no authenticated domain, count surbl tags
              local max_surbl_guilt
              for dom, tag in pairs(tags) do
                local guilt = 0
                local stags = tag['surbl']
                if stags then
                  for k in pairs(stags) do
                    if not settings.ignore_surbl[k] then
                      guilt = guilt + 1
                    end
                  end
                  if guilt > 1 then
                    if not most_relevant then
                      most_relevant = dom
                      max_surbl_guilt = guilt
                    elseif guilt > max_surbl_guilt then
                      most_relevant = dom
                      max_surbl_guilt = guilt
                    end
                  end
                end
              end
            end
          end
        end

        rk = {redis_incr_script_sha, 0}
        local added = 0
        if most_relevant then
          tlds = {most_relevant}
          which = most_relevant
        end
        for t in pairs(tlds) do
          if settings.update_limit and added > settings.update_limit then
            rspamd_logger.warnx(task, 'Not updating reputation on all TLDs')
            break
          end
          table.insert(rk, settings.key_prefix .. t .. '_total')
          table.insert(rk, settings.key_prefix .. t .. '_' .. scale[reputation])
          added = added + 1
        end
      end
      if rk[3] then
        rk[2] = (#rk - 2)
        local ret = rspamd_redis_make_request(task,
          redis_params,
          rk[3],
          true, -- is write
          redis_incr_cb, --callback
          'EVALSHA', -- command
          rk
        )
        if not ret then
          rspamd_logger.errx(task, 'couldnt schedule increment')
        end
      end
      insert_results()
    end

    local action = task:get_metric_action('default')
    if action == 'reject' then
      reputation = 4
    elseif action == 'add header' then
      reputation = 3
    elseif action == 'no action' or action == 'greylist' then
      local score = task:get_metric_score('default')[1]
      if score < 0 then
        reputation = 1
      end
    end

    local added = 0
    for k in pairs(tlds) do
      if settings.query_limit and added >= settings.query_limit then
        rspamd_logger.warnx(task, 'not querying reputation for all TLDs')
        break
      end
      if (not whitelist) or (not whitelist:get_key(k)) then
        added = added + 1
        table.insert(subset, k)
        table.insert(keys, settings.key_prefix .. k .. '_total')
        table.insert(keys, settings.key_prefix .. k .. '_white')
        table.insert(keys, settings.key_prefix .. k .. '_black')
        table.insert(keys, settings.key_prefix .. k .. '_grey')
        table.insert(keys, settings.key_prefix .. k .. '_neutral')
      end
    end

    local key = keys[1]
    if key then
      rspamd_redis_make_request(task,
        redis_params,
        key,
        false, -- is write
        rep_get_cb, --callback
        'MGET', -- command
        keys
      )
    end
  end

  -- Figure out what tags are present for each URL
  for _, url in ipairs(task:get_urls(false)) do
    local tld = url:get_tld()
    if not tlds[tld] then
      tlds[tld] = true
      tld_count = tld_count + 1
    end
    local utags = url:get_tags()
    if next(utags) then
      local dom = url:get_tld()
      if not tags[dom] then
        tags[dom] = {}
      end
      for ut, utv in pairs(utags) do
        if tags[dom][ut] then
          for _, e in ipairs(utv) do
            table.insert(tags[dom][ut], e)
          end
        else
          tags[dom][ut] = utv
        end
      end
    end
  end
  if next(tlds) then
    dynamic_reputation()
  end
end

local opts = rspamd_config:get_all_opt(N)
if not opts then return end
redis_params = rspamd_parse_redis_server(N)
if not redis_params then
  rspamd_logger.warnx(rspamd_config, 'no servers are specified, disabling module')
  return
end
for k, v in pairs(opts) do
  if k == 'ignore_surbl' then
    if type(v) == 'table' then
      if next(v) ~= 1 then
        settings[k] = v
      else
        settings[k] = {}
        for _, n in ipairs(v) do
          settings[k][n] = true
        end
      end
    end
  else
    settings[k] = v
  end
end
if settings.threshold < 1 then
  rspamd_logger.errx(rspamd_config, 'threshold should be >= 1, disabling module')
  return
end

whitelist = rspamd_map_add(N, 'whitelist', 'map', 'URL reputation whitelist')
rspamd_config:add_on_load(function(cfg, ev_base, worker)
  if not (worker:get_name() == 'normal' and worker:get_index() == 0) then return end
  load_scripts(cfg, ev_base)
end)
local id = rspamd_config:register_symbol({
  name = 'URL_REPUTATION_CHECK',
  type = 'postfilter',
  callback = url_reputation_check,
  priority = 10
})
for _, v in pairs(settings.symbols) do
  rspamd_config:register_symbol({
    name = v,
    parent = id,
    type = 'virtual'
  })
end
