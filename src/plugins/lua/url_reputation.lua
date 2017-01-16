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

-- A plugin that restores/persists URL reputation (tags)

local E = {}
local N = 'url_reputation'

local redis_params, redis_set_script_sha
local category = {}
local settings = {
  expire = 86400, -- 1 day
  key_prefix_tags = 'Ut.',
  key_prefix_rep = 'Ur.',
  tags = {
    white = {
      'white',
    },
    black = {
      'surbl',
    },
    grey = {
    },
  },
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
local ucl = require "ucl"

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

-- Tags are stored in format: [timestamp]|[tag1],[timestamp]|[tag2]
local redis_set_script_head = 'local expiry = '
local redis_set_script_tail = [[
local now = math.floor(table.remove(ARGV))
local res = redis.call('MGET', unpack(KEYS))
for i = 1, #res do
  local tmp1, tmp2, metatags = {}, {}, {}
  if res[i] then
    for goo in string.gmatch(res[i], '[^/]+') do
      local time, tag, meta = string.match(goo, '(%d+)|([^|]+)|(.+)')
      if (time + expiry) > now then
        for m in string.gmatch(meta, '[^,]+') do
           metatags[m] = true
        end
        tmp1[tag] = {time, metatags}
      end
    end
  end
  local idx = string.find(ARGV[i], '|')
  if not idx then
    return redis.error_reply('bad arguments')
  end
  local t_str = string.sub(ARGV[i], 1, idx - 1)
  local m_str = string.sub(ARGV[i], idx + 1)
  local mm = string.gmatch(m_str, '[^,]+')
  for t in string.gmatch(t_str, '[^,]+') do
    if not tmp1[t] then
      tmp1[t] = {now, {}}
    else
      tmp1[t][1] = now
    end
    local mt_str = mm()
    for mt in string.gmatch(mt_str, '[^,]+') do
      tmp1[t][2][mt] = true
    end
  end
  for k, v in pairs(tmp1) do
    local meta_list = {}
    for kk in pairs(v[2]) do
      table.insert(meta_list, kk)
    end
    table.insert(tmp2, v[1] .. '|' .. k .. '|' .. table.concat(meta_list, ','))
  end
  redis.call('SETEX', KEYS[i], expiry, table.concat(tmp2, '/'))
end
]]

-- Function to load the script
local function load_scripts(cfg, ev_base)
  local function redis_set_script_cb(err, data)
    if err then
      rspamd_logger.errx(cfg, 'Script loading failed: ' .. err)
    else
      redis_set_script_sha = tostring(data)
    end
  end
  local set_script =
    redis_set_script_head ..
    settings.expire ..
    '\n' ..
    redis_set_script_tail
  redis_make_request(ev_base,
    rspamd_config,
    nil,
    true, -- is write
    redis_set_script_cb, --callback
    'SCRIPT', -- command
    {'LOAD', set_script}
  )
end

-- Saves tags and calculates URL reputation
local function tags_save(task)

  -- Handle errors (reloads script if necessary)
  local function redis_set_cb(err)
    if err then
      rspamd_logger.errx(task, 'Redis error: %s', err)
      if string.match(err, 'NOSCRIPT') then
        load_scripts(rspamd_config, task:get_ev_base())
      end
    end
  end

  local tags = {}
  local tlds = {}
  local tld_count = 0
  local reputation = 2
  local which

  -- Save tags to redis and insert symbol
  local function insert_results()
    task:insert_result(settings.symbols[scale[reputation]], 1.0, which)
    -- Abort if no tags were found
    if not next(tags) then return end
    -- Don't populate old tags
    local old_tags = task:get_mempool():get_variable('urltags')
    if old_tags then
      local parser = ucl.parser()
      local res, err = parser:parse_string(old_tags)
      if not res then
        rspamd_logger.errx(task, 'Parser error: %s', err)
        return
      end
      local obj = parser:get_object()
      for k, v in pairs(obj) do
        if tags[k] then
          for sk in pairs(v) do
            tags[k][sk] = nil
          end
          if not next(tags[k]) then
            tags[k] = nil
          end
        end
      end
    end
    -- Prepare arguments to send to Redis
    local redis_keys = {}
    local redis_args = {}
    for dom, v in pairs(tags) do
      table.insert(redis_keys, settings.key_prefix_tags .. dom)
      local tmp, tmp2 = {}, {}
      for k, vv in pairs(v) do
        table.insert(tmp, k)
        for kk in pairs(vv) do
          table.insert(tmp2, kk)
        end
      end
      table.insert(redis_args, table.concat(tmp, ',') .. '|' .. table.concat(tmp2, ','))
    end
    local redis_final = {redis_set_script_sha}
    table.insert(redis_final, #redis_keys)
    for _, k in ipairs(redis_keys) do
      table.insert(redis_final, k)
    end
    for _, a in ipairs(redis_args) do
      table.insert(redis_final, a)
    end
    table.insert(redis_final, rspamd_util.get_time())
    rspamd_redis_make_request(task,
      redis_params,
      nil,
      true, -- is write
      redis_set_cb, --callback
      'EVALSHA', -- command
      redis_final
    )
  end

  -- Dynamic reputation is used in absence of tags
  local function dynamic_reputation()

    local subset = {}
    local keys = {}

    -- Spit out log if INCR fails
    local function redis_incr_cb(err)
      if err then
        rspamd_logger.errx(task, 'couldnt increment reputation: %s', err)
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
            elseif highest_k == 'grey' and reputation ~= 4 then
              reputation = 3
              which = subset[x]
            elseif highest_k == 'white' and reputation == 2 then
              reputation = 1
              which = subset[x]
            elseif highest_k == 'neutral' and reputation <= 2 then
              reputation = 2
              which = subset[x]
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
          settings.key_prefix_rep .. which .. '_total',
          settings.key_prefix_rep .. which .. '_' .. scale[reputation],
        }
      else
        -- No reputation found, pick some URLs
        local most_relevant
        if settings.relevance then
          -- XXX: blacklist for non-relevant identifiers (gmail etc)
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
        end

        rk = {}
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
          table.insert(rk, settings.key_prefix_rep .. t .. '_total')
          table.insert(rk, settings.key_prefix_rep .. t .. '_' .. scale[reputation])
          added = added + 1
        end
      end
      for _, k in ipairs(rk) do
        local ret = rspamd_redis_make_request(task,
          redis_params,
          k,
          false, -- is write
          redis_incr_cb, --callback
          'INCR', -- command
          {k}
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
      added = added + 1
      table.insert(subset, k)
      table.insert(keys, settings.key_prefix_rep .. k .. '_total')
      table.insert(keys, settings.key_prefix_rep .. k .. '_white')
      table.insert(keys, settings.key_prefix_rep .. k .. '_black')
      table.insert(keys, settings.key_prefix_rep .. k .. '_grey')
      table.insert(keys, settings.key_prefix_rep .. k .. '_neutral')
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
  -- and calculate overall URL reputation
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
        local cat = category[ut]
        if cat == 'black' then
          reputation = 4
          which = dom
        elseif cat == 'grey' and reputation ~= 4 then
          reputation = 3
          which = dom
        elseif cat == 'white' and reputation == 2 then
          reputation = 1
          which = dom
        end
      end
    end
  end
  if reputation == 2 then
    if next(tlds) then
      dynamic_reputation()
    end
    return
  end
  insert_results()
end

local function tags_restore(task)
  local urls
  local tlds = {}
  local tld_reverse = {}
  local mpool = task:get_mempool()

  local function redis_get_cb(err, data)
    if err then
      rspamd_logger.errx(task, 'Redis error: %s', err)
      return
    end
    local d_len = #data
    if d_len == 0 then return end
    local now = rspamd_util.get_time()
    local tracking = {}
    for i = 1, d_len do
      if type(data[i]) == 'string' then
        local tld = tld_reverse[i]
        for time, tag, meta in string.gmatch(data[i], '(%d+)|([^|]+)|(.+)') do
          if (time + settings.expire) > now then
            local metatags = {}
            for m in string.gmatch(meta, '[^,]+') do
              table.insert(metatags, m)
            end
            for _, idx in ipairs(tlds[tld]) do
              for _, ttag in ipairs(metatags) do
                urls[idx]:add_tag(tag, ttag, mpool)
              end
            end
            if not tracking[tld] then
              tracking[tld] = {}
            end
            tracking[tld][tag] = true
          end
        end
      end
    end
    mpool:set_variable('urltags', ucl.to_format(tracking, 'ucl'))
  end

  urls = task:get_urls(false)
  for idx = 1, #urls do
    local tld = urls[idx]:get_tld()
    tld_reverse[idx] = tld
    if not tlds[tld] then
      tlds[tld] = {}
    end
    table.insert(tlds[tld], idx)
  end
  local first = next(tlds)
  if first then
    local keys = {}
    for x in pairs(tlds) do
      table.insert(keys, settings.key_prefix_tags .. x)
    end
    rspamd_redis_make_request(task,
      redis_params,
      first,
      false, -- is write
      redis_get_cb, --callback
      'MGET', -- command
      keys
    )
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
  settings[k] = v
end
for k, v in pairs(settings.tags) do
  for _, sv in ipairs(v) do
    category[sv] = k
  end
end
rspamd_config:add_on_load(function(cfg, ev_base, worker)
  if not (worker:get_name() == 'normal' and worker:get_index() == 0) then return end
  load_scripts(cfg, ev_base)
end)
local id = rspamd_config:register_symbol({
  name = 'URL_TAGS_SAVE',
  type = 'postfilter',
  callback = tags_save,
  priority = 10
})
rspamd_config:register_symbol({
  name = 'URL_TAGS_RESTORE',
  type = 'prefilter',
  callback = tags_restore,
  priority = 5
})
for _, v in pairs(settings.symbols) do
  rspamd_config:register_symbol({
    name = v,
    parent = id,
    type = 'virtual'
  })
end
