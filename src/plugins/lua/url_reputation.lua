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

local N = 'url_reputation'

local redis_params, redis_set_script_sha
local settings = {
  expire = 86400, -- 1 day
  key_prefix = 'UR.',
}

local rspamd_logger = require "rspamd_logger"
local rspamd_util = require "rspamd_util"
local ucl = require "ucl"

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

local redis_set_script_head = 'local expiry = '
local redis_set_script_tail = [[
local now = math.floor(table.remove(ARGV))
local res = redis.call('MGET', unpack(KEYS))
for i = 1, #res do
  local tmp1, tmp2 = {}, {}
  if res[i] then
    for time, tag in string.gmatch(res[i], '(%d+)|([^,]+)') do
      if (time + expiry) > now then
        tmp1[tag] = time
      end
    end
  end
  for tag in string.gmatch(ARGV[i], '[^,]+') do
    tmp1[tag] = now
  end
  for k in pairs(tmp1) do
    table.insert(tmp2, tmp1[k] .. '|' .. k)
  end
  redis.call('SETEX', KEYS[i], expiry, table.concat(tmp2, ','))
end
]]

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

local function reputation_set(task)
  local function redis_set_cb(err)
    if err then
      rspamd_logger.errx(task, 'Redis error: %s', err)
      if string.match(err, 'NOSCRIPT') then
        load_scripts(rspamd_config, task:get_ev_base())
      end
    end
  end
  local tags = {}
  -- Figure out what tags are present for each URL
  for _, url in ipairs(task:get_urls(false)) do
    local utags = url:get_tags()
    if utags[1] then
      local dom = url:get_tld()
      if not tags[dom] then
        tags[dom] = {}
      end
      for _, ut in ipairs(utags) do
        tags[dom][ut] = true
      end
    end
  end
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
    table.insert(redis_keys, settings.key_prefix .. dom)
    local tmp = {}
    for k in pairs(v) do
      table.insert(tmp, k)
    end
    table.insert(redis_args, table.concat(tmp, ','))
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

local function reputation_check(task)
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
        for time, tag in string.gmatch(data[i], '(%d+)|([^,]+)') do
          if (time + settings.expire) > now then
            for _, idx in ipairs(tlds[tld]) do
              urls[idx]:add_tag(tag, mpool)
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
      table.insert(keys, settings.key_prefix .. x)
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
rspamd_config:add_on_load(function(cfg, ev_base, worker)
  if not (worker:get_name() == 'normal' and worker:get_index() == 0) then return end
  load_scripts(cfg, ev_base)
end)
rspamd_config:register_symbol({
  name = 'URL_REPUTATION_SAVE',
  type = 'postfilter',
  callback = reputation_set,
  priority = 10
})
rspamd_config:register_symbol({
  name = 'URL_REPUTATION_CHECK',
  type = 'prefilter',
  callback = reputation_check,
  priority = 5
})
