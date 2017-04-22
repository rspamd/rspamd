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

-- A plugin that restores/persists URL tags

local N = 'url_tags'

local redis_params, redis_set_script_sha
local settings = {
  -- lifetime for tags
  expire = 3600, -- 1 hour
  -- prefix for redis keys
  key_prefix = 'Ut.',
  -- tags in this list are not persisted
  ignore_tags = {},
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
local data = {}
for i = 1, #res do
  local which = KEYS[i]
  if type(res[i]) == 'string' then
    data[which] = {}
    for goo in string.gmatch(res[i], '[^/]+') do
      local metatags = {}
      local time, tag, meta = string.match(goo, '(%d+)|([^|]+)|(.+)')
      if (time + expiry) > now then
        for m in string.gmatch(meta, '[^,]+') do
           metatags[m] = true
        end
        data[which][tag] = {time, metatags}
      end
    end
  end
  for goo in string.gmatch(ARGV[i], '[^/]+') do
    local metatags = {}
    if not data[which] then
      data[which] = {}
    end
    local tag, meta = string.match(goo, '([^|]+)|(.+)')
    for m in string.gmatch(meta, '[^,]+') do
       metatags[m] = true
    end
    data[which][tag] = {now, metatags}
  end
  local tmp2 = {}
  for k, v in pairs(data[which]) do
    local meta_list = {}
    for kk in pairs(v[2]) do
      table.insert(meta_list, kk)
    end
    table.insert(tmp2, v[1] .. '|' .. k .. '|' .. table.concat(meta_list, ','))
  end
  redis.call('SETEX', which, expiry, table.concat(tmp2, '/'))
end
]]

-- Function to load the script
local function load_scripts(cfg, ev_base)
  local function redis_set_script_cb(err, data)
    if err then
      rspamd_logger.errx(cfg, 'Set script loading failed: ' .. err)
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

-- Saves tags to redis
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
  -- Figure out what tags are present for each TLD
  for _, url in ipairs(task:get_urls(false)) do
    local utags = url:get_tags()
    if next(utags) then
      local tld = url:get_tld()
      if not tags[tld] then
        tags[tld] = {}
      end
      for ut, utv in pairs(utags) do
        if not settings.ignore_tags[ut] then
          if not tags[tld][ut] then
            tags[tld][ut] = {}
          end
          for _, e in ipairs(utv) do
            tags[tld][ut][e] = true
          end
        end
      end
    end
  end
  if not next(tags) then
    return
  end

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
    for dom, domtags in pairs(obj) do
      if tags[dom] then
        for tag, mtags in pairs(domtags) do
          for mtag in pairs(mtags) do
            tags[dom][tag][mtag] = nil
          end
          if not next(tags[dom][tag]) then
            tags[dom][tag] = nil
          end
        end
        if not next(tags[dom]) then
          tags[dom] = nil
        end
      end
    end
  end

  -- Abort if no tags remaining
  if not next(tags) then
    return
  end

  -- Prepare arguments to send to Redis
  local redis_keys = {}
  local redis_args = {}
  local tmp3 = {}
  for dom, domtags in pairs(tags) do
    local tmp = {}
    for tag, mtags in pairs(domtags) do
      local tmp2 = {}
      for k in pairs(mtags) do
        table.insert(tmp2, tostring(rspamd_util.encode_base32(k)))
      end
      tmp[tag] = tmp2
    end
    tmp3[dom] = tmp
  end
  for dom, domtags in pairs(tmp3) do
    table.insert(redis_keys, settings.key_prefix .. dom)
    local tmp4 = {}
    for tag, mtags in pairs(domtags) do
      table.insert(tmp4, tag .. '|' .. table.concat(mtags, ','))
    end
    table.insert(redis_args, table.concat(tmp4, '/'))
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

  -- Send query to redis
  rspamd_redis_make_request(task,
    redis_params,
    nil,
    true, -- is write
    redis_set_cb, --callback
    'EVALSHA', -- command
    redis_final
  )
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
        for goo in string.gmatch(data[i], '[^/]+') do
          for time, tag, meta in string.gmatch(goo, '(%d+)|([^|]+)|(.+)') do
            if not settings.ignore_tags[tag] then
              if (time + settings.expire) > now then
                local metatags = {}
                for m in string.gmatch(meta, '[^,]+') do
                  table.insert(metatags, m)
                end
                for _, idx in ipairs(tlds[tld]) do
                  if not tracking[tld] then
                    tracking[tld] = {}
                  end
                  if not tracking[tld][tag] then
                    tracking[tld][tag] = {}
                  end
                  for _, ttag in ipairs(metatags) do
                    urls[idx]:add_tag(tag, tostring(rspamd_util.decode_base32(ttag)), mpool)
                    tracking[tld][tag][ttag] = true
                  end
                end
              end
            end
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
local function list_to_hash(list)
  if type(list) == 'table' then
    if list[1] then
      local h = {}
      for _, e in ipairs(list) do
        h[e] = true
      end
      return h
    else
      return list
    end
  elseif type(list) == 'string' then
    local h = {}
    h[list] = true
    return h
  else
    return {}
  end
end
settings.ignore_tags = list_to_hash(settings.ignore_tags)

rspamd_config:add_on_load(function(cfg, ev_base, worker)
  if not (worker:get_name() == 'normal' and worker:get_index() == 0) then return end
  load_scripts(cfg, ev_base)
end)
rspamd_config:register_symbol({
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
