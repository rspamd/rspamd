--[[
Copyright (c) 2016, Vsevolod Stakhov <vsevolod@highsecure.ru>
Copyright (c) 2016, Alexey Savelyev <info@homeweb.ru>

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

--[[
Example domains whitelist config:
greylist {
  # Search "example.com" and "mail.example.com" for "mx.out.mail.example.com":
  whitelist_domains_url = [
    "$LOCAL_CONFDIR/local.d/maps.d/greylist-whitelist-domains.inc",
    "${CONFDIR}/maps.d/maillist.inc",
    "${CONFDIR}/maps.d/redirectors.inc",
    "${CONFDIR}/maps.d/dmarc_whitelist.inc",
    "${CONFDIR}/maps.d/spf_dkim_whitelist.inc",
    "${CONFDIR}/maps.d/surbl-whitelist.inc",
    "https://maps.rspamd.com/freemail/free.txt.zst"
  ];
}
Example config for exim users:
greylist {
  action = "greylist";
}
--]]

if confighelp then
  rspamd_config:add_example(nil, 'greylist',
      "Performs adaptive greylisting using Redis",
      [[
greylist {
  expire = 1d; # Buckets expire (1 day by default)
  timeout = 5m; # Greylisting timeout
  key_prefix = 'rg'; # Redis prefix
  max_data_len = 10k; # Use boy hash up to this value of bytes for greylisting
  message = 'Try again later'; # Default greylisting message
  symbol = 'GREYLIST'; # Append symbol
  action = 'soft reject'; # Default action change (for Exim use `greylist`)
  whitelist_symbols = []; # Skip greylisting if one of the following symbols has been found
  ipv4_mask = 19; # Mask bits for ipv4
  ipv6_mask = 64; # Mask bits for ipv6
  report_time = false; # Tell when greylisting is expired (appended to `message`)
  check_local = false; # Greylist local messages
  check_authed = false; # Greylist authenticated users
}
  ]])
  return
end

-- A plugin that implements greylisting using redis

local redis_params
local whitelisted_ip
local whitelist_domains_map
local toint = math.ifloor or math.floor
local settings = {
  expire = 86400, -- 1 day by default
  timeout = 300, -- 5 minutes by default
  key_prefix = 'rg', -- default hash name
  max_data_len = 10240, -- default data limit to hash
  message = 'Try again later', -- default greylisted message
  symbol = 'GREYLIST',
  action = 'soft reject', -- default greylisted action
  whitelist_symbols = {}, -- whitelist when specific symbols have been found
  ipv4_mask = 19, -- Mask bits for ipv4
  ipv6_mask = 64, -- Mask bits for ipv6
  report_time = false, -- Tell when greylisting is epired (appended to `message`)
  check_local = false,
  check_authed = false,
}

local rspamd_logger = require "rspamd_logger"
local rspamd_util = require "rspamd_util"
local lua_redis = require "lua_redis"
local lua_util = require "lua_util"
local fun = require "fun"
local hash = require "rspamd_cryptobox_hash"
local rspamd_lua_utils = require "lua_util"
local lua_map = require "lua_maps"
local N = "greylist"

local function data_key(task)
  local cached = task:get_mempool():get_variable("grey_bodyhash")
  if cached then
    return cached
  end

  local body = task:get_rawbody()

  if not body then return nil end

  local len = body:len()
  if len > settings['max_data_len'] then
    len = settings['max_data_len']
  end

  local h = hash.create()
  h:update(body, len)

  local b32 = settings['key_prefix'] .. 'b' .. h:base32():sub(1, 20)
  task:get_mempool():set_variable("grey_bodyhash", b32)
  return b32
end

local function envelope_key(task)
  local cached = task:get_mempool():get_variable("grey_metahash")
  if cached then
    return cached
  end

  local from = task:get_from('smtp')
  local h = hash.create()

  local addr = '<>'
  if from and from[1] then
    addr = from[1]['addr']
  end

  h:update(addr)
  local rcpt = task:get_recipients('smtp')
  if rcpt then
    table.sort(rcpt, function(r1, r2)
      return r1['addr'] < r2['addr']
    end)

    fun.each(function(r)
      h:update(r['addr'])
    end, rcpt)
  end

  local ip = task:get_ip()

  if ip and ip:is_valid() then
    local s
    if ip:get_version() == 4 then
      s = tostring(ip:apply_mask(settings['ipv4_mask']))
    else
      s = tostring(ip:apply_mask(settings['ipv6_mask']))
    end
    h:update(s)
  end

  local b32 = settings['key_prefix'] .. 'm' .. h:base32():sub(1, 20)
  task:get_mempool():set_variable("grey_metahash", b32)
  return b32
end

-- Returns pair of booleans: found,greylisted
local function check_time(task, tm, type, now)
  local t = tonumber(tm)

  if not t then
    rspamd_logger.errx(task, 'not a valid number: %s', tm)
    return false,false
  end

  if now - t < settings['timeout'] then
    return true,true
  else
    -- We just set variable to pass when in post-filter stage
    task:get_mempool():set_variable("grey_whitelisted", type)

    return true,false
  end
end

local function greylist_message(task, end_time, why)
  task:insert_result(settings['symbol'], 0.0, 'greylisted', end_time, why)

  if not settings.check_local and rspamd_lua_utils.is_rspamc_or_controller(task) then
    return
  end

  if settings.message_func then
    task:set_pre_result(settings['action'],
      settings.message_func(task, end_time), N)
  else
    local message = settings['message']
    if settings.report_time then
      message = string.format("%s: %s", message, end_time)
    end
    task:set_pre_result(settings['action'], message, N)
  end

  task:set_flag('greylisted')
end

local function greylist_check(task)
  local ip = task:get_ip()

  if ((not settings.check_authed and task:get_user()) or
      (not settings.check_local and ip and ip:is_local())) then
    rspamd_logger.infox(task, "skip greylisting for local networks and/or authorized users");
    return
  end

  if ip and ip:is_valid() and whitelisted_ip then
    if whitelisted_ip:get_key(ip) then
      -- Do not check whitelisted ip
      rspamd_logger.infox(task, 'skip greylisting for whitelisted IP')
      return
    end
  end

  local body_key = data_key(task)
  local meta_key = envelope_key(task)
  local hash_key = body_key .. meta_key

  local function redis_get_cb(err, data)
    local ret_body = false
    local greylisted_body = false
    local ret_meta = false
    local greylisted_meta = false

    if data then
      local end_time_body,end_time_meta
      local now = rspamd_util.get_time()

      if data[1] and type(data[1]) ~= 'userdata' then
        local tm = tonumber(data[1]) or now
        ret_body,greylisted_body = check_time(task, data[1], 'body', now)
        if greylisted_body then
          end_time_body = tm + settings['timeout']
          task:get_mempool():set_variable("grey_greylisted_body",
              rspamd_util.time_to_string(end_time_body))
        end
      end

      if data[2] and type(data[2]) ~= 'userdata' then
        if not ret_body or greylisted_body then
          local tm = tonumber(data[2]) or now
          ret_meta,greylisted_meta = check_time(task, data[2], 'meta', now)

          if greylisted_meta then
            end_time_meta = tm + settings['timeout']
            task:get_mempool():set_variable("grey_greylisted_meta",
                rspamd_util.time_to_string(end_time_meta))
          end
        end
      end

      local how
      local end_time_str

      if not ret_body and not ret_meta then
        -- no record found
        task:get_mempool():set_variable("grey_greylisted", 'true')
      elseif greylisted_body and greylisted_meta then
        end_time_str = rspamd_util.time_to_string(
            math.min(end_time_body, end_time_meta))
        how = 'meta and body'
      elseif greylisted_body then
        end_time_str = rspamd_util.time_to_string(end_time_body)
        how = 'body only'
      elseif greylisted_meta then
        end_time_str = rspamd_util.time_to_string(end_time_meta)
        how = 'meta only'
      end

      if how and end_time_str then
        rspamd_logger.infox(task, 'greylisted until "%s" (%s)',
            end_time_str, how)
        greylist_message(task, end_time_str, 'too early')
      end
    elseif err then
      rspamd_logger.errx(task, 'got error while getting greylisting keys: %1', err)
      return
    end
  end

  local ret = lua_redis.redis_make_request(task,
      redis_params, -- connect params
      hash_key, -- hash key
      false, -- is write
      redis_get_cb, --callback
      'MGET', -- command
      {body_key, meta_key} -- arguments
  )
  if not ret then
    rspamd_logger.errx(task, 'cannot make redis request to check results')
  end
end

local function greylist_set(task)
  local action = task:get_metric_action('default')
  local ip = task:get_ip()

  -- Don't do anything if pre-result has been already set
  if task:has_pre_result() then return end

  -- Check whitelist_symbols
  for _,sym in ipairs(settings.whitelist_symbols) do
    if task:has_symbol(sym) then
      rspamd_logger.infox(task, 'skip greylisting as we have found symbol %s', sym)
      if action == 'greylist' then
        -- We are going to accept message
        rspamd_logger.infox(task, 'downgrading metric action from "greylist" to "no action"')
        task:disable_action('greylist')
      end
      return
    end
  end

  if settings.greylist_min_score then
    local score = task:get_metric_score('default')[1]
    if score < settings.greylist_min_score then
      rspamd_logger.infox(task, 'Score too low - skip greylisting')
      if action == 'greylist' then
        -- We are going to accept message
        rspamd_logger.infox(task, 'Downgrading metric action from "greylist" to "no action"')
        task:disable_action('greylist')
      end
      return
    end
  end

  if ((not settings.check_authed and task:get_user()) or
      (not settings.check_local and ip and ip:is_local())) then
    if action == 'greylist' then
      -- We are going to accept message
      rspamd_logger.infox(task, 'Downgrading metric action from "greylist" to "no action"')
      task:disable_action('greylist')
    end
    return
  end

  if ip and ip:is_valid() and whitelisted_ip then
    if whitelisted_ip:get_key(ip) then
      if action == 'greylist' then
        -- We are going to accept message
        rspamd_logger.infox(task, 'Downgrading metric action from "greylist" to "no action"')
        task:disable_action('greylist')
      end
      return
    end
  end

  local is_whitelisted = task:get_mempool():get_variable("grey_whitelisted")
  local do_greylisting = task:get_mempool():get_variable("grey_greylisted")
  local do_greylisting_required = task:get_mempool():get_variable("grey_greylisted_required")

  -- Third and second level domains whitelist
  if not is_whitelisted and whitelist_domains_map then
    local hostname = task:get_hostname()
    if hostname then
      local domain = rspamd_util.get_tld(hostname)
      if whitelist_domains_map:get_key(hostname) or (domain and whitelist_domains_map:get_key(domain)) then
        is_whitelisted = 'meta'
        rspamd_logger.infox(task, 'skip greylisting for whitelisted domain')
      end
    end
  end

  if action == 'reject' or
      not do_greylisting_required and action == 'no action' then
    return
  end
  local body_key = data_key(task)
  local meta_key = envelope_key(task)
  local upstream, ret, conn
  local hash_key = body_key .. meta_key

  local function redis_set_cb(err)
    if err then
      rspamd_logger.errx(task, 'got error %s when setting greylisting record on server %s',
        err, upstream:get_addr())
    end
  end

  local is_rspamc = rspamd_lua_utils.is_rspamc_or_controller(task)

  if is_whitelisted then
    if action == 'greylist' then
      -- We are going to accept message
      rspamd_logger.infox(task, 'Downgrading metric action from "greylist" to "no action"')
      task:disable_action('greylist')
    end

    task:insert_result(settings['symbol'], 0.0, 'pass', is_whitelisted)
    rspamd_logger.infox(task, 'greylisting pass (%s) until %s',
      is_whitelisted,
      rspamd_util.time_to_string(rspamd_util.get_time() + settings['expire']))

    if not settings.check_local and is_rspamc then return end

    ret,conn,upstream = lua_redis.redis_make_request(task,
      redis_params, -- connect params
      hash_key, -- hash key
      true, -- is write
      redis_set_cb, --callback
      'EXPIRE', -- command
      {body_key, tostring(toint(settings['expire']))} -- arguments
    )
    -- Update greylisting record expire
    if ret then
      conn:add_cmd('EXPIRE', {
        meta_key, tostring(toint(settings['expire']))
      })
    else
      rspamd_logger.errx(task, 'got error while connecting to redis')
    end
  elseif do_greylisting or do_greylisting_required then
    if not settings.check_local and is_rspamc then return end
    local t = tostring(toint(rspamd_util.get_time()))
    local end_time = rspamd_util.time_to_string(t + settings['timeout'])
    rspamd_logger.infox(task, 'greylisted until "%s", new record', end_time)
    greylist_message(task, end_time, 'new record')
    -- Create new record
    ret,conn,upstream = lua_redis.redis_make_request(task,
      redis_params, -- connect params
      hash_key, -- hash key
      true, -- is write
      redis_set_cb, --callback
      'SETEX', -- command
      {body_key, tostring(toint(settings['expire'])), t} -- arguments
    )

    if ret then
      conn:add_cmd('SETEX', {
        meta_key, tostring(toint(settings['expire'])), t
      })
    else
      rspamd_logger.errx(task, 'got error while connecting to redis')
    end
  else
    if action ~= 'no action' and action ~= 'reject' then
      local grey_res = task:get_mempool():get_variable("grey_greylisted_body")

      if grey_res then
        -- We need to delay message, hence set a temporary result
        rspamd_logger.infox(task, 'greylisting delayed until "%s": body', grey_res)
        greylist_message(task, grey_res, 'body')
      else
        grey_res = task:get_mempool():get_variable("grey_greylisted_meta")
        if grey_res then
          greylist_message(task, grey_res, 'meta')
        end
      end
    else
      task:insert_result(settings['symbol'], 0.0, 'greylisted', 'passed')
    end
  end
end

local opts = rspamd_config:get_all_opt('greylist')
if opts then
  if opts['message_func'] then
    settings.message_func = assert(load(opts['message_func']))()
  end

  for k,v in pairs(opts) do
    if k ~= 'message_func' then
      settings[k] = v
    end
  end

  local auth_and_local_conf = lua_util.config_check_local_or_authed(rspamd_config, N,
      false, false)
  settings.check_local = auth_and_local_conf[1]
  settings.check_authed = auth_and_local_conf[2]

  if settings['greylist_min_score'] then
    settings['greylist_min_score'] = tonumber(settings['greylist_min_score'])
  else
    local greylist_threshold = rspamd_config:get_metric_action('greylist')
    if greylist_threshold then
      settings['greylist_min_score'] = greylist_threshold
    end
  end

  whitelisted_ip = lua_map.rspamd_map_add(N, 'whitelisted_ip', 'radix',
    'Greylist whitelist ip map')
  whitelist_domains_map = lua_map.rspamd_map_add(N, 'whitelist_domains_url',
    'map', 'Greylist whitelist domains map')

  redis_params = lua_redis.parse_redis_server(N)
  if not redis_params then
    rspamd_logger.infox(rspamd_config, 'no servers are specified, disabling module')
    rspamd_lua_utils.disable_module(N, "redis")
  else
    lua_redis.register_prefix(settings.key_prefix .. 'b[a-z0-9]{20}', N,
        'Greylisting elements (body hashes)"', {
          type = 'string',
        })
    lua_redis.register_prefix(settings.key_prefix .. 'm[a-z0-9]{20}', N,
        'Greylisting elements (meta hashes)"', {
          type = 'string',
        })
    rspamd_config:register_symbol({
      name = 'GREYLIST_SAVE',
      type = 'postfilter',
      callback = greylist_set,
      priority = 6,
    })
    local id = rspamd_config:register_symbol({
      name = 'GREYLIST_CHECK',
      type = 'prefilter',
      callback = greylist_check,
      priority = 6,
    })
    rspamd_config:register_symbol({
      name = settings.symbol,
      type = 'virtual',
      parent = id,
      score = 0,
    })
  end
end
