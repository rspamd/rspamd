--[[
Copyright (c) 2016, Vsevolod Stakhov <vsevolod@highsecure.ru>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
]] --

local rspamd_logger = require "rspamd_logger"
local rspamd_util = require "rspamd_util"
local rspamd_redis = require "rspamd_redis"
local rspamd_regexp = require "rspamd_regexp"
local tcp = require "rspamd_tcp"
local upstream_list = require "rspamd_upstream_list"
local redis_params

local function match_patterns(default_sym, found, patterns)
  if not patterns then return default_sym end
  for sym, pat in pairs(patterns) do
    if pat:match(found) then
      return sym
    end
  end
  return default_sym
end

local function yield_result(task, rule, vname)
  local symname = match_patterns(rule['symbol'], vname, rule['patterns'])
  if rule['whitelist'] and rule['whitelist']:get_key(vname) then
    rspamd_logger.infox(task, '%s: "%s" is in whitelist', rule['type'], vname)
    return
  end
  task:insert_result(symname, 1.0, vname)
  rspamd_logger.infox(task, '%s: virus found: "%s"', rule['type'], vname)
end

local function clamav_config(opts)
  local clamav_conf = {
    attachments_only = true,
    default_port = 3310,
    timeout = 15.0,
    retransmits = 2,
    cache_expire = 3600, -- expire redis in one hour
  }

  for k,v in pairs(opts) do
    clamav_conf[k] = v
  end

  if redis_params and not redis_params['prefix'] then
    if clamav_conf.prefix then
        redis_params['prefix'] = clamav_conf.prefix
    else
      redis_params['prefix'] = 'rs_cl'
    end
  end

  if not clamav_conf['servers'] then
    rspamd_logger.errx(rspamd_config, 'no servers defined')

    return nil
  end

  clamav_conf['upstreams'] = upstream_list.create(rspamd_config,
    clamav_conf['servers'],
    clamav_conf.default_port)

  if clamav_conf['upstreams'] then
    return clamav_conf
  end

  rspamd_logger.errx(rspamd_config, 'cannot parse servers %s',
    clamav_conf['servers'])
  return nil
end

local function need_av_check(task, rule)
  if rule['attachments_only'] then
    for _,p in ipairs(task:get_parts()) do
      if p:get_filename() and not p:is_image() then
        return true
      end
    end

    return false
  else
    return true
  end
end

local function check_av_cache(task, rule, fn)
  local function redis_av_cb(task, err, data)
    if data and type(data) == 'string' then
      -- Cached
      if data ~= 'OK' then
        yield_result(task, rule, data)
      end
    else
      fn()
    end
  end

  if redis_params then
    local key = task:get_digest()
    if redis_params['prefix'] then
      key = redis_params['prefix'] .. key
    end

    if rspamd_redis_make_request(task,
      redis_params, -- connect params
      key, -- hash key
      false, -- is write
      redis_av_cb, --callback
      'GET', -- command
      {key} -- arguments)
    ) then
      return true
    end
  end

  return false
end

local function save_av_cache(task, rule, to_save)
  local key = task:get_digest()

  local function redis_set_cb(task, err, data)
    -- Do nothing
    if err then
      rspamd_logger.errx(task, 'failed to save virus cache for %s -> "%s": %s',
        to_save, key, err)
    end
  end

  if redis_params then
    if redis_params['prefix'] then
      key = redis_params['prefix'] .. key
    end

    rspamd_redis_make_request(task,
      redis_params, -- connect params
      key, -- hash key
      true, -- is write
      redis_set_cb, --callback
      'SETEX', -- command
      { key, rule['cache_expire'], to_save }
    )
  end

  return false
end


local function clamav_check(task, rule)
  local function clamav_check_uncached ()
    local upstream = rule.upstreams:get_upstream_round_robin()
    local addr = upstream:get_addr()
    local retransmits = rule.retransmits
    local header = rspamd_util.pack("c9 c1 >I4", "zINSTREAM", "\0",
      task:get_size())
    local footer = rspamd_util.pack(">I4", 0)

    local function clamav_callback(err, data)
      if err then
        if err == 'IO timeout' then
          if retransmits > 0 then
            retransmits = retransmits - 1
            tcp.request({
              task = task,
              host = addr:to_string(),
              port = addr:get_port(),
              timeout = rule['timeout'],
              callback = clamav_callback,
              data = { header, task:get_content(), footer },
              stop_pattern = '\0'
            })
          else
            rspamd_logger.errx(task, 'failed to scan, maximum retransmits exceed')
          end
        else
          rspamd_logger.errx(task, 'failed to scan: %s', err)
          upstream:fail()
        end
      else
        upstream:ok()

        data = tostring(data)
        local s,_ = string.find(data, ' FOUND')
        local cached = 'OK'
        if s then
          local vname = string.match(data:sub(1, s - 1), 'stream: (.+)')
          yield_result(task, rule, vname)
          cached = vname
        end

        save_av_cache(task, rule, cached)
      end
    end

    tcp.request({
      task = task,
      host = addr:to_string(),
      port = addr:get_port(),
      timeout = rule['timeout'],
      callback = clamav_callback,
      data = { header, task:get_content(), footer },
      stop_pattern = '\0'
    })
  end

  if need_av_check(task, rule) then
    if check_av_cache(task, rule, clamav_check_uncached) then
      return
    else
      clamav_check_uncached()
    end
  end
end

local av_types = {
  clamav = {
    configure = clamav_config,
    check = clamav_check
  }
}

local function add_antivirus_rule(sym, opts)
  local rule = {}
  if not opts['type'] then
    return nil
  end

  if not opts['symbol'] then opts['symbol'] = sym end
  local cfg = av_types[opts['type']]

  if not cfg then
    rspamd_logger.errx(rspamd_config, 'unknown antivirus type: %s',
      opts['type'])
  end

  rule = cfg.configure(opts)

  if not rule then
    rspamd_logger.errx(rspamd_config, 'cannot configure %s for %s',
      opts['type'], opts['symbol'])
    return nil
  end

  if opts['patterns'] then
    rule['patterns'] = {}
    for k, v in pairs(opts['patterns']) do
      rule['patterns'][k] = rspamd_regexp.create_cached(v)
    end
  end

  if opts['whitelist'] then
    rule['whitelist'] = rspamd_config:add_hash_map(opts['whitelist'])
  end

  return function(task)
    return cfg.check(task, rule)
  end
end

-- Registration
local opts = rspamd_config:get_all_opt('antivirus')
if opts and type(opts) == 'table' then
  redis_params = rspamd_parse_redis_server('antivirus')
  for k, m in pairs(opts) do
    if type(m) == 'table' and m['type'] then
      local cb = add_antivirus_rule(k, m)
      if not cb then
        rspamd_logger.errx(rspamd_config, 'cannot add rule: "' .. k .. '"')
      else
        local id = rspamd_config:register_symbol({
          type = 'normal',
          name = m['symbol'],
          callback = cb,
        })
        if m['score'] then
          -- Register metric symbol
          local description = 'antivirus symbol'
          local group = 'antivirus'
          if m['description'] then
            description = m['description']
          end
          if m['group'] then
            group = m['group']
          end
          rspamd_config:set_metric_symbol({
            name = m['symbol'],
            score = m['score'],
            description = description,
            group = group
          })
        end
      end
    end
  end
end
