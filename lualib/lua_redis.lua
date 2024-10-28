--[[
Copyright (c) 2022, Vsevolod Stakhov <vsevolod@rspamd.com>

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

local logger = require "rspamd_logger"
local lutil = require "lua_util"
local rspamd_util = require "rspamd_util"
local ts = require("tableshape").types

local exports = {}

local E = {}
local N = "lua_redis"

local db_schema = (ts.number / tostring + ts.string):is_optional():describe("Database number")
local common_schema = {
  timeout = (ts.number + ts.string / lutil.parse_time_interval):is_optional():describe("Connection timeout"),
  db = db_schema,
  database = db_schema,
  dbname = db_schema,
  prefix = ts.string:is_optional():describe("Key prefix"),
  username = ts.string:is_optional():describe("Username"),
  password = ts.string:is_optional():describe("Password"),
  expand_keys = ts.boolean:is_optional():describe("Expand keys"),
  sentinels = (ts.string + ts.array_of(ts.string)):is_optional():describe("Sentinel servers"),
  sentinel_watch_time = (ts.number + ts.string / lutil.parse_time_interval):is_optional():describe("Sentinel watch time"),
  sentinel_masters_pattern = ts.string:is_optional():describe("Sentinel masters pattern"),
  sentinel_master_maxerrors = (ts.number + ts.string / tonumber):is_optional():describe("Sentinel master max errors"),
  sentinel_username = ts.string:is_optional():describe("Sentinel username"),
  sentinel_password = ts.string:is_optional():describe("Sentinel password"),
}

local read_schema = lutil.table_merge({
  read_servers = ts.string + ts.array_of(ts.string),
}, common_schema)

local write_schema = lutil.table_merge({
  write_servers = ts.string + ts.array_of(ts.string),
}, common_schema)

local rw_schema = lutil.table_merge({
  read_servers = ts.string + ts.array_of(ts.string),
  write_servers = ts.string + ts.array_of(ts.string),
}, common_schema)

local servers_schema = lutil.table_merge({
  servers = ts.string + ts.array_of(ts.string),
}, common_schema)

local server_schema = lutil.table_merge({
  server = ts.string + ts.array_of(ts.string),
}, common_schema)

local enrich_schema = function(external)
  return ts.one_of {
    ts.shape(lutil.table_merge(common_schema,
        external)), -- no specific redis servers (e.g when global settings are used)
    ts.shape(lutil.table_merge(read_schema, external)), -- read_servers specified
    ts.shape(lutil.table_merge(write_schema, external)), -- write_servers specified
    ts.shape(lutil.table_merge(rw_schema, external)), -- both read and write servers defined
    ts.shape(lutil.table_merge(servers_schema, external)), -- just servers for both ops
    ts.shape(lutil.table_merge(server_schema, external)), -- legacy `server` attribute
  }
end

exports.enrich_schema = enrich_schema

local function redis_query_sentinel(ev_base, params, initialised)
  local function flatten_redis_table(tbl)
    local res = {}
    for i = 1, #tbl, 2 do
      res[tbl[i]] = tbl[i + 1]
    end

    return res
  end
  -- Coroutines syntax
  local rspamd_redis = require "rspamd_redis"
  local sentinels = params.sentinels
  local addr = sentinels:get_upstream_round_robin()

  local host = addr:get_addr()
  local masters = {}
  local process_masters -- Function that is called to process masters data

  local function masters_cb(err, result)
    if not err and result and type(result) == 'table' then

      local pending_subrequests = 0

      for _, m in ipairs(result) do
        local master = flatten_redis_table(m)

        -- Wrap IPv6-addresses in brackets
        if (master.ip:match(":")) then
          master.ip = "[" .. master.ip .. "]"
        end

        if params.sentinel_masters_pattern then
          if master.name:match(params.sentinel_masters_pattern) then
            lutil.debugm(N, 'found master %s with ip %s and port %s',
                master.name, master.ip, master.port)
            masters[master.name] = master
          else
            lutil.debugm(N, 'skip master %s with ip %s and port %s, pattern %s',
                master.name, master.ip, master.port, params.sentinel_masters_pattern)
          end
        else
          lutil.debugm(N, 'found master %s with ip %s and port %s',
              master.name, master.ip, master.port)
          masters[master.name] = master
        end
      end

      -- For each master we need to get a list of slaves
      for k, v in pairs(masters) do
        v.slaves = {}
        local function slaves_cb(slave_err, slave_result)
          if not slave_err and type(slave_result) == 'table' then
            for _, s in ipairs(slave_result) do
              local slave = flatten_redis_table(s)
              lutil.debugm(N, rspamd_config,
                  'found slave for master %s with ip %s and port %s',
                  v.name, slave.ip, slave.port)
              -- Wrap IPv6-addresses in brackets
              if (slave.ip:match(":")) then
                slave.ip = "[" .. slave.ip .. "]"
              end
              v.slaves[#v.slaves + 1] = slave
            end
          else
            logger.errx('cannot get slaves data from Redis Sentinel %s: %s',
                host:to_string(true), slave_err)
            addr:fail()
          end

          pending_subrequests = pending_subrequests - 1

          if pending_subrequests == 0 then
            -- Finalize masters and slaves
            process_masters()
          end
        end

        local ret = rspamd_redis.make_request {
          host = addr:get_addr(),
          timeout = params.timeout,
          username = params.sentinel_username,
          password = params.sentinel_password,
          config = rspamd_config,
          ev_base = ev_base,
          cmd = 'SENTINEL',
          args = { 'slaves', k },
          no_pool = true,
          callback = slaves_cb
        }

        if not ret then
          logger.errx(rspamd_config, 'cannot connect sentinel when query slaves at address: %s',
              host:to_string(true))
          addr:fail()
        else
          pending_subrequests = pending_subrequests + 1
        end
      end

      addr:ok()
    else
      logger.errx('cannot get masters data from Redis Sentinel %s: %s',
          host:to_string(true), err)
      addr:fail()
    end
  end

  local ret = rspamd_redis.make_request {
    host = addr:get_addr(),
    timeout = params.timeout,
    config = rspamd_config,
    ev_base = ev_base,
    username = params.sentinel_username,
    password = params.sentinel_password,
    cmd = 'SENTINEL',
    args = { 'masters' },
    no_pool = true,
    callback = masters_cb,
  }

  if not ret then
    logger.errx(rspamd_config, 'cannot connect sentinel at address: %s',
        host:to_string(true))
    addr:fail()
  end

  process_masters = function()
    -- We now form new strings for masters and slaves
    local read_servers_tbl, write_servers_tbl = {}, {}

    for _, master in pairs(masters) do
      write_servers_tbl[#write_servers_tbl + 1] = string.format(
          '%s:%s', master.ip, master.port
      )
      read_servers_tbl[#read_servers_tbl + 1] = string.format(
          '%s:%s', master.ip, master.port
      )

      for _, slave in ipairs(master.slaves) do
        if slave['master-link-status'] == 'ok' then
          read_servers_tbl[#read_servers_tbl + 1] = string.format(
              '%s:%s', slave.ip, slave.port
          )
        end
      end
    end

    table.sort(read_servers_tbl)
    table.sort(write_servers_tbl)

    local read_servers_str = table.concat(read_servers_tbl, ',')
    local write_servers_str = table.concat(write_servers_tbl, ',')

    lutil.debugm(N, rspamd_config,
        'new servers list: %s read; %s write',
        read_servers_str,
        write_servers_str)

    if read_servers_str ~= params.read_servers_str then
      local upstream_list = require "rspamd_upstream_list"

      local read_upstreams = upstream_list.create(rspamd_config,
          read_servers_str, 6379)

      if read_upstreams then
        logger.infox(rspamd_config, 'sentinel %s: replace read servers with new list: %s',
            host:to_string(true), read_servers_str)
        params.read_servers = read_upstreams
        params.read_servers_str = read_servers_str
      end
    end

    if write_servers_str ~= params.write_servers_str then
      local upstream_list = require "rspamd_upstream_list"

      local write_upstreams = upstream_list.create(rspamd_config,
          write_servers_str, 6379)

      if write_upstreams then
        logger.infox(rspamd_config, 'sentinel %s: replace write servers with new list: %s',
            host:to_string(true), write_servers_str)
        params.write_servers = write_upstreams
        params.write_servers_str = write_servers_str

        local queried = false

        local function monitor_failures(up, _, count)
          if count > params.sentinel_master_maxerrors and not queried then
            logger.infox(rspamd_config, 'sentinel: master with address %s, caused %s failures, try to query sentinel',
                host:to_string(true), count)
            queried = true -- Avoid multiple checks caused by this monitor
            redis_query_sentinel(ev_base, params, true)
          end
        end

        write_upstreams:add_watcher('failure', monitor_failures)
      end
    end
  end

end

local function add_redis_sentinels(params)
  local upstream_list = require "rspamd_upstream_list"

  local upstreams_sentinels = upstream_list.create(rspamd_config,
      params.sentinels, 5000)

  if not upstreams_sentinels then
    logger.errx(rspamd_config, 'cannot load redis sentinels string: %s',
        params.sentinels)

    return
  end

  params.sentinels = upstreams_sentinels

  if not params.sentinel_watch_time then
    params.sentinel_watch_time = 60 -- Each minute
  end

  if not params.sentinel_master_maxerrors then
    params.sentinel_master_maxerrors = 2 -- Maximum number of errors before rechecking
  end

  rspamd_config:add_on_load(function(_, ev_base, worker)
    local initialised = false
    if worker:is_scanner() or worker:get_type() == 'fuzzy' then
      rspamd_config:add_periodic(ev_base, 0.0, function()
        redis_query_sentinel(ev_base, params, initialised)
        initialised = true

        return params.sentinel_watch_time
      end, false)
    end
  end)
end

local cached_results = {}

local function calculate_redis_hash(params)
  local cr = require "rspamd_cryptobox_hash"

  local h = cr.create()

  local function rec_hash(k, v)
    if type(v) == 'string' then
      h:update(k)
      h:update(v)
    elseif type(v) == 'number' then
      h:update(k)
      h:update(tostring(v))
    elseif type(v) == 'table' then
      for kk, vv in pairs(v) do
        rec_hash(kk, vv)
      end
    end
  end

  rec_hash('top', params)

  return h:base32()
end

local function process_redis_opts(options, redis_params)
  local default_timeout = 1.0
  local default_expand_keys = false

  if not redis_params['timeout'] or redis_params['timeout'] == default_timeout then
    if options['timeout'] then
      redis_params['timeout'] = tonumber(options['timeout'])
    else
      redis_params['timeout'] = default_timeout
    end
  end

  if options['prefix'] and not redis_params['prefix'] then
    redis_params['prefix'] = options['prefix']
  end

  if type(options['expand_keys']) == 'boolean' then
    redis_params['expand_keys'] = options['expand_keys']
  else
    redis_params['expand_keys'] = default_expand_keys
  end

  if not redis_params['db'] then
    if options['db'] then
      redis_params['db'] = tostring(options['db'])
    elseif options['dbname'] then
      redis_params['db'] = tostring(options['dbname'])
    elseif options['database'] then
      redis_params['db'] = tostring(options['database'])
    end
  end
  if options['username'] and not redis_params['username'] then
    redis_params['username'] = options['username']
  end
  if options['password'] and not redis_params['password'] then
    redis_params['password'] = options['password']
  end

  if not redis_params.sentinels and options.sentinels then
    redis_params.sentinels = options.sentinels
  end

  if options['sentinel_masters_pattern'] and not redis_params['sentinel_masters_pattern'] then
    redis_params['sentinel_masters_pattern'] = options['sentinel_masters_pattern']
  end

end

local function enrich_defaults(rspamd_config, module, redis_params)
  if rspamd_config then
    local opts = rspamd_config:get_all_opt('redis')

    if opts then
      if module then
        if opts[module] then
          process_redis_opts(opts[module], redis_params)
        end
      end

      process_redis_opts(opts, redis_params)
    end
  end
end

local function maybe_return_cached(redis_params)
  local h = calculate_redis_hash(redis_params)

  if cached_results[h] then
    lutil.debugm(N, 'reused redis server: %s', redis_params)
    return cached_results[h]
  end

  redis_params.hash = h
  cached_results[h] = redis_params

  if not redis_params.read_only and redis_params.sentinels then
    add_redis_sentinels(redis_params)
  end

  lutil.debugm(N, 'loaded new redis server: %s', redis_params)
  return redis_params
end

--[[[
-- @module lua_redis
-- This module contains helper functions for working with Redis
--]]
local function process_redis_options(options, rspamd_config, result)
  local default_port = 6379
  local upstream_list = require "rspamd_upstream_list"
  local read_only = true

  -- Try to get read servers:
  local upstreams_read, upstreams_write

  if options['read_servers'] then
    if rspamd_config then
      upstreams_read = upstream_list.create(rspamd_config,
          options['read_servers'], default_port)
    else
      upstreams_read = upstream_list.create(options['read_servers'],
          default_port)
    end

    result.read_servers_str = options['read_servers']
  elseif options['servers'] then
    if rspamd_config then
      upstreams_read = upstream_list.create(rspamd_config,
          options['servers'], default_port)
    else
      upstreams_read = upstream_list.create(options['servers'], default_port)
    end

    result.read_servers_str = options['servers']
    read_only = false
  elseif options['server'] then
    if rspamd_config then
      upstreams_read = upstream_list.create(rspamd_config,
          options['server'], default_port)
    else
      upstreams_read = upstream_list.create(options['server'], default_port)
    end

    result.read_servers_str = options['server']
    read_only = false
  end

  if upstreams_read then
    if options['write_servers'] then
      if rspamd_config then
        upstreams_write = upstream_list.create(rspamd_config,
            options['write_servers'], default_port)
      else
        upstreams_write = upstream_list.create(options['write_servers'],
            default_port)
      end
      result.write_servers_str = options['write_servers']
      read_only = false
    elseif not read_only then
      upstreams_write = upstreams_read
      result.write_servers_str = result.read_servers_str
    end
  end

  -- Store options
  process_redis_opts(options, result)

  if read_only and not upstreams_write then
    result.read_only = true
  elseif upstreams_write then
    result.read_only = false
  end

  if upstreams_read then
    result.read_servers = upstreams_read

    if upstreams_write then
      result.write_servers = upstreams_write
    end

    return true
  end

  lutil.debugm(N, rspamd_config,
      'cannot load redis server from obj: %s, processed to %s',
      options, result)

  return false
end

--[[[
@function try_load_redis_servers(options, rspamd_config, no_fallback)
Tries to load redis servers from the specified `options` object.
Returns `redis_params` table or nil in case of failure

--]]
exports.try_load_redis_servers = function(options, rspamd_config, no_fallback, module_name)
  local result = {}

  if process_redis_options(options, rspamd_config, result) then
    if not no_fallback then
      enrich_defaults(rspamd_config, module_name, result)
    end
    return maybe_return_cached(result)
  end
end

-- This function parses redis server definition using either
-- specific server string for this module or global
-- redis section
local function rspamd_parse_redis_server(module_name, module_opts, no_fallback)
  local result = {}

  -- Try local options
  local opts
  lutil.debugm(N, rspamd_config, 'try load redis config for: %s', module_name)
  if not module_opts then
    opts = rspamd_config:get_all_opt(module_name)
  else
    opts = module_opts
  end

  if opts then
    local ret

    if opts.redis then
      ret = process_redis_options(opts.redis, rspamd_config, result)

      if ret then
        if not no_fallback then
          enrich_defaults(rspamd_config, module_name, result)
        end
        return maybe_return_cached(result)
      end
    end

    ret = process_redis_options(opts, rspamd_config, result)

    if ret then
      if not no_fallback then
        enrich_defaults(rspamd_config, module_name, result)
      end
      return maybe_return_cached(result)
    end
  end

  if no_fallback then
    logger.infox(rspamd_config, "cannot find Redis definitions for %s and fallback is disabled",
        module_name)

    return nil
  end

  -- Try global options
  opts = rspamd_config:get_all_opt('redis')

  if opts then
    local ret

    if opts[module_name] then
      ret = process_redis_options(opts[module_name], rspamd_config, result)

      if ret then
        return maybe_return_cached(result)
      end
    else
      ret = process_redis_options(opts, rspamd_config, result)

      -- Exclude disabled
      if opts['disabled_modules'] then
        for _, v in ipairs(opts['disabled_modules']) do
          if v == module_name then
            logger.infox(rspamd_config, "NOT using default redis server for module %s: it is disabled",
                module_name)

            return nil
          end
        end
      end

      if ret then
        logger.infox(rspamd_config, "use default Redis settings for %s",
            module_name)
        return maybe_return_cached(result)
      end
    end
  end

  if result.read_servers then
    return maybe_return_cached(result)
  end

  return nil
end

--[[[
-- @function lua_redis.parse_redis_server(module_name, module_opts, no_fallback)
-- Extracts Redis server settings from configuration
-- @param {string} module_name name of module to get settings for
-- @param {table} module_opts settings for module or `nil` to fetch them from configuration
-- @param {boolean} no_fallback should be `true` if global settings must not be used
-- @return {table} redis server settings
-- @example
-- local rconfig = lua_redis.parse_redis_server('my_module')
-- -- rconfig contains upstream_list objects in ['write_servers'] and ['read_servers']
-- -- ['timeout'] contains timeout in seconds
-- -- ['expand_keys'] if true tells that redis key expansion is enabled
--]]

exports.rspamd_parse_redis_server = rspamd_parse_redis_server
exports.parse_redis_server = rspamd_parse_redis_server

local process_cmd = {
  bitop = function(args)
    local idx_l = {}
    for i = 2, #args do
      table.insert(idx_l, i)
    end
    return idx_l
  end,
  blpop = function(args)
    local idx_l = {}
    for i = 1, #args - 1 do
      table.insert(idx_l, i)
    end
    return idx_l
  end,
  eval = function(args)
    local idx_l = {}
    local numkeys = args[2]
    if numkeys and tonumber(numkeys) >= 1 then
      for i = 3, numkeys + 2 do
        table.insert(idx_l, i)
      end
    end
    return idx_l
  end,
  set = function(args)
    return { 1 }
  end,
  mget = function(args)
    local idx_l = {}
    for i = 1, #args do
      table.insert(idx_l, i)
    end
    return idx_l
  end,
  mset = function(args)
    local idx_l = {}
    for i = 1, #args, 2 do
      table.insert(idx_l, i)
    end
    return idx_l
  end,
  sdiffstore = function(args)
    local idx_l = {}
    for i = 2, #args do
      table.insert(idx_l, i)
    end
    return idx_l
  end,
  smove = function(args)
    return { 1, 2 }
  end,
  script = function()
  end
}
process_cmd.append = process_cmd.set
process_cmd.auth = process_cmd.script
process_cmd.bgrewriteaof = process_cmd.script
process_cmd.bgsave = process_cmd.script
process_cmd.bitcount = process_cmd.set
process_cmd.bitfield = process_cmd.set
process_cmd.bitpos = process_cmd.set
process_cmd.brpop = process_cmd.blpop
process_cmd.brpoplpush = process_cmd.blpop
process_cmd.client = process_cmd.script
process_cmd.cluster = process_cmd.script
process_cmd.command = process_cmd.script
process_cmd.config = process_cmd.script
process_cmd.dbsize = process_cmd.script
process_cmd.debug = process_cmd.script
process_cmd.decr = process_cmd.set
process_cmd.decrby = process_cmd.set
process_cmd.del = process_cmd.mget
process_cmd.discard = process_cmd.script
process_cmd.dump = process_cmd.set
process_cmd.echo = process_cmd.script
process_cmd.evalsha = process_cmd.eval
process_cmd.exec = process_cmd.script
process_cmd.exists = process_cmd.mget
process_cmd.expire = process_cmd.set
process_cmd.expireat = process_cmd.set
process_cmd.flushall = process_cmd.script
process_cmd.flushdb = process_cmd.script
process_cmd.geoadd = process_cmd.set
process_cmd.geohash = process_cmd.set
process_cmd.geopos = process_cmd.set
process_cmd.geodist = process_cmd.set
process_cmd.georadius = process_cmd.set
process_cmd.georadiusbymember = process_cmd.set
process_cmd.get = process_cmd.set
process_cmd.getbit = process_cmd.set
process_cmd.getrange = process_cmd.set
process_cmd.getset = process_cmd.set
process_cmd.hdel = process_cmd.set
process_cmd.hexists = process_cmd.set
process_cmd.hget = process_cmd.set
process_cmd.hgetall = process_cmd.set
process_cmd.hincrby = process_cmd.set
process_cmd.hincrbyfloat = process_cmd.set
process_cmd.hkeys = process_cmd.set
process_cmd.hlen = process_cmd.set
process_cmd.hmget = process_cmd.set
process_cmd.hmset = process_cmd.set
process_cmd.hscan = process_cmd.set
process_cmd.hset = process_cmd.set
process_cmd.hsetnx = process_cmd.set
process_cmd.hstrlen = process_cmd.set
process_cmd.hvals = process_cmd.set
process_cmd.incr = process_cmd.set
process_cmd.incrby = process_cmd.set
process_cmd.incrbyfloat = process_cmd.set
process_cmd.info = process_cmd.script
process_cmd.keys = process_cmd.script
process_cmd.lastsave = process_cmd.script
process_cmd.lindex = process_cmd.set
process_cmd.linsert = process_cmd.set
process_cmd.llen = process_cmd.set
process_cmd.lpop = process_cmd.set
process_cmd.lpush = process_cmd.set
process_cmd.lpushx = process_cmd.set
process_cmd.lrange = process_cmd.set
process_cmd.lrem = process_cmd.set
process_cmd.lset = process_cmd.set
process_cmd.ltrim = process_cmd.set
process_cmd.migrate = process_cmd.script
process_cmd.monitor = process_cmd.script
process_cmd.move = process_cmd.set
process_cmd.msetnx = process_cmd.mset
process_cmd.multi = process_cmd.script
process_cmd.object = process_cmd.script
process_cmd.persist = process_cmd.set
process_cmd.pexpire = process_cmd.set
process_cmd.pexpireat = process_cmd.set
process_cmd.pfadd = process_cmd.set
process_cmd.pfcount = process_cmd.set
process_cmd.pfmerge = process_cmd.mget
process_cmd.ping = process_cmd.script
process_cmd.psetex = process_cmd.set
process_cmd.psubscribe = process_cmd.script
process_cmd.pubsub = process_cmd.script
process_cmd.pttl = process_cmd.set
process_cmd.publish = process_cmd.script
process_cmd.punsubscribe = process_cmd.script
process_cmd.quit = process_cmd.script
process_cmd.randomkey = process_cmd.script
process_cmd.readonly = process_cmd.script
process_cmd.readwrite = process_cmd.script
process_cmd.rename = process_cmd.mget
process_cmd.renamenx = process_cmd.mget
process_cmd.restore = process_cmd.set
process_cmd.role = process_cmd.script
process_cmd.rpop = process_cmd.set
process_cmd.rpoplpush = process_cmd.mget
process_cmd.rpush = process_cmd.set
process_cmd.rpushx = process_cmd.set
process_cmd.sadd = process_cmd.set
process_cmd.save = process_cmd.script
process_cmd.scard = process_cmd.set
process_cmd.sdiff = process_cmd.mget
process_cmd.select = process_cmd.script
process_cmd.setbit = process_cmd.set
process_cmd.setex = process_cmd.set
process_cmd.setnx = process_cmd.set
process_cmd.sinterstore = process_cmd.sdiff
process_cmd.sismember = process_cmd.set
process_cmd.slaveof = process_cmd.script
process_cmd.slowlog = process_cmd.script
process_cmd.smembers = process_cmd.script
process_cmd.sort = process_cmd.set
process_cmd.spop = process_cmd.set
process_cmd.srandmember = process_cmd.set
process_cmd.srem = process_cmd.set
process_cmd.strlen = process_cmd.set
process_cmd.subscribe = process_cmd.script
process_cmd.sunion = process_cmd.mget
process_cmd.sunionstore = process_cmd.mget
process_cmd.swapdb = process_cmd.script
process_cmd.sync = process_cmd.script
process_cmd.time = process_cmd.script
process_cmd.touch = process_cmd.mget
process_cmd.ttl = process_cmd.set
process_cmd.type = process_cmd.set
process_cmd.unsubscribe = process_cmd.script
process_cmd.unlink = process_cmd.mget
process_cmd.unwatch = process_cmd.script
process_cmd.wait = process_cmd.script
process_cmd.watch = process_cmd.mget
process_cmd.zadd = process_cmd.set
process_cmd.zcard = process_cmd.set
process_cmd.zcount = process_cmd.set
process_cmd.zincrby = process_cmd.set
process_cmd.zinterstore = process_cmd.eval
process_cmd.zlexcount = process_cmd.set
process_cmd.zrange = process_cmd.set
process_cmd.zrangebylex = process_cmd.set
process_cmd.zrank = process_cmd.set
process_cmd.zrem = process_cmd.set
process_cmd.zrembylex = process_cmd.set
process_cmd.zrembyrank = process_cmd.set
process_cmd.zrembyscore = process_cmd.set
process_cmd.zrevrange = process_cmd.set
process_cmd.zrevrangebyscore = process_cmd.set
process_cmd.zrevrank = process_cmd.set
process_cmd.zscore = process_cmd.set
process_cmd.zunionstore = process_cmd.eval
process_cmd.scan = process_cmd.script
process_cmd.sscan = process_cmd.set
process_cmd.hscan = process_cmd.set
process_cmd.zscan = process_cmd.set

local function get_key_indexes(cmd, args)
  local idx_l = {}
  cmd = string.lower(cmd)
  if process_cmd[cmd] then
    idx_l = process_cmd[cmd](args)
  else
    logger.warnx(rspamd_config, "Don't know how to extract keys for %s Redis command", cmd)
  end
  return idx_l
end

local gen_meta = {
  principal_recipient = function(task)
    return task:get_principal_recipient()
  end,
  principal_recipient_domain = function(task)
    local p = task:get_principal_recipient()
    if not p then
      return
    end
    return string.match(p, '.*@(.*)')
  end,
  ip = function(task)
    local i = task:get_ip()
    if i and i:is_valid() then
      return i:to_string()
    end
  end,
  from = function(task)
    return ((task:get_from('smtp') or E)[1] or E)['addr']
  end,
  from_domain = function(task)
    return ((task:get_from('smtp') or E)[1] or E)['domain']
  end,
  from_domain_or_helo_domain = function(task)
    local d = ((task:get_from('smtp') or E)[1] or E)['domain']
    if d and #d > 0 then
      return d
    end
    return task:get_helo()
  end,
  mime_from = function(task)
    return ((task:get_from('mime') or E)[1] or E)['addr']
  end,
  mime_from_domain = function(task)
    return ((task:get_from('mime') or E)[1] or E)['domain']
  end,
}

local function gen_get_esld(f)
  return function(task)
    local d = f(task)
    if not d then
      return
    end
    return rspamd_util.get_tld(d)
  end
end

gen_meta.smtp_from = gen_meta.from
gen_meta.smtp_from_domain = gen_meta.from_domain
gen_meta.smtp_from_domain_or_helo_domain = gen_meta.from_domain_or_helo_domain
gen_meta.esld_principal_recipient_domain = gen_get_esld(gen_meta.principal_recipient_domain)
gen_meta.esld_from_domain = gen_get_esld(gen_meta.from_domain)
gen_meta.esld_smtp_from_domain = gen_meta.esld_from_domain
gen_meta.esld_mime_from_domain = gen_get_esld(gen_meta.mime_from_domain)
gen_meta.esld_from_domain_or_helo_domain = gen_get_esld(gen_meta.from_domain_or_helo_domain)
gen_meta.esld_smtp_from_domain_or_helo_domain = gen_meta.esld_from_domain_or_helo_domain

local function get_key_expansion_metadata(task)

  local md_mt = {
    __index = function(self, k)
      k = string.lower(k)
      local v = rawget(self, k)
      if v then
        return v
      end
      if gen_meta[k] then
        v = gen_meta[k](task)
        rawset(self, k, v)
      end
      return v
    end,
  }

  local lazy_meta = {}
  setmetatable(lazy_meta, md_mt)
  return lazy_meta

end

-- Performs async call to redis hiding all complexity inside function
-- task - rspamd_task
-- redis_params - valid params returned by rspamd_parse_redis_server
-- key - key to select upstream or nil to select round-robin/master-slave
-- is_write - true if need to write to redis server
-- callback - function to be called upon request is completed
-- command - redis command
-- args - table of arguments
-- extra_opts - table of optional request arguments
local function rspamd_redis_make_request(task, redis_params, key, is_write,
                                         callback, command, args, extra_opts)
  local addr
  local function rspamd_redis_make_request_cb(err, data)
    if err then
      addr:fail()
    else
      addr:ok()
    end
    if callback then
      callback(err, data, addr)
    end
  end
  if not task or not redis_params or not command then
    return false, nil, nil
  end

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
    logger.errx(task, 'cannot select server to make redis request')
  end

  if redis_params['expand_keys'] then
    local m = get_key_expansion_metadata(task)
    local indexes = get_key_indexes(command, args)
    for _, i in ipairs(indexes) do
      args[i] = lutil.template(args[i], m)
    end
  end

  local ip_addr = addr:get_addr()
  local options = {
    task = task,
    callback = rspamd_redis_make_request_cb,
    host = ip_addr,
    timeout = redis_params['timeout'],
    cmd = command,
    args = args
  }

  if extra_opts then
    for k, v in pairs(extra_opts) do
      options[k] = v
    end
  end

  if redis_params['username'] then
    options['username'] = redis_params['username']
  end

  if redis_params['password'] then
    options['password'] = redis_params['password']
  end

  if redis_params['db'] then
    options['dbname'] = redis_params['db']
  end

  lutil.debugm(N, task, 'perform request to redis server' ..
      ' (host=%s, timeout=%s): cmd: %s', ip_addr,
      options.timeout, options.cmd)

  local ret, conn = rspamd_redis.make_request(options)

  if not ret then
    addr:fail()
    logger.warnx(task, "cannot make redis request to: %s", tostring(ip_addr))
  end

  return ret, conn, addr
end

--[[[
-- @function lua_redis.redis_make_request(task, redis_params, key, is_write, callback, command, args)
-- Sends a request to Redis
-- @param {rspamd_task} task task object
-- @param {table} redis_params redis configuration in format returned by lua_redis.parse_redis_server()
-- @param {string} key key to use for sharding
-- @param {boolean} is_write should be `true` if we are performing a write operating
-- @param {function} callback callback function (first parameter is error if applicable, second is a 2D array (table))
-- @param {string} command Redis command to run
-- @param {table} args Numerically indexed table containing arguments for command
--]]

exports.rspamd_redis_make_request = rspamd_redis_make_request
exports.redis_make_request = rspamd_redis_make_request

local function redis_make_request_taskless(ev_base, cfg, redis_params, key,
                                           is_write, callback, command, args, extra_opts)
  if not ev_base or not redis_params or not command then
    return false, nil, nil
  end

  local addr
  local function rspamd_redis_make_request_cb(err, data)
    if err then
      addr:fail()
    else
      addr:ok()
    end
    if callback then
      callback(err, data, addr)
    end
  end

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
    logger.errx(cfg, 'cannot select server to make redis request')
  end

  local options = {
    ev_base = ev_base,
    config = cfg,
    callback = rspamd_redis_make_request_cb,
    host = addr:get_addr(),
    timeout = redis_params['timeout'],
    cmd = command,
    args = args
  }
  if extra_opts then
    for k, v in pairs(extra_opts) do
      options[k] = v
    end
  end

  if redis_params['username'] then
    options['username'] = redis_params['username']
  end

  if redis_params['password'] then
    options['password'] = redis_params['password']
  end

  if redis_params['db'] then
    options['dbname'] = redis_params['db']
  end

  lutil.debugm(N, cfg, 'perform taskless request to redis server' ..
      ' (host=%s, timeout=%s): cmd: %s', options.host:tostring(true),
      options.timeout, options.cmd)
  local ret, conn = rspamd_redis.make_request(options)
  if not ret then
    logger.errx('cannot execute redis request')
    addr:fail()
  end

  return ret, conn, addr
end

--[[[
-- @function lua_redis.redis_make_request_taskless(ev_base, redis_params, key, is_write, callback, command, args)
-- Sends a request to Redis in context where `task` is not available for some specific use-cases
-- Identical to redis_make_request() except in that first parameter is an `event base` object
--]]

exports.rspamd_redis_make_request_taskless = redis_make_request_taskless
exports.redis_make_request_taskless = redis_make_request_taskless

local redis_scripts = {
}

local function script_set_loaded(script)
  if script.sha then
    script.loaded = true
  end

  local wait_table = {}
  for _, s in ipairs(script.waitq) do
    table.insert(wait_table, s)
  end

  script.waitq = {}

  for _, s in ipairs(wait_table) do
    s(script.loaded)
  end
end

local function prepare_redis_call(script)
  local servers = {}
  local options = {}

  if script.redis_params.read_servers then
    servers = lutil.table_merge(servers, script.redis_params.read_servers:all_upstreams())
  end
  if script.redis_params.write_servers then
    servers = lutil.table_merge(servers, script.redis_params.write_servers:all_upstreams())
  end

  -- Call load script on each server, set loaded flag
  if not script.servers_ready then
    script.servers_ready = { } -- possible values for each server: unsent, tempfail, failed, done
  end

  for idx, s in ipairs(servers) do
    local cur_opts = {
      host = s:get_addr(),
      timeout = script.redis_params['timeout'],
      cmd = 'SCRIPT',
      args = { 'LOAD', script.script },
      upstream = s
    }

    -- By default we start from unsent status
    if not script.servers_ready[idx] then
      script.servers_ready[idx] = "unsent"
    end

    if script.redis_params['username'] then
      cur_opts['username'] = script.redis_params['username']
    end

    if script.redis_params['password'] then
      cur_opts['password'] = script.redis_params['password']
    end

    if script.redis_params['db'] then
      cur_opts['dbname'] = script.redis_params['db']
    end

    table.insert(options, cur_opts)
  end

  return options
end

local function is_all_servers_ready(script)
  for _, s in ipairs(script.servers_ready) do
    if s == "unsent" or s == "tempfail" then
      return false
    end
  end

  -- We assume that permanent errors are not recoverable, so we will just skip those servers
  return true
end

local function is_all_servers_failed(script)
  for _, s in ipairs(script.servers_ready) do
    if s == "unsent" or s == "tempfail" or s == "done" then
      return false
    end
  end

  return true
end

local function script_description(script)
  return script.filename and ("from file: " .. script.filename)
      or ("with id: " .. script.id)
end

local function load_script_task(script, task, is_write)
  local rspamd_redis = require "rspamd_redis"
  local opts = prepare_redis_call(script)

  for idx, opt in ipairs(opts) do
    if script.servers_ready[idx] ~= 'done' then
      opt.task = task
      opt.is_write = is_write
      opt.callback = function(err, data)
        if err then
          if string.match(err, 'ERR') then
            logger.errx(task, 'cannot upload script %s to %s: %s; registered from: %s:%s',
                script_description(script),
                opt.upstream:get_addr():to_string(true),
                err, script.caller.short_src, script.caller.currentline)
            opt.upstream:fail()
            script.servers_ready[idx] = "failed"
            return
          else
            -- Assume temporary error
            logger.infox(task, 'temporary error uploading script %s to %s: %s; registered from: %s:%s',
                script_description(script),
                opt.upstream:get_addr():to_string(true),
                err, script.caller.short_src, script.caller.currentline)
            script.servers_ready[idx] = "tempfail"
            return
          end
        else
          opt.upstream:ok()
          logger.infox(task,
              "uploaded redis script to %s %s, sha: %s",
              opt.upstream:get_addr():to_string(true),
              script_description(script), data)
          script.sha = data -- We assume that sha is the same on all servers
          script.servers_ready[idx] = "done"
        end
        if is_all_servers_ready(script) then
          script_set_loaded(script)
        elseif is_all_servers_failed(script) then
          script.fatal_error = "cannot upload script to any server"
        end
      end -- callback

      local ret = rspamd_redis.make_request(opt)

      if not ret then
        logger.errx('cannot execute redis request to load script on %s',
            opt.upstream:get_addr())
        script.servers_ready[idx] = "failed"
        opt.upstream:fail()
      end
    end

    if is_all_servers_ready(script) then
      script_set_loaded(script)
    elseif is_all_servers_failed(script) then
      script.fatal_error = "cannot upload script to any server"
    end
  end
end

local function load_script_taskless(script, cfg, ev_base, is_write)
  local rspamd_redis = require "rspamd_redis"
  local opts = prepare_redis_call(script)

  for idx, opt in ipairs(opts) do
    if script.servers_ready[idx] ~= 'done' then
      opt.config = cfg
      opt.ev_base = ev_base
      opt.is_write = is_write
      opt.callback = function(err, data)
        if err then
          if string.match(err, 'ERR') then
            logger.errx(cfg, 'cannot upload script %s to %s: %s; registered from: %s:%s',
                script_description(script),
                opt.upstream:get_addr():to_string(true),
                err, script.caller.short_src, script.caller.currentline)
            opt.upstream:fail()
            script.servers_ready[idx] = "failed"
            return
          else
            -- Assume temporary error
            logger.infox(cfg, 'temporary error uploading script %s to %s: %s; registered from: %s:%s',
                script_description(script),
                opt.upstream:get_addr():to_string(true),
                err, script.caller.short_src, script.caller.currentline)
            script.servers_ready[idx] = "tempfail"
            return
          end
        else
          opt.upstream:ok()
          logger.infox(cfg,
              "uploaded redis script %s to %s, sha: %s",
              script_description(script),
              opt.upstream:get_addr():to_string(true),
              data)
          script.sha = data -- We assume that sha is the same on all servers
          script.servers_ready[idx] = "done"
        end

        if is_all_servers_ready(script) then
          script_set_loaded(script)
        elseif is_all_servers_failed(script) then
          script.fatal_error = "cannot upload script to any server"
        end
      end
      local ret = rspamd_redis.make_request(opt)

      if not ret then
        logger.errx('cannot execute redis request to load script %s on %s',
            script_description(script),
            opt.upstream:get_addr())
        script.servers_ready[idx] = "failed"
        opt.upstream:fail()
      end
    end

    if is_all_servers_ready(script) then
      script_set_loaded(script)
    elseif is_all_servers_failed(script) then
      script.fatal_error = "cannot upload script " .. script_description(script) .. " to any server"
    end
  end
end

local function load_redis_script(script, cfg, ev_base, _)
  if script.redis_params then
    load_script_taskless(script, cfg, ev_base)
  end
end

local function add_redis_script(script, redis_params, caller_level, maybe_filename)
  if not caller_level then
    caller_level = 2
  end
  local caller = debug.getinfo(caller_level) or debug.getinfo(caller_level - 1) or E

  local new_script = {
    caller = caller,
    loaded = false,
    redis_params = redis_params,
    script = script,
    waitq = {}, -- callbacks pending for script being loaded
    id = #redis_scripts + 1,
    filename = maybe_filename,
  }

  -- Register on load function
  rspamd_config:add_on_load(function(cfg, ev_base, worker)
    local mult = 0.0
    rspamd_config:add_periodic(ev_base, 0.0, function()
      if not new_script.sha and not new_script.fatal_error then
        load_redis_script(new_script, cfg, ev_base, worker)

        -- Do not wait for more than 10 seconds to retry
        if mult < 10 then
          mult = mult + 1
        end
        return 1.0 * mult -- Check one more time in one second
      end

      -- All loaded, we are good to go
      return false
    end, false)
  end)

  table.insert(redis_scripts, new_script)

  return #redis_scripts
end
exports.add_redis_script = add_redis_script

-- Loads a Redis script from a file, strips comments, and passes the content to
-- `add_redis_script` function.
--
-- @param filename The name of the file containing the Redis script.
-- @param redis_params The Redis parameters to use for this script.
-- @return The ID of the newly added Redis script.
--
local function load_redis_script_from_file(filename, redis_params, dir)
  local lua_util = require "lua_util"
  local rspamd_logger = require "rspamd_logger"

  if not dir then
    dir = rspamd_paths.LUALIBDIR
  end
  local path = filename
  if filename:sub(1, 1) ~= package.config:sub(1, 1) then
    -- Relative path
    path = lua_util.join_path(dir, "redis_scripts", filename)
  end
  -- Read file contents
  local file = io.open(path, "r")
  if not file then
    rspamd_logger.errx("failed to open Redis script file: %s", path)
    return nil
  end
  local script = file:read("*all")
  if not script then
    rspamd_logger.errx("failed to load Redis script file: %s", path)
    return nil
  end
  file:close()
  script = lua_util.strip_lua_comments(script)

  return add_redis_script(script, redis_params, 3, filename)
end

exports.load_redis_script_from_file = load_redis_script_from_file

local function exec_redis_script(id, params, callback, keys, args)
  local redis_args = {}

  if not redis_scripts[id] then
    logger.errx("cannot find registered script with id %s", id)
    return false
  end

  local script = redis_scripts[id]

  if script.fatal_error then
    callback(script.fatal_error, nil)
    return true
  end

  if not script.redis_params then
    callback('no redis servers defined', nil)
    return true
  end

  local function do_call(can_reload)
    local function redis_cb(err, data)
      if not err then
        callback(err, data)
      elseif string.match(err, 'NOSCRIPT') then
        -- Schedule restart
        logger.infox(params.task, 'redis script %s is not loaded (NOSCRIPT returned), scheduling reload',
            script_description(script))
        script.sha = nil
        if can_reload then
          table.insert(script.waitq, do_call)
          if not script.servers_ready then
            -- Reload scripts if this has not been initiated yet
            if params.task then
              load_script_task(script, params.task)
            else
              load_script_taskless(script, rspamd_config, params.ev_base)
            end
          end
        else
          callback(err, data)
        end
      else
        callback(err, data)
      end
    end

    if #redis_args == 0 then
      table.insert(redis_args, script.sha)
      table.insert(redis_args, tostring(#keys))
      for _, k in ipairs(keys) do
        table.insert(redis_args, k)
      end

      if type(args) == 'table' then
        for _, a in ipairs(args) do
          table.insert(redis_args, a)
        end
      end
    end

    if params.task then
      if not rspamd_redis_make_request(params.task, script.redis_params,
          params.key, params.is_write, redis_cb, 'EVALSHA', redis_args) then
        callback('Cannot make redis request', nil)
      end
    else
      if not redis_make_request_taskless(params.ev_base, rspamd_config,
          script.redis_params,
          params.key, params.is_write, redis_cb, 'EVALSHA', redis_args) then
        callback('Cannot make redis request', nil)
      end
    end
  end

  if script.loaded then
    do_call(true)
  else
    -- Delayed until scripts are loaded
    logger.infox(params.task or rspamd_config, 'redis script %s is not loaded, trying to load',
        script_description(script))
    if not params.task then
      table.insert(script.waitq, do_call)
    else
      -- TODO: fix taskfull requests
      table.insert(script.waitq, function()
        if script.loaded then
          do_call(false)
        else
          callback('NOSCRIPT', nil)
        end
      end)
      load_script_task(script, params.task, params.is_write)
    end
  end

  return true
end

exports.exec_redis_script = exec_redis_script

local function redis_connect_sync(redis_params, is_write, key, cfg, ev_base)
  if not redis_params then
    return false, nil
  end

  local rspamd_redis = require "rspamd_redis"
  local addr

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
    logger.errx(cfg, 'cannot select server to make redis request')
  end

  local options = {
    host = addr:get_addr(),
    timeout = redis_params['timeout'],
    config = cfg or rspamd_config,
    ev_base = ev_base or rspamadm_ev_base,
    session = redis_params.session or rspamadm_session
  }

  for k, v in pairs(redis_params) do
    options[k] = v
  end

  if not options.config then
    logger.errx('config is not set')
    return false, nil, addr
  end

  if not options.ev_base then
    logger.errx('ev_base is not set')
    return false, nil, addr
  end

  if not options.session then
    logger.errx('session is not set')
    return false, nil, addr
  end

  local ret, conn = rspamd_redis.connect_sync(options)
  if not ret then
    logger.errx('cannot create redis connection: %s', conn)
    addr:fail()

    return false, nil, addr
  end

  if conn then
    local need_exec = false
    if redis_params['username'] then
      if redis_params['password'] then
        conn:add_cmd('AUTH', { redis_params['username'], redis_params['password'] })
        need_exec = true
      else
        logger.warnx('Redis requires a password when username is supplied')
        return false, nil, addr
      end
    elseif redis_params['password'] then
      conn:add_cmd('AUTH', { redis_params['password'] })
      need_exec = true
    end

    if redis_params['db'] then
      conn:add_cmd('SELECT', { tostring(redis_params['db']) })
      need_exec = true
    elseif redis_params['dbname'] then
      conn:add_cmd('SELECT', { tostring(redis_params['dbname']) })
      need_exec = true
    end

    if need_exec then
      local exec_ret, res = conn:exec()

      if not exec_ret then
        logger.errx('cannot prepare redis connection (authentication or db selection failure): %s',
            res)
        addr:fail()
        return false, nil, addr
      end
    end
  end

  return ret, conn, addr
end

exports.redis_connect_sync = redis_connect_sync

--[[[
-- @function lua_redis.request(redis_params, attrs, req)
-- Sends a request to Redis synchronously with coroutines or asynchronously using
-- a callback (modern API)
-- @param redis_params a table of redis server parameters
-- @param attrs a table of redis request attributes (e.g. task, or ev_base + cfg + session)
-- @param req a table of request: a command + command options
-- @return {result,data/connection,address} boolean result, connection object in case of async request and results if using coroutines, redis server address
--]]

exports.request = function(redis_params, attrs, req)
  local lua_util = require "lua_util"

  if not attrs then
    logger.errx('invalid attrs for redis request')
    return false, nil, nil
  end

  if not redis_params then
    logger.errx('invalid redis_params for redis request')
    return false, nil, nil
  end

  if not req then
    logger.errx('invalid req for redis request')
    return false, nil, nil
  end

  if not attrs or not redis_params or not req then
    logger.errx('invalid arguments for redis request')
    return false, nil, nil
  end

  if not (attrs.task or (attrs.config and attrs.ev_base)) then
    logger.errx('invalid attributes for redis request')
    return false, nil, nil
  end

  local opts = lua_util.shallowcopy(attrs)

  local log_obj = opts.task or opts.config

  local addr

  if opts.callback then
    -- Wrap callback
    local callback = opts.callback
    local function rspamd_redis_make_request_cb(err, data)
      if err then
        addr:fail()
      else
        addr:ok()
      end
      callback(err, data, addr)
    end
    opts.callback = rspamd_redis_make_request_cb
  end

  local rspamd_redis = require "rspamd_redis"
  local is_write = opts.is_write

  if opts.key then
    if is_write then
      addr = redis_params['write_servers']:get_upstream_by_hash(attrs.key)
    else
      addr = redis_params['read_servers']:get_upstream_by_hash(attrs.key)
    end
  else
    if is_write then
      addr = redis_params['write_servers']:get_upstream_master_slave(attrs.key)
    else
      addr = redis_params['read_servers']:get_upstream_round_robin(attrs.key)
    end
  end

  if not addr then
    logger.errx(log_obj, 'cannot select server to make redis request')
  end

  opts.host = addr:get_addr()
  opts.timeout = redis_params.timeout

  if type(req) == 'string' then
    opts.cmd = req
  else
    -- XXX: modifies the input table
    opts.cmd = table.remove(req, 1);
    opts.args = req
  end

  if redis_params.username then
    opts.username = redis_params.username
  end

  if redis_params.password then
    opts.password = redis_params.password
  end

  if redis_params.db then
    opts.dbname = redis_params.db
  end

  lutil.debugm(N, 'perform generic request to redis server' ..
      ' (host=%s, timeout=%s): cmd: %s, arguments: %s', addr,
      opts.timeout, opts.cmd, opts.args)

  if opts.callback then
    local ret, conn = rspamd_redis.make_request(opts)
    if not ret then
      logger.errx(log_obj, 'cannot execute redis request')
      addr:fail()
    end

    return ret, conn, addr
  else
    -- Coroutines version
    local ret, conn = rspamd_redis.connect_sync(opts)
    if not ret then
      logger.errx(log_obj, 'cannot execute redis request')
      addr:fail()
    else
      conn:add_cmd(opts.cmd, opts.args)
      return conn:exec()
    end
    return false, nil, addr
  end
end

--[[[
-- @function lua_redis.connect(redis_params, attrs)
-- Connects to Redis synchronously with coroutines or asynchronously using a callback (modern API)
-- @param redis_params a table of redis server parameters
-- @param attrs a table of redis request attributes (e.g. task, or ev_base + cfg + session)
-- @return {result,connection,address} boolean result, connection object, redis server address
--]]

exports.connect = function(redis_params, attrs)
  local lua_util = require "lua_util"

  if not attrs or not redis_params then
    logger.errx('invalid arguments for redis connect')
    return false, nil, nil
  end

  if not (attrs.task or (attrs.config and attrs.ev_base)) then
    logger.errx('invalid attributes for redis connect')
    return false, nil, nil
  end

  local opts = lua_util.shallowcopy(attrs)

  local log_obj = opts.task or opts.config

  local addr

  if opts.callback then
    -- Wrap callback
    local callback = opts.callback
    local function rspamd_redis_make_request_cb(err, data)
      if err then
        addr:fail()
      else
        addr:ok()
      end
      callback(err, data, addr)
    end
    opts.callback = rspamd_redis_make_request_cb
  end

  local rspamd_redis = require "rspamd_redis"
  local is_write = opts.is_write

  if opts.key then
    if is_write then
      addr = redis_params['write_servers']:get_upstream_by_hash(attrs.key)
    else
      addr = redis_params['read_servers']:get_upstream_by_hash(attrs.key)
    end
  else
    if is_write then
      addr = redis_params['write_servers']:get_upstream_master_slave(attrs.key)
    else
      addr = redis_params['read_servers']:get_upstream_round_robin(attrs.key)
    end
  end

  if not addr then
    logger.errx(log_obj, 'cannot select server to make redis connect')
  end

  opts.host = addr:get_addr()
  opts.timeout = redis_params.timeout

  if redis_params.username then
    opts.username = redis_params.username
  end

  if redis_params.password then
    opts.password = redis_params.password
  end

  if redis_params.db then
    opts.dbname = redis_params.db
  end

  if opts.callback then
    local ret, conn = rspamd_redis.connect(opts)
    if not ret then
      logger.errx(log_obj, 'cannot execute redis connect')
      addr:fail()
    end

    return ret, conn, addr
  else
    -- Coroutines version
    local ret, conn = rspamd_redis.connect_sync(opts)
    if not ret then
      logger.errx(log_obj, 'cannot execute redis connect')
      addr:fail()
    else
      return true, conn, addr
    end

    return false, nil, addr
  end
end

local redis_prefixes = {}

--[[[
-- @function lua_redis.register_prefix(prefix, module, description[, optional])
-- Register new redis prefix for documentation purposes
-- @param {string} prefix string prefix
-- @param {string} module module name
-- @param {string} description prefix description
-- @param {table} optional optional kv pairs (e.g. pattern)
--]]
local function register_prefix(prefix, module, description, optional)
  local pr = {
    module = module,
    description = description
  }

  if optional and type(optional) == 'table' then
    for k, v in pairs(optional) do
      pr[k] = v
    end
  end

  redis_prefixes[prefix] = pr
end

exports.register_prefix = register_prefix

--[[[
-- @function lua_redis.prefixes([mname])
-- Returns prefixes for specific module (or all prefixes). Returns a table prefix -> table
--]]
exports.prefixes = function(mname)
  if not mname then
    return redis_prefixes
  else
    local fun = require "fun"

    return fun.totable(fun.filter(function(_, data)
      return data.module == mname
    end,
        redis_prefixes))
  end
end

return exports
