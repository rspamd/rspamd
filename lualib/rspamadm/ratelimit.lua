local argparse = require 'argparse'
local redis = require 'lua_redis'
local logger = require 'rspamd_logger'

local parser = argparse()
    :name "ratelimit"
    :description "Manage ratelimit functional"
    :help_description_margin(32)
    :command_target('command')
    :require_command(true)
parser:option "-c --config"
      :description "Path to config file"
      :argname("<cfg>")
      :default(rspamd_paths["CONFDIR"] .. "/" .. "rspamd.conf")

local track_limits = parser:command 'track'
                           :description 'Track last limits of ratelimit module'

track_limits:option "-q --quantity"
            :description("Number of limits to track")
            :argname("<quantity>")
            :default(1)

local upgrade_bucket = parser:command 'upgrade'
                             :description 'Upgrade certain bucket or top limit bucket'
upgrade_bucket:argument "prefix"
              :description("Prefix of bucket to operate with")
              :args("?")
upgrade_bucket:option "-b --burst"
              :description("Burst to set")
              :argname("<burst>")
              :args("?")
upgrade_bucket:option "-r --rate"
              :description("Rate to set")
              :argname("<rate>")
              :args("?")
upgrade_bucket:option "-s --symbol"
              :description("Symbol to set")
              :argname("<symbol>")
              :args("?")
upgrade_bucket:option "-B --dynamic_burst"
              :description("Dynamic burst to set")
              :argname("<dynb>")
              :args("?")
upgrade_bucket:option "-R --dynamic_rate"
              :description("Dynamic rate to set")
              :argname("<dynr>")
              :args("?")

local unblock_bucket = parser:command 'unblock'
                             :description 'Unblock certain bucket or number of buckets(default: 1)'

parser:mutex(
    unblock_bucket:argument "prefix"
                  :description("Prefix of bucket to operate with")
                  :args(1),
    unblock_bucket:argument "quantity"
                  :description("Number of buckets to ublock")
                  :default(1)
)

local redis_params
local lfb_cache_prefix = 'RL_cache_prefix'
local redis_attrs = {
  config = rspamd_config,
  ev_base = rspamadm_ev_base,
  session = rspamadm_session,
  log_obj = rspamd_config,
  resolver = rspamadm_dns_resolver,
}

local function track_limits_handler(args)
  for i = 1, args.quantity do
    local res, prefix = redis.request(redis_params, redis_attrs,
        { 'ZRANGE', lfb_cache_prefix, -i, -i })
    if not res then
      logger.errx('Redis request error: %s', prefix)
      os.exit(1)
    end

    if #prefix == 1 then
      local _, bucket_params = redis.request(redis_params, redis_attrs,
          { 'HMGET', tostring(prefix[1]), 'l', 'b', 'r', 'dr', 'db' })

      local last = tonumber(bucket_params[1])
      local burst = tonumber(bucket_params[2])
      local rate = tonumber(bucket_params[3])
      local dynr = tonumber(bucket_params[4]) / 10000.0
      local dynb = tonumber(bucket_params[5]) / 10000.0

      print(string.format('prefix: %s, last: %s, burst: %s, rate: %s, dynamic_rate: %s, dynamic_burst: %s',
          prefix[1], last, burst, rate, dynr, dynb))
    end
  end
end

local function upgrade_bucket_handler(args)
  local prefix = args.prefix
  if prefix == nil or prefix == "" then
    local res = nil
    res, prefix = redis.request(redis_params, redis_attrs,
        { 'ZRANGE', lfb_cache_prefix, '-1', '-1' })
    if res ~= 1 then
      logger.errx('Redis request parameters are wrong')
      os.exit(1)
    end
  end

  if args.burst then
    local res, err = redis.request(redis_params, redis_attrs,
        { 'HSET', tostring(prefix), 'b', tostring(args.burst) })
    if not res then
      logger.errx('Incorrect arguments for redis request for burst or prefix is incorrect: %s', err)
      os.exit(1)
    end
  end

  if args.rate then
    local res, err = redis.request(redis_params, redis_attrs,
        { 'HSET', tostring(prefix), 'r', tostring(args.rate) })
    if not res then
      logger.errx('Incorrect arguments for redis request for rate or prefix is incorrect: %s', err)
      os.exit(1)
    end
  end

  if args.symbol then
    local res, err = redis.request(redis_params, redis_attrs,
        { 'HSET', tostring(prefix), 's', tostring(args.symbol) })
    if not res then
      logger.errx('Incorrect arguments for redis request for symbol or prefix is incorrect: %s', err)
      os.exit(1)
    end
  end

  if args.dynb then
    local res, err = redis.request(redis_params, redis_attrs,
        { 'HSET', tostring(prefix), 'db', tostring(args.dynb) })
    if not res then
      logger.errx('Incorrect arguments for redis request for dynamic burst or prefix is incorrect: %s', err)
      os.exit(1)
    end
  end

  if args.dynr then
    local res, err = redis.request(redis_params, redis_attrs,
        { 'HSET', tostring(prefix), 'dr', tostring(args.dynr) })
    if not res then
      logger.errx('Incorrect arguments for redis request for dynamic rate or prefix is incorrect: %s', err)
      os.exit(1)
    end
  end

end

local function unblock_bucket_helper(prefix)
  local res, err = redis.request(redis_params, redis_attrs, { 'HSET', tostring(prefix), 'b', 0 })
  if not res then
    logger.errx('Failed to unblock bucket: %s', err)
    os.exit(1)
  end
end

local function unblock_buckets_handler(args)
  for i = 1, args.quantity do
    local res, prefix = redis.request(redis_params, redis_attrs,
        { 'ZRANGE', lfb_cache_prefix, -i, -i })
    if not res then
      logger.errx('Redis request parameters are wrong: %s', prefix)
      os.exit(1)
    end
    unblock_bucket_helper(prefix)
  end
end

local function unblock_bucket_handler(args)
  if (args.prefix == nil or args.prefix == "") then
    unblock_buckets_handler(args)
  end
  unblock_bucket_helper(args.prefix)
end

local command_handlers = {
  track = track_limits_handler,
  upgrade = upgrade_bucket_handler,
  unblock = unblock_bucket_handler
}

local function handler(args)
  local function load_config(opts)
    local _r, err = rspamd_config:load_ucl(opts['config'])

    if not _r then
      logger.errx('cannot parse %s: %s', opts['config'], err)
      os.exit(1)
    end

    _r, err = rspamd_config:parse_rcl({ 'logging', 'worker' })
    if not _r then
      logger.errx('cannot process %s: %s', opts['config'], err)
      os.exit(1)
    end
  end
  local cmd_opts = parser:parse(args)
  load_config(cmd_opts)

  redis_params = redis.parse_redis_server('ratelimit')
  if not redis_params then
    logger.errx(rspamd_config, 'no servers are specified, cannot work with rate limits')
    os.exit(1)
  end

  local f = command_handlers[cmd_opts.command]
  if not f then
    parser:error(string.format("command isn't implemented: %s",
        cmd_opts.command))
  end
  f(cmd_opts)
end

return {
  name = 'ratelimit',
  aliases = { 'ratelimit' },
  handler = handler,
  description = parser._description
}