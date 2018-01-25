local logger = require "rspamd_logger"

local exports = {}

-- This function parses redis server definition using either
-- specific server string for this module or global
-- redis section
local function rspamd_parse_redis_server(module_name, module_opts, no_fallback)

  local result = {}
  local default_port = 6379
  local default_timeout = 1.0
  local upstream_list = require "rspamd_upstream_list"

  local function try_load_redis_servers(options)
    -- Try to get read servers:
    local upstreams_read, upstreams_write

    if options['read_servers'] then
      upstreams_read = upstream_list.create(rspamd_config,
        options['read_servers'], default_port)
    elseif options['servers'] then
      upstreams_read = upstream_list.create(rspamd_config,
        options['servers'], default_port)
    elseif options['server'] then
      upstreams_read = upstream_list.create(rspamd_config,
        options['server'], default_port)
    end

    if upstreams_read then
      if options['write_servers'] then
        upstreams_write = upstream_list.create(rspamd_config,
          options['write_servers'], default_port)
      else
        upstreams_write = upstreams_read
      end
    end

    -- Store options
    if not result['timeout'] or result['timeout'] == default_timeout then
      if options['timeout'] then
        result['timeout'] = tonumber(options['timeout'])
      else
        result['timeout'] = default_timeout
      end
    end

    if options['prefix'] and not result['prefix'] then
      result['prefix'] = options['prefix']
    end

    if not result['db'] then
      if options['db'] then
        result['db'] = tostring(options['db'])
      elseif options['dbname'] then
        result['db'] = tostring(options['dbname'])
      end
    end
    if options['password'] and not result['password'] then
      result['password'] = options['password']
    end

    if upstreams_write and upstreams_read then
      result.read_servers = upstreams_read
      result.write_servers = upstreams_write

      return true
    end

    return false
  end

  -- Try local options
  local opts
  if not module_opts then
    opts = rspamd_config:get_all_opt(module_name)
  else
    opts = module_opts
  end
  local ret

  if opts then
    if opts.redis then
      ret = try_load_redis_servers(opts.redis, result)

      if ret then
        return result
      end
    end

    ret = try_load_redis_servers(opts, result)

    if ret then
      return result
    end
  end

  if no_fallback then return nil end

  -- Try global options
  opts = rspamd_config:get_all_opt('redis')

  if opts then
    if opts[module_name] then
      ret = try_load_redis_servers(opts[module_name], result)
      if ret then
        return result
      end
    else
      ret = try_load_redis_servers(opts, result)

      -- Exclude disabled
      if opts['disabled_modules'] then
        for _,v in ipairs(opts['disabled_modules']) do
          if v == module_name then
            logger.infox(rspamd_config, "NOT using default redis server for module %s: it is disabled",
              module_name)

              return nil
          end
        end
      end

      if ret then
        logger.infox(rspamd_config, "using default redis server for module %s",
          module_name)
      end
    end
  end

  if result.read_servers then
    return result
  else
    return nil
  end
end

exports.rspamd_parse_redis_server = rspamd_parse_redis_server
exports.parse_redis_server = rspamd_parse_redis_server

-- Performs async call to redis hiding all complexity inside function
-- task - rspamd_task
-- redis_params - valid params returned by rspamd_parse_redis_server
-- key - key to select upstream or nil to select round-robin/master-slave
-- is_write - true if need to write to redis server
-- callback - function to be called upon request is completed
-- command - redis command
-- args - table of arguments
local function rspamd_redis_make_request(task, redis_params, key, is_write, callback, command, args)
  local addr
  local function rspamd_redis_make_request_cb(err, data)
    if err then
      addr:fail()
    else
      addr:ok()
    end
    callback(err, data, addr)
  end
  if not task or not redis_params or not callback or not command then
    return false,nil,nil
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

  local options = {
    task = task,
    callback = rspamd_redis_make_request_cb,
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
  return ret,conn,addr
end

exports.rspamd_redis_make_request = rspamd_redis_make_request
exports.redis_make_request = rspamd_redis_make_request

local function redis_make_request_taskless(ev_base, cfg, redis_params, key, is_write, callback, command, args)
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
    logger.errx(cfg, 'cannot select server to make redis request')
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
    logger.errx('cannot execute redis request')
  end
  return ret,conn,addr
end

exports.rspamd_redis_make_request_taskless = redis_make_request_taskless
exports.redis_make_request_taskless = redis_make_request_taskless

return exports
