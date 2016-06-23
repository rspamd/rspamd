
-- This function parses redis server definition using either
-- specific server string for this module or global
-- redis section
function rspamd_parse_redis_server(module_name)

  local default_port = 6379
  local default_timeout = 1.0
  local logger = require "rspamd_logger"
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

    if upstreams_write and upstreams_read then
      local ret = {
        read_servers = upstreams_read,
        write_servers = upstreams_write,
      }
      ret['timeout'] = default_timeout
      if options['timeout'] then
        ret['timeout'] = tonumber(options['timeout'])
      end
      if options['prefix'] then
        ret['prefix'] = options['prefix']
      end
      if options['db'] then
        ret['db'] = options['db']
      elseif options['dbname'] then
        ret['db'] = options['dbname']
      end
      if options['password'] then
        ret['password'] = options['password']
      end
      return ret
    end

    return nil
  end

  local opts = rspamd_config:get_all_opt(module_name)
  local ret

  if opts then
    ret = try_load_redis_servers(opts)
  end

  if ret then
    return ret
  end

  opts = rspamd_config:get_all_opt('redis')

  if opts then
    if opts[module_name] then
      ret = try_load_redis_servers(opts[module_name])
      if ret then
        return ret
      end
    else
      ret = try_load_redis_servers(opts)

      if ret then
        logger.infox(rspamd_config, "using default redis server for module %s",
          module_name)
      end
    end
  end

  return ret
end

-- Performs async call to redis hiding all complexity inside function
-- task - rspamd_task
-- redis_params - valid params returned by rspamd_parse_redis_server
-- key - key to select upstream or nil to select round-robin/master-slave
-- is_write - true if need to write to redis server
-- callback - function to be called upon request is completed
-- command - redis command
-- args - table of arguments
function rspamd_redis_make_request(task, redis_params, key, is_write, callback, command, args)
  if not task or not redis_params or not callback or not command then
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
    logger.errx(task, 'cannot select server to make redis request')
  end

  local options = {
    task = task,
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
  return ret,conn,addr
end

function rspamd_str_split(s, sep)
  local lpeg = require "lpeg"
  sep = lpeg.P(sep)
  local elem = lpeg.C((1 - sep)^0)
  local p = lpeg.Ct(elem * (sep * elem)^0)   -- make a table capture
  return lpeg.match(p, s)
end
