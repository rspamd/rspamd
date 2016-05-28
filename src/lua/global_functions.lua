
-- This function parses redis server definition using either
-- specific server string for this module or global
-- redis section
function rspamd_parse_redis_server(module_name)

  local default_port = 6379
  local logger = require "rspamd_logger"
  local upstream_list = require "rspamd_upstream_list"

  local function try_load_redis_servers(options)
    local key = options['servers']

    if not key then key = options['server'] end

    if key then
      local upstreams = upstream_list.create(rspamd_config, key, default_port)

      if upstreams then
        return upstreams
      end
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

function rspamd_str_split(s, sep)
  local lpeg = require "lpeg"
  sep = lpeg.P(sep)
  local elem = lpeg.C((1 - sep)^0)
  local p = lpeg.Ct(elem * (sep * elem)^0)   -- make a table capture
  return lpeg.match(p, s)
end