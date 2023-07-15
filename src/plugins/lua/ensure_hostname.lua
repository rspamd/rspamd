local rspamd_logger = require "rspamd_logger"
local lua_util = require "lua_util"

if confighelp then
  return
end

local function ensure_hostname(task)
  local hostname = task:get_hostname()
  if hostname then
    return
  end

  -- If the hostname wasn't provided by the MTA, do a reverse lookup of the IP to find it.
  local ip = task:get_ip()
  if not (ip and ip:is_valid()) then
    rspamd_logger.errx(task, 'ip for task is not valid')
    task:insert_result('HFILTER_HOSTNAME_UNKNOWN', 1.00)
    return false
  end

  rspamd_logger.infox('looking up hostname for ip %s', ip:to_string())

  local function dns_cb(_, to_resolve, results, err)
    if err and (err ~= 'requested record is not found' and err ~= 'no records with this name') then
      rspamd_logger.errx(task, 'error looking up %s: %s', to_resolve, err)
      task:insert_result('ENSURE_HOSTNAME_FAILED', 0.00)
    end
    if not results then
      rspamd_logger.errx(task, 'no results when looking up %s: %s', to_resolve, err)
      task:insert_result('ENSURE_HOSTNAME_NOTFOUND', 0.00)
    end
    rspamd_logger.infox('found result for %s: %s', to_resolve, results[1])
    task:set_hostname(results[1])
    task:insert_result('ENSURE_HOSTNAME_FOUND', 0.00)
  end

  task:get_resolver():resolve_ptr({
    task = task,
    name = ip:to_string(),
    callback = dns_cb,
    forced = true
  })
end

local opts = rspamd_config:get_all_opt('ensure_hostname')
if opts then
  local id = rspamd_config:register_symbol({
    name = 'ENSURE_HOSTNAME_FOUND',
    type = 'prefilter',
    callback = ensure_hostname,
    priority = lua_util.symbols_priorities.high,
    flags = 'empty,nostat',
    augmentations = { lua_util.dns_timeout_augmentation(rspamd_config) },
  })
  rspamd_config:register_symbol {
    name = 'ENSURE_HOSTNAME_NOTFOUND',
    parent = id,
    type = 'virtual',
    flags = 'empty,nostat',
    score = 0,
  }
  rspamd_config:register_symbol {
    name = 'ENSURE_HOSTNAME_FAILED',
    parent = id,
    type = 'virtual',
    flags = 'empty,nostat',
    score = 0,
  }
end
