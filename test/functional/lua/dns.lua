local rspamd_dns = require "rspamd_dns"
local logger = require "rspamd_logger"

local function dns_sync_symbol(task)
  local to_resolve = tostring(task:get_request_header('to-resolve'))
  local is_ok, results = rspamd_dns.request({
    task = task,
    type = 'a',
    name = to_resolve ,
  })

  logger.errx(task, "is_ok=%1, results=%2, results[1]=%3", is_ok, results, results[1])

  if not is_ok then
    task:insert_result('DNS_SYNC_ERROR', 1.0, results)
  else
    task:insert_result('DNS_SYNC', 1.0, tostring(results[1]))
  end
end

rspamd_config:register_symbol({
  name = 'SIMPLE_DNS_SYNC',
  score = 1.0,
  callback = dns_sync_symbol,
  no_squeeze = true,
  flags = 'coro',
})


-- Async request
local function dns_symbol(task)
  local function dns_cb(_, to_resolve, results, err)
    logger.errx(task, "_=%1, to_resolve=%2, results=%3, err%4", _, to_resolve, results, err)
    if err then
      task:insert_result('DNS_ERROR', 1.0, err)
    else
      task:insert_result('DNS', 1.0, tostring(results[1]))
    end
  end
  local to_resolve = tostring(task:get_request_header('to-resolve'))

  task:get_resolver():resolve_a({
    task = task,
    name = to_resolve,
    callback = dns_cb
  })
end

rspamd_config:register_symbol({
  name = 'SIMPLE_DNS',
  score = 1.0,
  callback = dns_symbol,
})