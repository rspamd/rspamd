local rspamd_http = require "rspamd_http"

local function http_symbol(task)
  local function http_callback(err, code, body)
    task:insert_result('HTTP_' .. code, 1.0)
  end

  local function http_dns_callback(err, code, body)
    task:insert_result('HTTP_DNS_' .. code, 1.0)
  end

  rspamd_http.request({
    url = 'http://127.0.0.1:18080/request',
    task = task,
    method = 'post',
    callback = http_callback,
  })

  --[[ request to this address involved DNS resolver subsystem ]]
  rspamd_http.request({
    url = 'http://site.resolveme:18080/request',
    task = task,
    method = 'post',
    callback = http_dns_callback,
  })
end

rspamd_config:register_symbol({
  name = 'SIMPLE_TEST',
  score = 1.0,
  callback = http_symbol
})
