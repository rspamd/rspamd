local rspamd_http = require "rspamd_http"
local rspamd_logger = require "rspamd_logger"

local function http_symbol(task)

  local url = tostring(task:get_request_header('url'))
  local method = tostring(task:get_request_header('method'))
  task:insert_result('method_' .. method, 1.0)

  local function http_callback(err, code, body)
    if err then
      rspamd_logger.errx('http_callback error: ' .. err)
      task:insert_result('HTTP_ERROR', 1.0, err)
    else
      task:insert_result('HTTP_' .. code, 1.0, body)
    end
  end

  local function http_dns_callback(err, code, body)
    if err then
      rspamd_logger.errx('http_dns_callback error: ' .. err)
      task:insert_result('HTTP_DNS_ERROR', 1.0, err)
    else
      task:insert_result('HTTP_DNS_' .. code, 1.0, body)
    end
  end

  rspamd_logger.errx(task, 'do http request with callback')
  rspamd_http.request({
    url = 'http://127.0.0.1:18080' .. url,
    task = task,
    method = method,
    callback = http_callback,
    timeout = 1,
  })

  --[[ request to this address involved DNS resolver subsystem ]]
  rspamd_logger.errx(task, 'do http request with callback + dns resolving')
  rspamd_http.request({
    url = 'http://site.resolveme:18080' .. url,
    task = task,
    method = method,
    callback = http_dns_callback,
    timeout = 1,
  })

  rspamd_logger.errx(task, 'rspamd_http.request[before]')

  local err, response = rspamd_http.request({
    url = 'http://127.0.0.1:18080' .. url,
    task = task,
    method = method,
    timeout = 1,
  })
  rspamd_logger.errx(task, 'rspamd_http.request[done] err: %1 response:%2', err, response)

  if not err then
    task:insert_result('HTTP_CORO_' .. response.code, 1.0, response.content)
  else
    task:insert_result('HTTP_CORO_ERROR', 1.0, err)
  end

  rspamd_logger.errx(task, 'do http request after coroutine finished')
  err, response = rspamd_http.request({
    url = 'http://site.resolveme:18080' .. url,
    task = task,
    method = method,
    timeout = 1,
  })

  if not err then
    task:insert_result('HTTP_CORO_DNS_' .. response.code, 1.0, response.content)
  else
    task:insert_result('HTTP_CORO_DNS_ERROR', 1.0, err)
  end
end


local function finish(task)
  rspamd_logger.errx('function finish')
  local err, response = rspamd_http.request({
    url = 'http://site.resolveme:18080/timeout',
    task = task,
    method = 'get',
    timeout = 1,
  })
  if err then
    task:insert_result('HTTP_CORO_DNS_FINISH_ERROR', 1.0, err)
  else
    task:insert_result('HTTP_CORO_DNS_FINISH_' .. response.code, 1.0, response.content)
  end
end

local function periodic(cfg, ev_base)
  local err, response = rspamd_http.request({
    url = 'http://site.resolveme:18080/request/periodic',
    config = cfg,
  })
  if err then
    rspamd_logger.errx('periodic err ' .. err)
  else
    rspamd_logger.errx('periodic success ' .. response.content)
  end

  return false
end

rspamd_config:register_symbol({
  name = 'SIMPLE_HTTP_TEST',
  score = 1.0,
  callback = http_symbol,
  no_squeeze = true,
  flags = 'coro'
})

local function http_large_symbol(task)
  if task:get_queue_id() == 'SSL Large HTTP request' then
    local data = {}
    for i = 1,2 do
      local st = {}
      for j=1,300000 do
        st[j] = 't'
      end
      data[i] = table.concat(st)
    end
    data[#data + 1] = '\n'

    local function http_callback(err, code, body)
      if err then
        rspamd_logger.errx('http_callback error: ' .. err)
        task:insert_result('HTTP_ERROR', 1.0, err)
      else
        task:insert_result('HTTP_SSL_LARGE', 1.0)
      end
    end
    rspamd_http.request({
      url = 'https://127.0.0.1:18081/',
      task = task,
      method = 'post',
      callback = http_callback,
      timeout = 10,
      body = data,
      no_ssl_verify = true,
    })
  end
end
rspamd_config:register_symbol({
  name = 'LARGE_HTTP_TEST',
  score = 1.0,
  callback = http_large_symbol,
  no_squeeze = true,
  flags = 'coro'
})

rspamd_config:register_finish_script(finish)

rspamd_config:add_on_load(function(cfg, ev_base, worker)
  local err, response = rspamd_http.request({
    url = 'http://site.resolveme:18080/request/add_on_load',
    config = cfg,
  })
  if err then
    rspamd_logger.errx('add_on_load err ' .. err)
  else
    rspamd_logger.errx('add_on_load success ' .. response.content)
  end

  rspamd_config:add_periodic(ev_base, 0, periodic, false)
end)
