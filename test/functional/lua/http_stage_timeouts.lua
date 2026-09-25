local rspamd_http = require "rspamd_http"

local ports = {
  http = tonumber(rspamd_env and rspamd_env.PORT_DUMMY_HTTP_STAGES) or 18084,
  https = tonumber(rspamd_env and rspamd_env.PORT_DUMMY_HTTPS_STAGES) or 18085,
}
local silent_port = tonumber(rspamd_env and rspamd_env.PORT_DUMMY_SILENT) or 18086

-- The server holds a slow request for DELAY: a stage timeout of SHORT fires on it, one of LONG does not
local DELAY, SHORT, LONG = 3, 1, 6

-- `before` is the stage ahead of the write one: connect for plain HTTP, the handshake for TLS
local cases = {
  ['read'] = { path = '/answer', before = SHORT, write = LONG, read = LONG },
  ['read-timeout'] = { path = '/answer', before = LONG, write = LONG, read = SHORT },
  ['write'] = { path = '/no-read', before = SHORT, write = LONG, read = LONG },
  ['write-timeout'] = { path = '/no-read', before = LONG, write = SHORT, read = LONG },
  ['handshake-timeout'] = { path = '/answer', before = SHORT, write = LONG, read = LONG, silent = true },
}

-- Larger than the socket buffers, so a server that does not read it blocks the write
local large_body

local function stage_symbol(task)
  local name = tostring(task:get_request_header('Stage-Case'))
  local proto = tostring(task:get_request_header('Stage-Proto'))
  -- 'prime' opens a pooled connection, 'run' is the request on it; no step means a fresh connection
  local step = task:get_request_header('Stage-Step')
  step = step and tostring(step)
  local c = cases[name]

  local path, delay = c.path, DELAY
  if step == 'prime' then
    path, delay = '/answer', 0
  end
  local body = 'x'
  if path == '/no-read' then
    large_body = large_body or string.rep('x', 16 * 1024 * 1024)
    body = large_body
  end

  local url = string.format('%s://127.0.0.1:%d%s?delay=%d&tag=%s-%s-%s', proto,
      c.silent and silent_port or ports[proto], path, delay, name, proto, step or 'fresh')
  if step == 'run' then
    -- Leave the pool empty for the next case
    url = url .. '&close=1'
  end

  local req = {
    url = url,
    task = task,
    method = 'post',
    body = body,
    timeout = 8,
    write_timeout = c.write,
    read_timeout = c.read,
    keepalive = step ~= nil,
    no_ssl_verify = true,
    callback = function(err, code)
      task:insert_result('HTTP_STAGE_RESULT', 1.0, err or tostring(code))
    end,
  }
  if proto == 'https' then
    req.ssl_timeout = c.before
  else
    req.connect_timeout = c.before
  end

  rspamd_http.request(req)
end

rspamd_config:register_symbol({
  name = 'HTTP_STAGE_TIMEOUT_TEST',
  score = 1.0,
  callback = stage_symbol,
  no_squeeze = true,
})
