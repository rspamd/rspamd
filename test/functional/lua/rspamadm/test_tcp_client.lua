local logger = require "rspamd_logger"
local tcp_sync = require "lua_tcp_sync"

-- dummy_http port comes from the test harness. This script runs under
-- `rspamadm lua` (not the rspamd config loader), so prefer the exported
-- RSPAMD_PORT_DUMMY_HTTP env var, then rspamd_env, then the historical
-- literal for ad-hoc runs.
local http_port = tonumber(os.getenv('RSPAMD_PORT_DUMMY_HTTP'))
  or tonumber(rspamd_env and rspamd_env.PORT_DUMMY_HTTP) or 18080

local is_ok, connection = tcp_sync.connect {
  config = rspamd_config,
  ev_base = rspamadm_ev_base,
  session = rspamadm_session,
  host = '127.0.0.1',
  timeout = 20,
  port = http_port,
}
if not is_ok then
  logger.errx(rspamd_config, 'connect error: %1', connection)
  return
end
local err
is_ok, err = connection:write(string.format('POST /request HTTP/1.1\r\nConnection: close\r\n\r\n'))

logger.info('write %1, %2', is_ok, err)
if not is_ok then
  logger.errx(rspamd_config, 'write error: %1', err)
  return
end

local content_length, content

while true do
  local header_line
  is_ok, header_line = connection:read_until("\r\n")
  if not is_ok then
    logger.errx(rspamd_config, 'failed to get header: %1', header_line)
    return
  end

  if header_line == "" then
    logger.info('headers done')
    break
  end

  local value
  local header = header_line:gsub("([%w-]+): (.*)",
      function (h, v) value = v; return h:lower() end)

  logger.info('parsed header: %1 -> "%2"', header, value)

  if header == "content-length" then
    content_length = tonumber(value)
  end

end

if content_length then
  is_ok, content = connection:read_bytes(content_length)
  if is_ok then
  end
else
  is_ok, content = connection:read_until_eof()
  if is_ok then
  end
end
logger.info('(is_ok: %1) content [%2 bytes] %3', is_ok, content_length, content)


print(content)
