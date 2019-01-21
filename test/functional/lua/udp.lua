--[[[
-- Just a test for UDP API
--]]

local rspamd_udp = require "rspamd_udp"
local logger = require "rspamd_logger"

-- [[ old fashioned callback api ]]
local function simple_udp_async_symbol(task)
  logger.errx(task, 'udp_symbol: begin')
  local function udp_cb(success, data)
    logger.errx(task, 'udp_cb: got reply: %s', data)

    if success then
      task:insert_result('UDP_SUCCESS', 1.0, data)
    else
      task:insert_result('UDP_FAIL', 1.0, data)
    end
  end
  rspamd_udp:sendto({
    task = task,
    callback = udp_cb,
    host = '127.0.0.1',
    data = {'hello', 'world'},
    port = 5005,
  })
end

rspamd_config:register_symbol({
  name = 'UDP_SUCCESS',
  score = 0.0,
  callback = simple_udp_async_symbol,
})

local function send_only_udp(task)
  logger.errx(task, 'udp_symbol_sendonly: begin')
  if rspamd_udp:sendto({
    task = task,
    host = '127.0.0.1',
    data = {'hoho'},
    port = 5005,
  }) then

    task:insert_result('UDP_SENDTO', 1.0)
  end
end

rspamd_config:register_symbol({
  name = 'UDP_SENDTO',
  score = 0.0,
  callback = send_only_udp,
})

local function udp_failed_cb(task)
  logger.errx(task, 'udp_failed_cb: begin')
  local function udp_cb(success, data)
    logger.errx(task, 'udp_failed_cb: got reply: %s', data)

    if success then
      task:insert_result('UDP_SUCCESS', 1.0, data)
    else
      task:insert_result('UDP_FAIL', 1.0, data)
    end
  end
  rspamd_udp:sendto({
    task = task,
    callback = udp_cb,
    host = '127.0.0.1',
    data = {'hello', 'world'},
    port = 5006,
    retransmits = 2,
    timeout = 0.1,
  })
end

rspamd_config:register_symbol({
  name = 'UDP_FAIL',
  score = 0.0,
  callback = udp_failed_cb,
})
-- ]]
