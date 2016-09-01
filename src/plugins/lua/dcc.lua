--[[
Copyright (c) 2016, Steve Freegard <steve.freegard@fsl.com>
Copyright (c) 2016, Vsevolod Stakhov

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
]]--

-- Check messages for 'bulkiness' using DCC

local symbol_bulk = "DCC_BULK"
local opts = rspamd_config:get_all_opt('dcc')
local logger = require "rspamd_logger"
local tcp = require "rspamd_tcp"
require "fun" ()

local function check_dcc (task)
  -- Connection
  local client = '0.0.0.0'
  local client_ip = task:get_from_ip()
  if client_ip and client_ip:is_valid() then
    client = client_ip:to_string()
  end
  local client_host = task:get_hostname()
  if client_host and client_host ~= 'unknown' then
    client = client .. "\r" .. client_host
  end

  -- HELO
  local helo = task:get_helo() or ''

  -- Envelope From
  local ef = task:get_from()
  local envfrom = 'test@example.com'
  if ef and ef[1] then
    envfrom = ef[1]['addr']
  end

  -- Envelope To
  local envrcpt = 'test@example.com'
  local rcpts = task:get_recipients();
  if rcpts then
    local r = table.concat(totable(map(function(rcpt)
      return rcpt['addr'] end,
    rcpts)), '\n')
    if r then
      envrcpt = r
    end
  end

  -- Callback function to receive async result from DCC
  local function cb(err, data)
    if (err) then
      logger.warnx(task, 'DCC error: %1', err)
      return
    end
    -- Parse the response
    local _,_,result,disposition,header = tostring(data):find("(.-)\n(.-)\n(.-)\n")
    logger.debugx(task, 'DCC result=%1 disposition=%2 header="%3"',
      result, disposition, header)

    if header then
      local _,_,info = header:find("; (.-)$")
      if (result == 'A') then
      -- Accept
      elseif (result == 'G') then
      -- Greylist
      elseif (result == 'R') then
        -- Reject
        task:insert_result(symbol_bulk, 1.0, info)
      elseif (result == 'S') then
      -- Accept for some recipients only
      elseif (result == 'T') then
        -- Temporary failure
        logger.warnx(task, 'DCC returned a temporary failure result')
      else
        -- Unknown result
        logger.warnx(task, 'DCC result error: %1', result);
      end
    end
  end

  -- Build the DCC query
  -- https://www.dcc-servers.net/dcc/dcc-tree/dccifd.html#Protocol
  local data = {
    "header\n",
    client .. "\n",
    helo .. "\n",
    envfrom .. "\n",
    envrcpt .. "\n",
    "\n",
    task:get_content()
  }

  logger.debugx(task, 'sending to dcc: client=%1 helo="%2" envfrom="%3" envrcpt="%4"',
    client, helo, envfrom, envrcpt)

  tcp.request({
    task = task,
    host = opts['host'],
    port = opts['port'] or 1,
    shutdown = true,
    data = data,
    callback = cb
  })
end

-- Configuration
if opts and opts['host'] then
  if opts['enabled'] == false then
    logger.info('Module is disabled')
    return
  end
  rspamd_config:register_symbol({
    name = symbol_bulk,
    callback = check_dcc
  })
  rspamd_config:set_metric_symbol({
    group = 'dcc',
    score = 2.0,
    description = 'Detected as bulk mail by DCC',
    one_shot = true,
    name = symbol_bulk
  })
else
  logger.infox('DCC module not configured');
end
