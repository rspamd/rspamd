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

local N = 'dcc'
local symbol_bulk = "DCC_BULK"
local opts = rspamd_config:get_all_opt(N)
local rspamd_logger = require "rspamd_logger"
local lua_util = require "lua_util"
local tcp = require "rspamd_tcp"
local upstream_list = require "rspamd_upstream_list"
local fun = require "fun"

if confighelp then
  rspamd_config:add_example(nil, 'dcc',
    "Check messages for 'bulkiness' using DCC",
    [[
dcc {
  socket = "/var/dcc/dccifd"; # Unix socket
  servers = "127.0.0.1:10045" # OR TCP upstreams
  timeout = 2s; # Timeout to wait for checks
}
]])
  return
end

local function check_dcc (task)
  -- Connection
  local client = '0.0.0.0'
  local client_ip = task:get_from_ip()
  local dcc_upstream
  local upstream
  local addr
  local port
  local retransmits = 2

  if opts['servers'] then
    dcc_upstream = upstream_list.create(rspamd_config, opts['servers'])
    upstream = dcc_upstream:get_upstream_round_robin()
    addr = upstream:get_addr()
    port = addr:get_port()
  else
    lua_util.debugm(N, task, 'using socket %s', opts['socket'])
    addr = opts['socket']
  end

  if client_ip and client_ip:is_valid() then
    client = client_ip:to_string()
  end
  local client_host = task:get_hostname()
  if client_host then
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
    local r = table.concat(fun.totable(fun.map(function(rcpt)
      return rcpt['addr'] end,
    rcpts)), '\n')
    if r then
      envrcpt = r
    end
  end

  -- Callback function to receive async result from DCC
  local function cb(err, data)

    if err then
      if retransmits > 0 then
        retransmits = retransmits - 1
        -- Select a different upstream or the socket again
        if opts['servers'] then
          upstream = dcc_upstream:get_upstream_round_robin()
          addr = upstream:get_addr()
          port = addr:get_port()
        else
          addr = opts['socket']
        end

        lua_util.debugm(N, task, "sending query to %s:%s",tostring(addr), port)

        data = {
          "header\n",
          client .. "\n",
          helo .. "\n",
          envfrom .. "\n",
          envrcpt .. "\n",
          "\n",
          task:get_content()
        }

        tcp.request({
          task = task,
          host = tostring(addr),
          port = port or 1,
          timeout = opts['timeout'] or 2.0,
          shutdown = true,
          data = data,
          callback = cb
        })

      else
        rspamd_logger.errx(task, 'failed to scan, maximum retransmits exceed')
        if upstream then upstream:fail() end
      end
    else
      -- Parse the response
      if upstream then upstream:ok() end
      local _,_,result,disposition,header = tostring(data):find("(.-)\n(.-)\n(.-)\n")
      lua_util.debugm(N, task, 'DCC result=%1 disposition=%2 header="%3"',
        result, disposition, header)

      if header then
        local _,_,info = header:find("; (.-)$")
        if (result == 'R') then
          -- Reject
          task:insert_result(symbol_bulk, 1.0, info)
        elseif (result == 'T') then
          -- Temporary failure
          rspamd_logger.warnx(task, 'DCC returned a temporary failure result')
        else
          if result ~= 'A' and result ~= 'G' and result ~= 'S' then
            -- Unknown result
            rspamd_logger.warnx(task, 'DCC result error: %1', result);
          end
        end
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

  rspamd_logger.warnx(task, "sending to %s:%s",tostring(addr), port)

  tcp.request({
    task = task,
    host = tostring(addr),
    port = port or 1,
    timeout = opts['timeout'] or 2.0,
    shutdown = true,
    data = data,
    callback = cb
  })
end

-- Configuration

-- WORKAROUND for deprecated host and port settings
if opts['host'] ~= nil and opts['port'] ~= nil then
  opts['servers'] = opts['host'] .. ':' .. opts['port']
  rspamd_logger.warnx(rspamd_config, 'Using host and port parameters is deprecated. '..
   'Please use servers = "%s:%s"; instead', opts['host'], opts['port'])
end
if opts['host'] ~= nil and not opts['port'] then
  opts['socket'] = opts['host']
  rspamd_logger.warnx(rspamd_config, 'Using host parameters is deprecated. '..
   'Please use socket = "%s"; instead', opts['host'])
end
-- WORKAROUND for deprecated host and port settings

if opts and ( opts['servers'] or opts['socket'] ) then
  rspamd_config:register_symbol({
    name = symbol_bulk,
    callback = check_dcc
  })
  rspamd_config:set_metric_symbol({
    group = N,
    score = 2.0,
    description = 'Detected as bulk mail by DCC',
    one_shot = true,
    name = symbol_bulk
  })
else
  lua_util.disable_module(N, "config")
  rspamd_logger.infox('DCC module not configured');
end
