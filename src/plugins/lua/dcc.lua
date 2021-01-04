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
local symbol = "DCC_REJECT"
local opts = rspamd_config:get_all_opt(N)
local lua_util = require "lua_util"
local rspamd_logger = require "rspamd_logger"
local dcc = require("lua_scanners").filter('dcc').dcc


if confighelp then
  rspamd_config:add_example(nil, 'dcc',
    "Check messages for 'bulkiness' using DCC",
    [[
dcc {
  socket = "/var/dcc/dccifd"; # Unix socket
  servers = "127.0.0.1:10045" # OR TCP upstreams
  timeout = 2s; # Timeout to wait for checks
  body_max = 999999; # Bulkness threshold for body
  fuz1_max = 999999; # Bulkness threshold for fuz1
  fuz2_max = 999999; # Bulkness threshold for fuz2
}
]])
  return
end

local rule

local function check_dcc (task)
  dcc.check(task, task:get_content(), nil, rule)
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

if not opts.symbol_bulk then opts.symbol_bulk = symbol_bulk end
if not opts.symbol then opts.symbol = symbol end

rule = dcc.configure(opts)

if rule then
  local id = rspamd_config:register_symbol({
    name = 'DCC_CHECK',
    callback = check_dcc,
    type = 'callback',
  })
  rspamd_config:register_symbol{
    type = 'virtual',
    parent = id,
    name = opts.symbol
  }
  rspamd_config:register_symbol{
    type = 'virtual',
    parent = id,
    name = opts.symbol_bulk
  }
  rspamd_config:register_symbol{
    type = 'virtual',
    parent = id,
    name = 'DCC_FAIL'
  }
  rspamd_config:set_metric_symbol({
    group = N,
    score = 1.0,
    description = 'Detected as bulk mail by DCC',
    one_shot = true,
    name = opts.symbol_bulk,
  })
  rspamd_config:set_metric_symbol({
    group = N,
    score = 2.0,
    description = 'Rejected by DCC',
    one_shot = true,
    name = opts.symbol,
  })
  rspamd_config:set_metric_symbol({
    group = N,
    score = 0.0,
    description = 'DCC failure',
    one_shot = true,
    name = 'DCC_FAIL',
  })
else
  lua_util.disable_module(N, "config")
  rspamd_logger.infox('DCC module not configured');
end
