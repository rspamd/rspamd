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
local dcc = require("lua_scanners").filter('dcc').dcc


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

if not opts.symbol then opts.symbol = symbol_bulk end
rule = dcc.configure(opts)

if rule then
  rspamd_config:register_symbol({
    name = opts.symbol,
    callback = check_dcc
  })
  rspamd_config:set_metric_symbol({
    group = N,
    score = 2.0,
    description = 'Detected as bulk mail by DCC',
    one_shot = true,
    name = opts.symbol,
  })
else
  lua_util.disable_module(N, "config")
  rspamd_logger.infox('DCC module not configured');
end
