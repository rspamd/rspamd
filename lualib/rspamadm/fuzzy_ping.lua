--[[
Copyright (c) 2023, Vsevolod Stakhov <vsevolod@rspamd.com>

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

local argparse = require "argparse"
local ansicolors = require "ansicolors"
local rspamd_logger = require "rspamd_logger"
local lua_util = require "lua_util"

local E = {}

local parser = argparse()
    :name 'rspamadm fuzzy_ping'
    :description 'Pings fuzzy storage'
    :help_description_margin(30)
parser:option "-c --config"
      :description "Path to config file"
      :argname("<cfg>")
      :default(rspamd_paths["CONFDIR"] .. "/" .. "rspamd.conf")
parser:option "-r --rule"
      :description "Storage to ping (must be configured in Rspamd configuration)"
      :argname("<name>")
      :default("rspamd.com")
parser:option "-f --flood"
      :description "Flood mode (send requests as fast as possible)"
      :argname("<count>")
      :convert(tonumber)
      :default(10)
parser:option "-t --timeout"
      :description "Timeout for requests"
      :argname("<timeout>")
      :convert(tonumber)
      :default(5)
parser:option "-n --number"
      :description "Timeout for requests"
      :argname("<number>")
      :convert(tonumber)
      :default(5)
parser:flag "-l --list"
      :description "List configured storages"

local function load_config(opts)
  local _r, err = rspamd_config:load_ucl(opts['config'])

  if not _r then
    rspamd_logger.errx('cannot parse %s: %s', opts['config'], err)
    os.exit(1)
  end

  -- Init the real structure excluding logging and workers
  _r, err = rspamd_config:parse_rcl({ 'logging', 'worker' })
  if not _r then
    rspamd_logger.errx('cannot process %s: %s', opts['config'], err)
    os.exit(1)
  end

  _r, err = rspamd_config:init_modules()
  if not _r then
    rspamd_logger.errx('cannot init modules from %s: %s', opts['config'], err)
    os.exit(1)
  end
end

local function highlight(fmt, ...)
  return ansicolors.white .. string.format(fmt, ...) .. ansicolors.reset
end

local function print_storages(rules)
  for n, rule in pairs(rules) do
    print(highlight('Rule: %s', n))
    print(string.format("\tRead only: %s", rule.read_only))
    print(string.format("\tServers: %s", table.concat(lua_util.values(rule.servers), ',')))
    print("\tFlags:")

    for fl, id in pairs(rule.flags or E) do
      print(string.format("\t\t%s: %s", fl, id))
    end
  end
end

local function handler(args)
  local opts = parser:parse(args)

  load_config(opts)

  if opts.list then
    local storages = rspamd_plugins.fuzzy_check.list_storages(rspamd_config)
    print_storages(storages)
    os.exit(0)
  end


end

return {
  name = 'fuzzy_ping',
  aliases = { 'fuzzyping' },
  handler = handler,
  description = parser._description
}