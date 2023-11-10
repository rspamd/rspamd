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
parser:option "-t --timeout"
      :description "Timeout for requests"
      :argname("<timeout>")
      :convert(tonumber)
      :default(5)
parser:option "-s --server"
      :description "Override server to ping"
      :argname("<name>")
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

local function print_results(results)
  for _, res in ipairs(results) do
    if res.success then
      print(highlight('Server %s: %s ms', res.server, res.latency))
    else
      print(highlight('Server %s: %s', res.server, res.error))
    end
  end
end

local function handler(args)
  local opts = parser:parse(args)

  load_config(opts)

  if opts.list then
    print_storages(rspamd_plugins.fuzzy_check.list_storages(rspamd_config))
    os.exit(0)
  end

  -- Perform ping using a fake task from async stuff provided by rspamadm
  local rspamd_task = require "rspamd_task"

  -- TODO: this task is not cleared at the end, do something about it some day
  local task = rspamd_task.create(rspamd_config, rspamadm_ev_base)
  task:set_session(rspamadm_session)
  task:set_resolver(rspamadm_dns_resolver)

  local replied = 0
  local results = {}

  local function gen_ping_fuzzy_cb(num)
    return function(success, server, latency_or_err)
      rspamd_logger.errx(task, 'pinged %s: %s', server, latency_or_err)
      if not success then
        results[num] = {
          success = false,
          error = latency_or_err,
          server = server,
        }
      else
        results[num] = {
          success = true,
          latency = latency_or_err,
          server = server,
        }
      end

      if replied == opts.number - 1 then
        print_results(results)
      else
        replied = replied + 1
      end
    end
  end

  local function ping_fuzzy(num)
    local ret, err = rspamd_plugins.fuzzy_check.ping_storage(task, gen_ping_fuzzy_cb(num),
        opts.rule, opts.timeout, opts.server)

    if not ret then
      rspamd_logger.errx('cannot ping fuzzy storage: %s', err)
      os.exit(1)
    end
  end

  for i = 1, opts.number do
    ping_fuzzy(i)
  end
end

return {
  name = 'fuzzy_ping',
  aliases = { 'fuzzyping' },
  handler = handler,
  description = parser._description
}