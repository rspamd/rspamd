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
parser:flag "-f --flood"
      :description "Flood mode (no waiting for replies)"
parser:flag "-S --silent"
      :description "Silent mode (statistics only)"
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

local function highlight_err(fmt, ...)
  return ansicolors.red .. string.format(fmt, ...) .. ansicolors.reset
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

local function std_mean(tbl)
  local function mean()
    local sum = 0
    local count = 0

    for _, v in ipairs(tbl) do
      sum = sum + v
      count = count + 1
    end

    return (sum / count)
  end

  local m
  local vm
  local sum = 0
  local count = 0
  local result

  m = mean(tbl)

  for _, v in ipairs(tbl) do
    vm = v - m
    sum = sum + (vm * vm)
    count = count + 1
  end

  result = math.sqrt(sum / (count - 1))

  return result, m
end

local function maxmin(tbl)
  local max = -math.huge
  local min = math.huge

  for _, v in ipairs(tbl) do
    max = math.max(max, v)
    min = math.min(min, v)
  end

  return max, min
end

local function print_results(results)
  local servers = {}
  local err_servers = {}
  for _, res in ipairs(results) do
    if res.success then
      if servers[res.server] then
        table.insert(servers[res.server], res.latency)
      else
        servers[res.server] = { res.latency }
      end
    else
      if err_servers[res.server] then
        err_servers[res.server] = err_servers[res.server] + 1
      else
        err_servers[res.server] = 1
      end
      -- For the case if no successful replies are detected
      if not servers[res.server] then
        servers[res.server] = {}
      end
    end
  end

  for s, l in pairs(servers) do
    local total = #l + (err_servers[s] or 0)
    print(highlight('Summary for %s: %d packets transmitted, %d packets received, %.1f%% packet loss',
        s, total, #l, (total - #l) * 100.0 / total))
    local mean, std = std_mean(l)
    local max, min = maxmin(l)
    print(string.format('round-trip min/avg/max/std-dev = %.2f/%.2f/%.2f/%.2f ms',
        min, mean,
        max, std))
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
  local ping_fuzzy

  local function gen_ping_fuzzy_cb(num)
    return function(success, server, latency_or_err)
      if not success then
        if not opts.silent then
          print(highlight_err('error from %s: %s', server, latency_or_err))
        end
        results[num] = {
          success = false,
          error = latency_or_err,
          server = tostring(server),
        }
      else
        if not opts.silent then
          local adjusted_latency = math.floor(latency_or_err * 1000) * 1.0 / 1000;
          print(highlight('reply from %s: %s ms', server, adjusted_latency))

        end
        results[num] = {
          success = true,
          latency = latency_or_err,
          server = tostring(server),
        }
      end

      if replied == opts.number - 1 then
        print_results(results)
      else
        replied = replied + 1
        if not opts.flood then
          ping_fuzzy(replied + 1)
        end
      end
    end
  end

  ping_fuzzy = function(num)
    local ret, err = rspamd_plugins.fuzzy_check.ping_storage(task, gen_ping_fuzzy_cb(num),
        opts.rule, opts.timeout, opts.server)

    if not ret then
      print(highlight_err('error from %s: %s', opts.server, err))
      opts.number = opts.number - 1 -- To avoid issues with waiting for other replies
    end
  end

  if opts.flood then
    for i = 1, opts.number do
      ping_fuzzy(i)
    end
  else
    ping_fuzzy(1)
  end
end

return {
  name = 'fuzzy_ping',
  aliases = { 'fuzzyping' },
  handler = handler,
  description = parser._description
}