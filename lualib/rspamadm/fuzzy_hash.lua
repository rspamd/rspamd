--[[
Copyright (c) 2026, Vsevolod Stakhov <vsevolod@rspamd.com>

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

local E = {}

local parser = argparse()
    :name 'rspamadm fuzzy_hash'
    :description 'Computes fuzzy hashes of messages and queries fuzzy storages'
    :help_description_margin(30)

parser:argument "file"
      :description "Message file(s) to process"
      :argname "<file>"
      :args "*"
parser:option "-c --config"
      :description "Path to config file"
      :argname("<cfg>")
      :default(rspamd_paths["CONFDIR"] .. "/" .. "rspamd.conf")
parser:option "-r --rule"
      :description "Rule to use (all configured rules if not set)"
      :argname("<name>")
parser:option "-H --hash"
      :description "Query the storage for a specific hex digest instead of a file (can be repeated, requires -r)"
      :argname("<hex>")
      :count "*"
parser:flag "-C --check"
      :description "Also query the storage for the computed hashes (shingles included, like a real scan)"
parser:option "-s --server"
      :description "Override server for the queries"
      :argname("<addr>")
parser:option "-t --timeout"
      :description "Timeout for requests"
      :argname("<timeout>")
      :convert(tonumber)
      :default(5)

local function load_config(opts)
  local _r, err = rspamd_config:load_ucl(opts['config'])

  if not _r then
    rspamd_logger.errx('cannot parse %s: %s', opts['config'], err)
    os.exit(1)
  end

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

  -- Tokenization must match the scanner, otherwise text hashes differ
  rspamd_config:init_subsystem('langdet')
end

local function highlight(fmt, ...)
  return ansicolors.white .. string.format(fmt, ...) .. ansicolors.reset
end

local function highlight_err(fmt, ...)
  return ansicolors.red .. string.format(fmt, ...) .. ansicolors.reset
end

local function selected_rules(opts)
  local all_rules = rspamd_plugins.fuzzy_check.list_storages(rspamd_config)
  local res = {}

  for name, rule in pairs(all_rules) do
    if not opts.rule or opts.rule == name then
      res[name] = rule
    end
  end

  if not next(res) then
    print(highlight_err('no fuzzy rules matched (rule filter: %s)', opts.rule or 'none'))
    os.exit(1)
  end

  return res
end

local function print_check_result(ok, server, result)
  if not ok then
    print(highlight_err('  error from %s: %s', server, result))
    return
  end

  if result.found then
    local when = (result.added and result.added > 0)
        and os.date('!%Y-%m-%d %H:%M:%S', result.added) or 'unknown'
    print(highlight('  %s (%s): FOUND %s; flag=%s value=%s prob=%.2f added=%s confirmed=%s',
        result.queried, result.type, result.digest, result.flag, result.value,
        result.prob, when, result.confirmed))
  elseif result.value ~= 0 then
    print(highlight_err('  %s (%s): server error %s', result.queried, result.type, result.value))
  else
    print(string.format('  %s (%s): not found', result.queried, result.type))
  end
end

local function make_task(fname)
  local rspamd_task = require "rspamd_task"
  local task = rspamd_task.create(rspamd_config, rspamadm_ev_base)

  task:set_session(rspamadm_session)
  task:set_resolver(rspamadm_dns_resolver)

  if fname then
    if not task:load_from_file(fname) then
      print(highlight_err('cannot load message from %s', fname))
      os.exit(1)
    end

    if not task:process_message() then
      print(highlight_err('cannot process message %s', fname))
      os.exit(1)
    end
  end

  return task
end

local function query_hashes(opts)
  if not opts.rule then
    print(highlight_err('-H/--hash requires an explicit rule (-r)'))
    os.exit(1)
  end

  local task = make_task(nil)
  local ret, err = rspamd_plugins.fuzzy_check.check(task, print_check_result,
      opts.rule, opts.timeout, opts.hash, opts.server)

  if not ret then
    print(highlight_err('cannot query %s: %s', opts.rule, err))
  end
end

local function process_file(opts, fname, rules)
  local task = make_task(fname)

  print(highlight('%s:', fname))

  for name, rule in pairs(rules) do
    -- Pick any flag defined for the rule: computed hashes do not depend on it
    local _, flag = next(rule.flags or E)

    if flag then
      local hashes = rspamd_plugins.fuzzy_check.hex_hashes(task, flag) or E

      for _, h in ipairs(hashes[name] or E) do
        print(string.format('  rule %s: %s', name, h))
      end
    end

    if opts.check then
      print(highlight('  checking rule %s (%s):', name,
          opts.server or 'configured servers'))
      local ret, err = rspamd_plugins.fuzzy_check.check(task, print_check_result,
          name, opts.timeout, nil, opts.server)

      if not ret then
        print(highlight_err('  cannot query %s: %s', name, err))
      end
    end
  end
end

local function handler(args)
  local opts = parser:parse(args)

  load_config(opts)

  if #opts.hash > 0 then
    query_hashes(opts)
    return
  end

  if #opts.file == 0 then
    parser:error('no files or hashes given')
  end

  local rules = selected_rules(opts)

  for _, fname in ipairs(opts.file) do
    process_file(opts, fname, rules)
  end
end

return {
  name = 'fuzzy_hash',
  aliases = { 'fuzzyhash' },
  handler = handler,
  description = parser._description
}
