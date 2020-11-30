--[[
Copyright (c) 2020, Vsevolod Stakhov <vsevolod@highsecure.ru>

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
local lua_clickhouse = require "lua_clickhouse"
local rspamd_upstream_list = require "rspamd_upstream_list"
local ucl = require "ucl"

-- Define command line options
local parser = argparse()
    :name 'rspamadm clickhouse'
    :description 'Retrieve information from Clickhouse'
    :help_description_margin(30)
    :command_target('command')
    :require_command(true)

parser:option '-c --config'
      :description 'Path to config file'
      :argname('config_file')
      :default(rspamd_paths['CONFDIR'] .. '/rspamd.conf')
parser:option '-d --database'
      :description 'Name of Clickhouse database to use'
      :argname('database')
      :default('default')
parser:flag '--no-ssl-verify'
      :description 'Disable SSL verification'
      :argname('no_ssl_verify')
parser:mutex(
    parser:option '-p --password'
          :description 'Password to use for Clickhouse'
          :argname('password'),
    parser:flag '-a --ask-password'
          :description 'Ask password from the terminal'
          :argname('ask_password')
)
parser:option '-s --server'
      :description 'Address[:port] to connect to Clickhouse with'
      :argname('server')
parser:option '-u --user'
      :description 'Username to use for Clickhouse'
      :argname('user')
parser:option '--use-gzip'
      :description 'Use Gzip with Clickhouse'
      :argname('use_gzip')
      :default(true)
parser:flag '--use-https'
      :description 'Use HTTPS with Clickhouse'
      :argname('use_https')

local neural_profile = parser:command 'neural_profile'
      :description 'Generate symbols profile using data from Clickhouse'
neural_profile:option '-w --where'
      :description 'WHERE clause for Clickhouse query'
      :argname('where')
parser:flag '-j --json'
      :description 'Write output as JSON'
      :argname('json')

local http_params = {
  config = rspamd_config,
  ev_base = rspamadm_ev_base,
  session = rspamadm_session,
  resolver = rspamadm_dns_resolver,
}

local function load_config(config_file)
  local _r,err = rspamd_config:load_ucl(config_file)

  if not _r then
    io.stderr:write(string.format('cannot parse %s: %s',
        config_file, err))
    os.exit(1)
  end
end

local function get_excluded_symbols(known_symbols, correlations, seen_total)
  -- Walk results once to collect all symbols & count ocurrences

  local remove = {}
  local known_symbols_list = {}
  local composites = rspamd_config:get_all_opt('composites')
  for k, v in pairs(known_symbols) do
    local lower_count, higher_count
    if v.seen_spam > v.seen_ham then
      lower_count = v.seen_ham
      higher_count = v.seen_spam
    else
      lower_count = v.seen_spam
      higher_count = v.seen_ham
    end
    if composites[k] then
      remove[k] = 'composite symbol'
    elseif lower_count / higher_count >= 0.95 then
      remove[k] = 'weak ham/spam correlation'
    elseif v.seen / seen_total >= 0.9 then
      remove[k] = 'omnipresent symbol'
    end
    known_symbols_list[v.id] = {
      seen = v.seen,
      name = k,
    }
  end

  -- Walk correlation matrix and check total counts
  for sym_id, row in pairs(correlations) do
    for inner_sym_id, count in pairs(row) do
      local known = known_symbols_list[sym_id]
      local inner = known_symbols_list[inner_sym_id]
      if known and count == known.seen and not remove[inner.name] and not remove[known.name] then
        remove[known.name] = string.format("overlapped by %s",
            known_symbols_list[inner_sym_id].name)
      end
    end
  end

  return remove
end

local function handle_neural_profile(args)
  if args.where then
    args.where = 'WHERE ' .. args.where
  end
  local query = string.format(
      "SELECT Action, Symbols.Names FROM rspamd %s", args.where or '')
  local upstream = args.upstream:get_upstream_round_robin()
  local known_symbols = {}
  local symbols_count, seen_total = 1, 0
  local correlations = {}

  local function process_row(r)
    local is_spam = true
    if r['Action'] == 'no action' or r['Action'] == 'greylist' then
      is_spam = false
    end
    seen_total = seen_total + 1

    local nsym = #r['Symbols.Names']

    for i = 1,nsym do
      local sym = r['Symbols.Names'][i]
      local t = known_symbols[sym]
      if not t then
        local spam_count, ham_count = 0, 0
        if is_spam then
          spam_count = spam_count + 1
        else
          ham_count = ham_count + 1
        end
        known_symbols[sym] = {
          id = symbols_count,
          seen = 1,
          seen_ham = ham_count,
          seen_spam = spam_count,
        }
        symbols_count = symbols_count + 1
      else
        known_symbols[sym].seen = known_symbols[sym].seen + 1
        if is_spam then
          known_symbols[sym].seen_spam = known_symbols[sym].seen_spam + 1
        else
          known_symbols[sym].seen_ham = known_symbols[sym].seen_ham + 1
        end
      end
    end

    -- Fill correlations
    for i = 1,nsym do
      for j = 1,nsym do
        if i ~= j then
          local sym = r['Symbols.Names'][i]
          local inner_sym_name = r['Symbols.Names'][j]
          local known_sym = known_symbols[sym]
          local inner_sym = known_symbols[inner_sym_name]
          if known_sym and inner_sym then
            if not correlations[known_sym.id] then
              correlations[known_sym.id] = {}
            end
            local n = correlations[known_sym.id][inner_sym.id] or 0
            n = n + 1
            correlations[known_sym.id][inner_sym.id] = n
          end
        end
      end
    end
  end

  local err, _ = lua_clickhouse.select_sync(upstream, args, http_params, query, process_row)
  if err ~= nil then
    io.stderr:write(string.format('Error querying Clickhouse: %s\n', err))
    os.exit(1)
  end

  local remove = get_excluded_symbols(known_symbols, correlations, seen_total)
  if not args.json then
    for k in pairs(known_symbols) do
      if not remove[k] then
        io.stdout:write(string.format('%s\n', k))
      end
    end
    os.exit(0)
  end

  local json_output = {
    all_symbols = {},
    removed_symbols = {},
    used_symbols = {},
  }
  for k in pairs(known_symbols) do
    table.insert(json_output.all_symbols, k)
    local why_removed = remove[k]
    if why_removed then
      json_output.removed_symbols[k] = why_removed
    else
      table.insert(json_output.used_symbols, k)
    end
  end
  io.stdout:write(ucl.to_format(json_output, 'json'))
end

local command_handlers = {
  neural_profile = handle_neural_profile,
}

local function handler(args)
  local cmd_opts = parser:parse(args)

  load_config(cmd_opts.config_file)
  local cfg_opts = rspamd_config:get_all_opt('clickhouse')

  if cmd_opts.ask_password then
    local rspamd_util = require "rspamd_util"

    io.write('Password: ')
    cmd_opts.password = rspamd_util.readpassphrase()
  end

  local function override_settings(params)
    for _, which in ipairs(params) do
      if cmd_opts[which] == nil then
        cmd_opts[which] = cfg_opts[which]
      end
    end
  end

  override_settings({
    'database', 'no_ssl_verify', 'password', 'server',
    'use_gzip', 'use_https', 'user',
  })

  local servers = cmd_opts['server'] or cmd_opts['servers']
  if not servers then
    parser:error("server(s) unspecified & couldn't be fetched from config")
  end

  cmd_opts.upstream = rspamd_upstream_list.create(rspamd_config, servers, 8123)

  if not cmd_opts.upstream then
    io.stderr:write(string.format("can't parse clickhouse address: %s\n", servers))
    os.exit(1)
  end

  local f = command_handlers[cmd_opts.command]
  if not f then
    parser:error(string.format("command isn't implemented: %s",
        cmd_opts.command))
  end
  f(cmd_opts)
end

return {
  handler = handler,
  description = parser._description,
  name = 'clickhouse'
}
