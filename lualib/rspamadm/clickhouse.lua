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
local lua_util = require "lua_util"
local rspamd_http = require "rspamd_http"
local rspamd_upstream_list = require "rspamd_upstream_list"
local rspamd_logger = require "rspamd_logger"
local ucl = require "ucl"

local E = {}

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
neural_profile:flag '-j --json'
      :description 'Write output as JSON'
      :argname('json')
neural_profile:option '--days'
      :description 'Number of days to collect stats for'
      :argname('days')
      :default('7')
neural_profile:option '--limit -l'
      :description 'Maximum rows to fetch per day'
      :argname('limit')
neural_profile:option '--settings-id'
      :description 'Settings ID to query'
      :argname('settings_id')
      :default('')

local neural_train = parser:command 'neural_train'
      :description 'Train neural using data from Clickhouse'
neural_train:option '--days'
      :description 'Number of days to query data for'
      :argname('days')
      :default('7')
neural_train:option '--column-name-digest'
      :description 'Name of neural profile digest column in Clickhouse'
      :argname('column_name_digest')
      :default('NeuralDigest')
neural_train:option '--column-name-vector'
      :description 'Name of neural training vector column in Clickhouse'
      :argname('column_name_vector')
      :default('NeuralMpack')
neural_train:option '--limit -l'
      :description 'Maximum rows to fetch per day'
      :argname('limit')
neural_train:option '--profile -p'
      :description 'Profile to use for training'
      :argname('profile')
      :default('default')
neural_train:option '--rule -r'
      :description 'Rule to train'
      :argname('rule')
      :default('default')
neural_train:option '--spam -s'
      :description 'WHERE clause to use for spam'
      :argname('spam')
      :default("Action == 'reject'")
neural_train:option '--ham -h'
      :description 'WHERE clause to use for ham'
      :argname('ham')
      :default('Score < 0')
neural_train:option '--url -u'
      :description 'URL to use for training'
      :argname('url')
      :default('http://127.0.0.1:11334/plugins/neural/learn')

local http_params = {
  config = rspamd_config,
  ev_base = rspamadm_ev_base,
  session = rspamadm_session,
  resolver = rspamadm_dns_resolver,
}

local function load_config(config_file)
  local _r,err = rspamd_config:load_ucl(config_file)

  if not _r then
    rspamd_logger.errx('cannot load %s: %s', config_file, err)
    os.exit(1)
  end

  _r,err = rspamd_config:parse_rcl({'logging', 'worker'})
  if not _r then
    rspamd_logger.errx('cannot process %s: %s', config_file, err)
    os.exit(1)
  end

  if not rspamd_config:init_modules() then
    rspamd_logger.errx('cannot init modules when parsing %s', config_file)
    os.exit(1)
  end

  rspamd_config:init_subsystem('symcache')
end

local function days_list(days)
  -- Create list of days to query starting with yesterday
  local query_days = {}
  local previous_date = os.time() - 86400
  local num_days = tonumber(days)
  for _ = 1, num_days do
    table.insert(query_days, os.date('%Y-%m-%d', previous_date))
    previous_date = previous_date - 86400
  end
  return query_days
end

local function get_excluded_symbols(known_symbols, correlations, seen_total)
  -- Walk results once to collect all symbols & count ocurrences

  local remove = {}
  local known_symbols_list = {}
  local composites = rspamd_config:get_all_opt('composites')
  local all_symbols = rspamd_config:get_symbols()
  local skip_flags = {
    nostat = true,
    skip = true,
    idempotent = true,
    composite = true,
  }
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
    elseif not all_symbols[k] then
      remove[k] = 'nonexistent symbol'
    else
      for fl,_ in pairs(all_symbols[k].flags or {}) do
        if skip_flags[fl] then
          remove[k] = fl .. ' symbol'
          break
        end
      end
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

  local known_symbols, correlations = {}, {}
  local symbols_count, seen_total = 0, 0

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

  local query_days = days_list(args.days)
  local conditions = {}
  table.insert(conditions, string.format("SettingsId = '%s'", args.settings_id))
  local limit = ''
  local num_limit = tonumber(args.limit)
  if num_limit then
    limit = string.format(' LIMIT %d', num_limit) -- Contains leading space
  end
  if args.where then
    table.insert(conditions, args.where)
  end

  local query_fmt = 'SELECT Action, Symbols.Names FROM rspamd WHERE %s%s'
  for _, query_day in ipairs(query_days) do
    -- Date should be the last condition
    table.insert(conditions, string.format("Date = '%s'", query_day))
    local query = string.format(query_fmt, table.concat(conditions, ' AND '), limit)
    local upstream = args.upstream:get_upstream_round_robin()
    local err = lua_clickhouse.select_sync(upstream, args, http_params, query, process_row)
    if err ~= nil then
      io.stderr:write(string.format('Error querying Clickhouse: %s\n', err))
      os.exit(1)
    end
    conditions[#conditions] = nil -- remove Date condition
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

local function post_neural_training(url, rule, spam_rows, ham_rows)
  -- Prepare JSON payload
  local payload = ucl.to_format(
    {
      ham_vec = ham_rows,
      rule = rule,
      spam_vec = spam_rows,
    }, 'json')

  -- POST the payload
  local err, response = rspamd_http.request({
    body = payload,
    config = rspamd_config,
    ev_base = rspamadm_ev_base,
    log_obj = rspamd_config,
    resolver = rspamadm_dns_resolver,
    session = rspamadm_session,
    url = url,
  })

  if err then
    io.stderr:write(string.format('HTTP error: %s\n', err))
    os.exit(1)
  end
  if response.code ~= 200 then
    io.stderr:write(string.format('bad HTTP code: %d\n', response.code))
    os.exit(1)
  end
  io.stdout:write(string.format('%s\n', response.content))
end

local function handle_neural_train(args)

  local this_where -- which class of messages are we collecting data for
  local ham_rows, spam_rows = {}, {}
  local want_spam, want_ham = true, true -- keep collecting while true

  -- Try find profile in config
  local neural_opts = rspamd_config:get_all_opt('neural')
  local symbols_profile = ((((neural_opts or E).rules or E)[args.rule] or E).profile or E)[args.profile]
  if not symbols_profile then
    io.stderr:write(string.format("Couldn't find profile %s in rule %s\n", args.profile, args.rule))
    os.exit(1)
  end
  -- Try find max_trains
  local max_trains = (neural_opts.rules[args.rule].train or E).max_trains or 1000

  -- Callback used to process rows from Clickhouse
  local function process_row(r)
    local destination -- which table to collect this information in
    if this_where == args.ham then
      destination = ham_rows
      if #destination >= max_trains then
        want_ham = false
        return
      end
    else
      destination = spam_rows
      if #destination >= max_trains then
        want_spam = false
        return
      end
    end
    local ucl_parser = ucl.parser()
    local ok, err = ucl_parser:parse_string(r[args.column_name_vector], 'msgpack')
    if not ok then
      io.stderr:write(string.format("Couldn't parse [%s]: %s", r[args.column_name_vector], err))
      os.exit(1)
    end
    table.insert(destination, ucl_parser:get_object())
  end

  -- Generate symbols digest
  table.sort(symbols_profile)
  local symbols_digest = lua_util.table_digest(symbols_profile)
  -- Create list of days to query data for
  local query_days = days_list(args.days)
  -- Set value for limit
  local limit = ''
  local num_limit = tonumber(args.limit)
  if num_limit then
    limit = string.format(' LIMIT %d', num_limit) -- Contains leading space
  end
  -- Prepare query elements
  local conditions = {string.format("%s = '%s'", args.column_name_digest, symbols_digest)}
  local query_fmt = 'SELECT %s FROM rspamd WHERE %s%s'

  -- Run queries
  for _, the_where in ipairs({args.ham, args.spam}) do
    -- Inform callback which group of vectors we're collecting
    this_where = the_where
    table.insert(conditions, the_where) -- should be 2nd from last condition
    -- Loop over days and try collect data
    for _, query_day in ipairs(query_days) do
      -- Break the loop if we have enough data already
      if this_where == args.ham then
        if not want_ham then
          break
	end
      else
        if not want_spam then
          break
        end
      end
      -- Date should be the last condition
      table.insert(conditions, string.format("Date = '%s'", query_day))
      local query = string.format(query_fmt, args.column_name_vector, table.concat(conditions, ' AND '), limit)
      local upstream = args.upstream:get_upstream_round_robin()
      local err = lua_clickhouse.select_sync(upstream, args, http_params, query, process_row)
      if err ~= nil then
        io.stderr:write(string.format('Error querying Clickhouse: %s\n', err))
        os.exit(1)
      end
      conditions[#conditions] = nil -- remove Date condition
    end
    conditions[#conditions] = nil -- remove spam/ham condition
  end

  -- Make sure we collected enough data for training
  if #ham_rows < max_trains then
    io.stderr:write(string.format('Insufficient ham rows: %d/%d\n', #ham_rows, max_trains))
    os.exit(1)
  end
  if #spam_rows < max_trains then
    io.stderr:write(string.format('Insufficient spam rows: %d/%d\n', #spam_rows, max_trains))
    os.exit(1)
  end

  return post_neural_training(args.url, args.rule, spam_rows, ham_rows)
end

local command_handlers = {
  neural_profile = handle_neural_profile,
  neural_train = handle_neural_train,
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
