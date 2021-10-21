--[[
Copyright (c) 2021, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

local lua_redis = require "lua_redis"
local rspamd_logger = require "rspamd_logger"
local argparse = require "argparse"
local rspamd_zstd = require "rspamd_zstd"
local rspamd_text = require "rspamd_text"
local rspamd_util = require "rspamd_util"
local rspamd_cdb = require "rspamd_cdb"
local lua_util = require "lua_util"
local rspamd_i64 = require "rspamd_int64"
local ucl = require "ucl"

local N = "statistics_dump"
local E = {}
local classifiers = {}

-- Define command line options
local parser = argparse()
    :name "rspamadm statistics_dump"
    :description "Dump/restore Rspamd statistics"
    :help_description_margin(30)
    :command_target("command")
    :require_command(false)

parser:option "-c --config"
      :description "Path to config file"
      :argname("<cfg>")
      :default(rspamd_paths["CONFDIR"] .. "/" .. "rspamd.conf")

-- Extract subcommand
local dump = parser:command "dump d"
                   :description "Dump bayes statistics"
dump:mutex(
    dump:flag "-j --json"
        :description "Json output",
    dump:flag "-C --cdb"
        :description "CDB output"
)
dump:flag "-c --compress"
    :description "Compress output"
dump:option "-b --batch-size"
    :description "Number of entires to process at once"
    :argname("<elts>")
    :convert(tonumber)
    :default(1000)


-- Restore
local restore = parser:command "restore r"
                      :description "Restore bayes statistics"
restore:argument "file"
       :description "Input file to process"
       :argname "<file>"
       :args "*"
restore:option "-b --batch-size"
    :description "Number of entires to process at once"
    :argname("<elts>")
    :convert(tonumber)
    :default(1000)
restore:option "-m --mode"
       :description "Number of entires to process at once"
       :argname("<append|subtract|replace>")
       :convert {
          ['append'] = 'append',
          ['subtract'] = 'subtract',
          ['replace'] = 'replace',
        }
       :default 'append'
restore:flag "-n --no-operation"
    :description "Only show redis commands to be issued"

local function load_config(opts)
  local _r,err = rspamd_config:load_ucl(opts['config'])

  if not _r then
    rspamd_logger.errx('cannot parse %s: %s', opts['config'], err)
    os.exit(1)
  end

  _r,err = rspamd_config:parse_rcl({'logging', 'worker'})
  if not _r then
    rspamd_logger.errx('cannot process %s: %s', opts['config'], err)
    os.exit(1)
  end
end

local function check_redis_classifier(cls, cfg)
  -- Skip old classifiers
  if cls.new_schema then
    local symbol_spam, symbol_ham
    -- Load symbols from statfiles

    local function check_statfile_table(tbl, def_sym)
      local symbol = tbl.symbol or def_sym

      local spam
      if tbl.spam then
        spam = tbl.spam
      else
        if string.match(symbol:upper(), 'SPAM') then
          spam = true
        else
          spam = false
        end
      end

      if spam then
        symbol_spam = symbol
      else
        symbol_ham = symbol
      end
    end

    local statfiles = cls.statfile
    if statfiles[1] then
      for _,stf in ipairs(statfiles) do
        if not stf.symbol then
          for k,v in pairs(stf) do
            check_statfile_table(v, k)
          end
        else
          check_statfile_table(stf, 'undefined')
        end
      end
    else
      for stn,stf in pairs(statfiles) do
        check_statfile_table(stf, stn)
      end
    end

    local redis_params
    redis_params = lua_redis.try_load_redis_servers(cls,
        rspamd_config, false, 'bayes')
    if not redis_params then
      redis_params = lua_redis.try_load_redis_servers(cfg[N] or E,
          rspamd_config, false, 'bayes')
      if not redis_params then
        redis_params = lua_redis.try_load_redis_servers(cfg[N] or E,
            rspamd_config, true)
        if not redis_params then
          return false
        end
      end
    end

    table.insert(classifiers, {
      symbol_spam = symbol_spam,
      symbol_ham = symbol_ham,
      redis_params = redis_params,
    })
  end
end

local function redis_map_zip(ar)
  local data = {}
  for j=1,#ar,2 do
    data[ar[j]] = ar[j + 1]
  end

  return data
end

-- Used to clear tables
local clear_fcn = table.clear or function(tbl)
  local keys = lua_util.keys(tbl)
  for _,k in ipairs(keys) do
    tbl[k] = nil
  end
end

local compress_ctx

local function dump_out(out, opts, last)
  if opts.compress and not compress_ctx then
    compress_ctx = rspamd_zstd.compress_ctx()
  end

  if compress_ctx then
    if last then
      compress_ctx:stream(rspamd_text.fromtable(out), 'end'):write()
    else
      compress_ctx:stream(rspamd_text.fromtable(out), 'flush'):write()
    end
  else
    for _,o in ipairs(out) do
      io.write(o)
    end
  end
end

local function dump_cdb(out, opts, last, pattern)
  local results = out[pattern]

  if not out.cdb_builder then
    -- First invocation
    out.cdb_builder = rspamd_cdb.build(string.format('%s.cdb', pattern))
    out.cdb_builder:add('_lrnspam', rspamd_i64.fromstring(results.learns_spam or '0'))
    out.cdb_builder:add('_lrnham_', rspamd_i64.fromstring(results.learns_ham or '0'))
  end

  for _,o in ipairs(results.elts) do
    out.cdb_builder:add(o.key, o.value)
  end

  if last then
    out.cdb_builder:finalize()
    out.cdb_builder = nil
  end
end

local function dump_pattern(conn, pattern, opts, out, key)
  local cursor = 0

  repeat
    conn:add_cmd('SCAN', {tostring(cursor),
                          'MATCH', pattern,
                          'COUNT', tostring(opts.batch_size)})
    local ret, results = conn:exec()

    if not ret then
      rspamd_logger.errx("cannot connect execute scan command: %s", results)
      os.exit(1)
    end

    cursor = tonumber(results[1])

    local elts = results[2]
    local tokens = {}

    for _,e in ipairs(elts) do
      conn:add_cmd('HGETALL', {e})
    end
    -- This function returns many results, each for each command
    -- So if we have batch 1000, then we would have 1000 tables in form
    -- [result, {hash_content}]
    local all_results = {conn:exec()}

    for i=1,#all_results,2 do
      local r, hash_content = all_results[i], all_results[i + 1]

      if r then
        -- List to a hash map
        local data = redis_map_zip(hash_content)
        tokens[#tokens + 1] = {key = elts[(i + 1)/2], data = data}
      end
    end

    -- Output keeping track of the commas
    for i,d in ipairs(tokens) do
      if cursor == 0 and i == #tokens or not opts.json then
        if opts.cdb then
          table.insert(out[key].elts, {
            key = rspamd_i64.fromstring(string.match(d.key, '%d+')),
            value = rspamd_util.pack('ff', tonumber(d.data["S"] or '0') or 0,
                tonumber(d.data["H"] or '0'))
          })
        else
          out[#out + 1] = rspamd_logger.slog('"%s": %s\n', d.key,
              ucl.to_format(d.data, "json-compact"))
        end
      else
        out[#out + 1] = rspamd_logger.slog('"%s": %s,\n', d.key,
            ucl.to_format(d.data, "json-compact"))
      end

    end

    if opts.json and cursor == 0 then
      out[#out + 1] = '}}\n'
    end

    -- Do not write the last chunk of out as it will be processed afterwards
    if not cursor == 0 then
      if opts.cdb then
        dump_out(out, opts, false)
        clear_fcn(out)
      else
        dump_cdb(out, opts, false, key)
        out[key].elts = {}
      end
    elseif opts.cdb then
      dump_cdb(out, opts, true, key)
    end

  until cursor == 0
end

local function dump_handler(opts)
  local patterns_seen = {}
  for _,cls in ipairs(classifiers) do
    local res,conn = lua_redis.redis_connect_sync(cls.redis_params, false)

    if not res then
      rspamd_logger.errx("cannot connect to redis server: %s", cls.redis_params)
      os.exit(1)
    end

    local out = {}
    local function check_keys(sym)
      local sym_keys_pattern = string.format("%s_keys", sym)
      conn:add_cmd('SMEMBERS', { sym_keys_pattern })
      local ret,keys = conn:exec()

      if not ret then
        rspamd_logger.errx("cannot execute command to get keys: %s", keys)
        os.exit(1)
      end

      if not opts.json then
        out[#out + 1] = string.format('"%s": %s\n', sym_keys_pattern,
            ucl.to_format(keys, 'json-compact'))
      end
      for _,k in ipairs(keys) do
        local pat = string.format('%s*_*', k)
        if not patterns_seen[pat] then
          conn:add_cmd('HGETALL', {k})
          local _ret,additional_keys = conn:exec()

          if _ret then
            if opts.json then
              out[#out + 1] = string.format('{"pattern": "%s", "meta": %s, "elts": {\n',
                  k, ucl.to_format(redis_map_zip(additional_keys), 'json-compact'))
            elseif opts.cdb then
              out[k] = redis_map_zip(additional_keys)
              out[k].elts = {}
            else
              out[#out + 1] = string.format('"%s": %s\n', k,
                  ucl.to_format(redis_map_zip(additional_keys), 'json-compact'))
            end
            dump_pattern(conn, pat, opts, out, k)
            patterns_seen[pat] = true
          end
        end
      end
    end

    check_keys(cls.symbol_spam)
    check_keys(cls.symbol_ham)

    if #out > 0 then
      dump_out(out, opts, true)
    end
  end
end

local function obj_to_redis_arguments(obj, opts, cmd_pipe)
  local key,value = next(obj)

  if type(key) == 'string' then
    if type(value) == 'table' then
      if not value[1] then
        if opts.mode == 'replace' then
          local cmd = 'HMSET'
          local params = {key}
          for k,v in pairs(value) do
            table.insert(params, k)
            table.insert(params, v)
          end
          table.insert(cmd_pipe, {cmd, params})
        else
          local cmd = 'HINCRBYFLOAT'
          local mult = 1.0
          if opts.mode == 'subtract' then
            mult = (-mult)
          end

          for k,v in pairs(value) do
            if tonumber(v) then
              v = tonumber(v)
              table.insert(cmd_pipe, {cmd, {key, k, tostring(v * mult)}})
            else
              table.insert(cmd_pipe, {'HSET', {key, k, v}})
            end
          end
        end
      else
        -- Numeric table of elements (e.g. _keys) - it is actually a set in Redis
        for _,elt in ipairs(value) do
          table.insert(cmd_pipe, {'SADD', {key, elt}})
        end
      end
    end
  end

  return cmd_pipe
end

local function execute_batch(batch, conns, opts)
  local cmd_pipe = {}

  for _,cmd in ipairs(batch) do
    obj_to_redis_arguments(cmd, opts, cmd_pipe)
  end

  if opts.no_operation then
    for _,cmd in ipairs(cmd_pipe) do
      rspamd_logger.messagex('%s %s', cmd[1], table.concat(cmd[2], ' '))
    end
  else
    for _, conn in ipairs(conns) do
      for _,cmd in ipairs(cmd_pipe) do
        local is_ok, err = conn:add_cmd(cmd[1], cmd[2])

        if not is_ok then
          rspamd_logger.errx("cannot add command: %s with args: %s: %s", cmd[1], cmd[2], err)
        end
      end

      conn:exec()
    end
  end
end

local function restore_handler(opts)
  local files = opts.file or {'-'}
  local conns = {}

  for _,cls in ipairs(classifiers) do
    local res,conn = lua_redis.redis_connect_sync(cls.redis_params, true)

    if not res then
      rspamd_logger.errx("cannot connect to redis server: %s", cls.redis_params)
      os.exit(1)
    end

    table.insert(conns, conn)
  end

  local batch = {}

  for _,f in ipairs(files) do
    local fd
    if f ~= '-' then
      fd = io.open(f, 'r')
      io.input(fd)
    end

    local cur_line = 1
    for line in io.lines() do
      local ucl_parser = ucl.parser()
      local res, err
      res,err = ucl_parser:parse_string(line)

      if not res then
        rspamd_logger.errx("%s: cannot read line %s: %s", f, cur_line, err)
        os.exit(1)
      end

      table.insert(batch, ucl_parser:get_object())
      cur_line = cur_line + 1

      if cur_line % opts.batch_size == 0 then
        execute_batch(batch, conns, opts)
        batch = {}
      end
    end

    if fd then fd:close() end
  end

  if #batch > 0 then
    execute_batch(batch, conns, opts)
  end
end

local function handler(args)
  local opts = parser:parse(args)

  local command = opts.command or 'dump'

  load_config(opts)
  rspamd_config:init_subsystem('stat')

  local obj = rspamd_config:get_ucl()

  local classifier = obj.classifier

  if classifier then
    if classifier[1] then
      for _,cls in ipairs(classifier) do
        if cls.bayes then cls = cls.bayes end
        if cls.backend and cls.backend == 'redis' then
          check_redis_classifier(cls, obj)
        end
      end
    else
      if classifier.bayes then

        classifier = classifier.bayes
        if classifier[1] then
          for _,cls in ipairs(classifier) do
            if cls.backend and cls.backend == 'redis' then
              check_redis_classifier(cls, obj)
            end
          end
        else
          if classifier.backend and classifier.backend == 'redis' then
            check_redis_classifier(classifier, obj)
          end
        end
      end
    end
  end

  if type(opts.file) == 'string' then
    opts.file = {opts.file}
  elseif type(opts.file) == 'none' then
    opts.file = {}
  end

  if command == 'dump' then
    dump_handler(opts)
  elseif command == 'restore' then
    restore_handler(opts)
  else
    parser:error('command %s is not implemented', command)
  end
end

return {
  name = 'statistics_dump',
  aliases = {'stat_dump', 'bayes_dump'},
  handler = handler,
  description = parser._description
}