--[[
Copyright (c) 2022, Vsevolod Stakhov <vsevolod@rspamd.com>

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

parser:option "-b --batch-size"
    :description "Number of entries to process at once"
    :argname("<elts>")
    :convert(tonumber)
    :default(1000)

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
    :description "Number of entries to process at once"
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
       :description "Number of entries to process at once"
       :argname("<elts>")
       :convert(tonumber)
       :default(1000)
restore:option "-m --mode"
       :description "Number of entries to process at once"
       :argname("<append|subtract|replace>")
       :convert {
  ['append'] = 'append',
  ['subtract'] = 'subtract',
  ['replace'] = 'replace',
}
       :default 'append'
restore:flag "-n --no-operation"
       :description "Only show redis commands to be issued"

-- Migrate
local migrate = parser:command "migrate m"
                      :description "Migrate bayes data between shards (after hash algorithm change)"
migrate:flag "-n --dry-run"
       :description "Only show what would be migrated, without writing"
migrate:flag "--no-delete"
       :description "Copy keys to target shard without deleting from source"
migrate:option "-b --batch-size"
       :description "Number of entries to process per SCAN batch"
       :argname("<elts>")
       :convert(tonumber)
       :default(1000)

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
end

local function check_redis_classifier(cls, cfg)
  -- Skip old classifiers
  if cls.new_schema then
    local symbol_spam, symbol_ham
    local symbols = {}
    -- Load symbols from statfiles

    local function get_class_label(class_name)
      -- Check class_labels mapping in classifier config
      if cls.class_labels and class_name then
        local label = cls.class_labels[class_name]
        if label then
          return label
        end
      end
      -- Default mapping: spam→S, ham→H, custom→class_name
      if class_name == 'spam' then
        return 'S'
      elseif class_name == 'ham' then
        return 'H'
      end
      return class_name
    end

    local function check_statfile_table(tbl, def_sym)
      local symbol = tbl.symbol or def_sym

      -- Determine class_name by priority:
      -- 1. Explicit tbl.class
      -- 2. Legacy tbl.spam boolean
      -- 3. Heuristic from symbol name
      local class_name
      if tbl.class then
        class_name = tbl.class
      elseif tbl.spam then
        class_name = 'spam'
      else
        if string.match(symbol:upper(), 'SPAM') then
          class_name = 'spam'
        else
          class_name = 'ham'
        end
      end

      local label = get_class_label(class_name)

      -- Backward compat for binary classifiers
      if class_name == 'spam' then
        symbol_spam = symbol
      elseif class_name == 'ham' then
        symbol_ham = symbol
      end

      table.insert(symbols, {
        symbol = symbol,
        class_name = class_name,
        label = label,
      })
    end

    local statfiles = cls.statfile
    if statfiles[1] then
      for _, stf in ipairs(statfiles) do
        if not stf.symbol then
          for k, v in pairs(stf) do
            check_statfile_table(v, k)
          end
        else
          check_statfile_table(stf, 'undefined')
        end
      end
    else
      for stn, stf in pairs(statfiles) do
        check_statfile_table(stf, stn)
      end
    end

    local redis_params
    -- Try load from classifier config
    redis_params = lua_redis.try_load_redis_servers(cls,
        rspamd_config, false, 'bayes')
    if not redis_params then
      -- Try load from statistics_dump module config
      redis_params = lua_redis.try_load_redis_servers(cfg[N] or E,
          rspamd_config, false, 'bayes')
      if not redis_params then
        redis_params = lua_redis.try_load_redis_servers(cfg[N] or E,
            rspamd_config, true)
        if not redis_params then
          -- Try load from global redis config
          redis_params = lua_redis.try_load_redis_servers(rspamd_config:get_all_opt('redis'),
              rspamd_config, true)
          if not redis_params then
            return false
          end
        end
      end
    end

    table.insert(classifiers, {
      symbol_spam = symbol_spam,
      symbol_ham = symbol_ham,
      symbols = symbols,
      redis_params = redis_params,
    })
  end
end

local function redis_map_zip(ar)
  local data = {}
  for j = 1, #ar, 2 do
    data[ar[j]] = ar[j + 1]
  end

  return data
end

-- Used to clear tables
local clear_fcn = table.clear or function(tbl)
  local keys = lua_util.keys(tbl)
  for _, k in ipairs(keys) do
    tbl[k] = nil
  end
end

local function connect_to_upstream(up, redis_params)
  local rspamd_redis = require "rspamd_redis"
  local ret, conn = rspamd_redis.connect_sync({
    host = up:get_addr(),
    timeout = redis_params.timeout,
    config = rspamd_config,
    ev_base = rspamadm_ev_base,
    session = rspamadm_session,
  })

  if not ret or not conn then
    rspamd_logger.errx("cannot connect to redis %s: %s", up:get_name(), conn)
    return false, nil
  end

  local need_exec = false
  if redis_params.username then
    if redis_params.password then
      conn:add_cmd('AUTH', { redis_params.username, redis_params.password })
      need_exec = true
    else
      rspamd_logger.errx("redis requires a password when username is supplied")
      return false, nil
    end
  elseif redis_params.password then
    conn:add_cmd('AUTH', { redis_params.password })
    need_exec = true
  end

  if redis_params.db then
    conn:add_cmd('SELECT', { tostring(redis_params.db) })
    need_exec = true
  elseif redis_params.dbname then
    conn:add_cmd('SELECT', { tostring(redis_params.dbname) })
    need_exec = true
  end

  if need_exec then
    local exec_ret, res = conn:exec()
    if not exec_ret then
      rspamd_logger.errx("cannot authenticate/select db on %s: %s", up:get_name(), res)
      return false, nil
    end
  end

  return true, conn
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
    for _, o in ipairs(out) do
      io.write(o)
    end
  end
end

local function dump_cdb(out, opts, last, pattern, class_labels)
  local results = out[pattern]

  if not out.cdb_builder then
    -- First invocation
    out.cdb_builder = rspamd_cdb.build(string.format('%s.cdb', pattern))
    -- Write learned counts for all class labels
    for _, lbl in ipairs(class_labels or { 'S', 'H' }) do
      local learned_key
      if lbl == 'S' then
        learned_key = 'learns_spam'
      elseif lbl == 'H' then
        learned_key = 'learns_ham'
      else
        learned_key = 'learns_' .. lbl
      end
      -- Pad CDB key to 8 bytes for consistent lookup
      local cdb_key = string.format('_lrn%-4s', lbl)
      out.cdb_builder:add(cdb_key, rspamd_i64.fromstring(results[learned_key] or '0'))
    end
  end

  for _, o in ipairs(results.elts) do
    out.cdb_builder:add(o.key, o.value)
  end

  if last then
    out.cdb_builder:finalize()
    out.cdb_builder = nil
  end
end

local function dump_pattern(conn, pattern, opts, out, key, class_labels)
  local cursor = 0

  -- Build CDB pack format string from class labels
  local cdb_fmt
  if opts.cdb then
    cdb_fmt = string.rep('f', #class_labels)
  end

  repeat
    conn:add_cmd('SCAN', { tostring(cursor),
                           'MATCH', pattern,
                           'COUNT', tostring(opts.batch_size) })
    local ret, results = conn:exec()

    if not ret then
      rspamd_logger.errx("cannot connect execute scan command: %s", results)
      os.exit(1)
    end

    cursor = tonumber(results[1])

    local elts = results[2]
    local tokens = {}

    for _, e in ipairs(elts) do
      conn:add_cmd('HGETALL', { e })
    end
    -- This function returns many results, each for each command
    -- So if we have batch 1000, then we would have 1000 tables in form
    -- [result, {hash_content}]
    local all_results = { conn:exec() }

    for i = 1, #all_results, 2 do
      local r, hash_content = all_results[i], all_results[i + 1]

      if r then
        -- List to a hash map
        local data = redis_map_zip(hash_content)
        tokens[#tokens + 1] = { key = elts[(i + 1) / 2], data = data }
      end
    end

    -- Output keeping track of the commas
    for i, d in ipairs(tokens) do
      if cursor == 0 and i == #tokens or not opts.json then
        if opts.cdb then
          -- Pack all class label values dynamically
          local values = {}
          for _, lbl in ipairs(class_labels) do
            values[#values + 1] = tonumber(d.data[lbl] or '0') or 0
          end
          table.insert(out[key].elts, {
            key = rspamd_i64.fromstring(string.match(d.key, '%d+')),
            value = rspamd_util.pack(cdb_fmt, lua_util.unpack(values))
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
    if cursor ~= 0 then
      if opts.cdb then
        dump_cdb(out, opts, false, key, class_labels)
        out[key].elts = {}
      else
        dump_out(out, opts, false)
        clear_fcn(out)
      end
    elseif opts.cdb then
      dump_cdb(out, opts, true, key, class_labels)
    end

  until cursor == 0
end

local function dump_handler(opts)
  local patterns_seen = {}
  for _, cls in ipairs(classifiers) do
    -- Collect class labels for CDB packing
    local class_labels = {}
    for _, s in ipairs(cls.symbols) do
      class_labels[#class_labels + 1] = s.label
    end

    -- Connect to all shards to ensure complete dump
    local connections = {}
    local read_servers = cls.redis_params.read_servers
    if read_servers then
      local all_ups = read_servers:all_upstreams()
      if all_ups and #all_ups > 0 then
        for _, up in ipairs(all_ups) do
          local res, conn = connect_to_upstream(up, cls.redis_params)
          if res then
            connections[#connections + 1] = { up = up, conn = conn }
          else
            rspamd_logger.errx("cannot connect to redis shard %s", up:get_name())
          end
        end
      end
    end

    -- Fallback: single connection via round-robin
    if #connections == 0 then
      local res, conn = lua_redis.redis_connect_sync(cls.redis_params, false)
      if not res then
        rspamd_logger.errx("cannot connect to redis server: %s", cls.redis_params)
        os.exit(1)
      end
      connections[#connections + 1] = { conn = conn }
    end

    local out = {}
    local function check_keys(conn, sym)
      local sym_keys_pattern = string.format("%s_keys", sym)
      conn:add_cmd('SMEMBERS', { sym_keys_pattern })
      local ret, keys = conn:exec()

      if not ret then
        rspamd_logger.errx("cannot execute command to get keys: %s", keys)
        return
      end

      if not keys or #keys == 0 then
        return
      end

      if not opts.json then
        out[#out + 1] = string.format('"%s": %s\n', sym_keys_pattern,
            ucl.to_format(keys, 'json-compact'))
      end
      for _, k in ipairs(keys) do
        local pat = string.format('%s*_*', k)
        if not patterns_seen[pat] then
          conn:add_cmd('HGETALL', { k })
          local _ret, additional_keys = conn:exec()

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
            dump_pattern(conn, pat, opts, out, k, class_labels)
            patterns_seen[pat] = true
          end
        end
      end
    end

    for _, c in ipairs(connections) do
      for _, s in ipairs(cls.symbols) do
        check_keys(c.conn, s.symbol)
      end
    end

    if #out > 0 then
      dump_out(out, opts, true)
    end
  end
end

local function obj_to_redis_arguments(obj, opts, cmd_pipe)
  local key, value = next(obj)

  if type(key) == 'string' then
    if type(value) == 'table' then
      if not value[1] then
        if opts.mode == 'replace' then
          local cmd = 'HMSET'
          local params = { key }
          for k, v in pairs(value) do
            table.insert(params, k)
            table.insert(params, v)
          end
          table.insert(cmd_pipe, { cmd, params })
        else
          local cmd = 'HINCRBYFLOAT'
          local mult = 1.0
          if opts.mode == 'subtract' then
            mult = (-mult)
          end

          for k, v in pairs(value) do
            if tonumber(v) then
              v = tonumber(v)
              table.insert(cmd_pipe, { cmd, { key, k, tostring(v * mult) } })
            else
              table.insert(cmd_pipe, { 'HSET', { key, k, v } })
            end
          end
        end
      else
        -- Numeric table of elements (e.g. _keys) - it is actually a set in Redis
        for _, elt in ipairs(value) do
          table.insert(cmd_pipe, { 'SADD', { key, elt } })
        end
      end
    end
  end

  return cmd_pipe
end

local function execute_batch(batch, conns, opts)
  local cmd_pipe = {}

  for _, cmd in ipairs(batch) do
    obj_to_redis_arguments(cmd, opts, cmd_pipe)
  end

  if opts.no_operation then
    for _, cmd in ipairs(cmd_pipe) do
      rspamd_logger.messagex('%s %s', cmd[1], table.concat(cmd[2], ' '))
    end
  else
    for _, conn in ipairs(conns) do
      for _, cmd in ipairs(cmd_pipe) do
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
  local files = opts.file or { '-' }
  local conns = {}

  for _, cls in ipairs(classifiers) do
    local res, conn = lua_redis.redis_connect_sync(cls.redis_params, true)

    if not res then
      rspamd_logger.errx("cannot connect to redis server: %s", cls.redis_params)
      os.exit(1)
    end

    table.insert(conns, conn)
  end

  local batch = {}

  for _, f in ipairs(files) do
    local fd
    if f ~= '-' then
      fd = io.open(f, 'r')
      io.input(fd)
    end

    local cur_line = 1
    for line in io.lines() do
      local ucl_parser = ucl.parser()
      local res, err
      res, err = ucl_parser:parse_string(line)

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

    if fd then
      fd:close()
    end
  end

  if #batch > 0 then
    execute_batch(batch, conns, opts)
  end
end

-- Redis Lua scripts for migration
local export_script = [[
local result = redis.call('SCAN', ARGV[1], 'MATCH', ARGV[2], 'COUNT', ARGV[3])
local cursor = result[1]
local keys = result[2]
local data = {}
local key_names = {}
for i, k in ipairs(keys) do
  data[i] = {k, redis.call('HGETALL', k)}
  key_names[i] = k
end
return {cursor, cmsgpack.pack(data), cmsgpack.pack(key_names)}
]]

local import_script = [[
local data = cmsgpack.unpack(ARGV[1])
for _, entry in ipairs(data) do
  if #entry[2] > 0 then
    redis.call('HMSET', entry[1], unpack(entry[2]))
  end
end
return #data
]]

local delete_script = [[
local keys = cmsgpack.unpack(ARGV[1])
for _, k in ipairs(keys) do
  redis.call('DEL', k)
end
return #keys
]]

local function migrate_handler(opts)
  local stats = {
    checked = 0,
    correct = 0,
    migrated = 0,
    tokens = 0,
    errors = 0,
  }

  for _, cls in ipairs(classifiers) do
    local write_servers = cls.redis_params.write_servers
    if not write_servers then
      rspamd_logger.errx("no write servers configured, cannot migrate")
      os.exit(1)
    end

    local all_ups = write_servers:all_upstreams()
    if not all_ups or #all_ups <= 1 then
      rspamd_logger.messagex("only %s shard(s) configured, nothing to migrate",
          all_ups and #all_ups or 0)
      return
    end

    rspamd_logger.messagex("found %s shards to check for migration", #all_ups)

    -- Connect to every shard
    local shard_map = {}
    for _, up in ipairs(all_ups) do
      local res, conn = connect_to_upstream(up, cls.redis_params)
      if not res then
        rspamd_logger.errx("cannot connect to shard %s, aborting", up:get_name())
        os.exit(1)
      end
      shard_map[#shard_map + 1] = {
        name = up:get_name(),
        up = up,
        conn = conn,
      }
    end

    -- Migrate each symbol's keys
    for _, s in ipairs(cls.symbols) do
      local sym = s.symbol
      rspamd_logger.messagex("processing symbol: %s", sym)
      local sym_keys = string.format("%s_keys", sym)

      for shard_idx, shard in ipairs(shard_map) do
        shard.conn:add_cmd('SMEMBERS', { sym_keys })
        local ret, prefixes = shard.conn:exec()

        if not ret then
          rspamd_logger.errx("cannot get %s from shard %s: %s",
              sym_keys, shard.name, prefixes)
          stats.errors = stats.errors + 1
        elseif prefixes and #prefixes > 0 then
          rspamd_logger.messagex("  shard %s [%s/%s]: %s prefix key(s) for %s",
              shard.name, shard_idx, #shard_map, #prefixes, sym)

          for _, prefix in ipairs(prefixes) do
            stats.checked = stats.checked + 1

            -- Determine which shard this prefix should live on
            local target_up = write_servers:get_upstream_by_hash(prefix)
            local target_name = target_up:get_name()

            if target_name == shard.name then
              -- Already on the correct shard
              stats.correct = stats.correct + 1
            else
              -- Find target connection
              local target_conn
              for _, ts in ipairs(shard_map) do
                if ts.name == target_name then
                  target_conn = ts.conn
                  break
                end
              end

              if not target_conn then
                rspamd_logger.errx("    cannot find connection for target shard %s", target_name)
                stats.errors = stats.errors + 1
              else
                rspamd_logger.messagex("    migrating prefix '%s': %s -> %s",
                    prefix, shard.name, target_name)

                if opts.dry_run then
                  stats.migrated = stats.migrated + 1
                else
                  -- 1. Copy the prefix metadata hash
                  shard.conn:add_cmd('HGETALL', { prefix })
                  local hret, hdata = shard.conn:exec()

                  if hret and hdata and #hdata > 0 then
                    local hmset_args = { prefix }
                    for _, v in ipairs(hdata) do
                      hmset_args[#hmset_args + 1] = v
                    end
                    target_conn:add_cmd('HMSET', hmset_args)
                    local mret, merr = target_conn:exec()
                    if not mret then
                      rspamd_logger.errx("    failed to copy metadata for %s: %s", prefix, merr)
                      stats.errors = stats.errors + 1
                    end
                  end

                  -- 2. Scan and migrate token keys in batches
                  local scan_pattern = string.format('%s_*', prefix)
                  local cursor = "0"

                  repeat
                    shard.conn:add_cmd('EVAL', {
                      export_script, '0',
                      cursor, scan_pattern, tostring(opts.batch_size)
                    })
                    local eret, eresults = shard.conn:exec()

                    if not eret then
                      rspamd_logger.errx("    export script failed for %s: %s", prefix, eresults)
                      stats.errors = stats.errors + 1
                      break
                    end

                    cursor = eresults[1]
                    local packed_data = eresults[2]
                    local packed_keys = eresults[3]

                    -- Import to target
                    if packed_data and #packed_data > 0 then
                      target_conn:add_cmd('EVAL', {
                        import_script, '0', packed_data
                      })
                      local iret, ires = target_conn:exec()

                      if not iret then
                        rspamd_logger.errx("    import script failed for %s: %s", prefix, ires)
                        stats.errors = stats.errors + 1
                      else
                        stats.tokens = stats.tokens + (tonumber(ires) or 0)
                      end
                    end

                    -- Delete from source (unless --no-delete)
                    if not opts.no_delete and packed_keys and #packed_keys > 0 then
                      shard.conn:add_cmd('EVAL', {
                        delete_script, '0', packed_keys
                      })
                      local dret, derr = shard.conn:exec()
                      if not dret then
                        rspamd_logger.errx("    delete script failed for %s: %s", prefix, derr)
                        stats.errors = stats.errors + 1
                      end
                    end
                  until cursor == "0"

                  -- 3. Update _keys sets
                  target_conn:add_cmd('SADD', { sym_keys, prefix })
                  target_conn:exec()

                  shard.conn:add_cmd('SREM', { sym_keys, prefix })
                  shard.conn:exec()

                  -- 4. Delete source prefix hash (unless --no-delete)
                  if not opts.no_delete then
                    shard.conn:add_cmd('DEL', { prefix })
                    shard.conn:exec()
                  end

                  stats.migrated = stats.migrated + 1
                end
              end
            end
          end
        end
      end
    end
  end

  rspamd_logger.messagex("migration %s: checked=%s correct=%s migrated=%s tokens=%s errors=%s",
      opts.dry_run and "dry-run complete" or "complete",
      stats.checked, stats.correct, stats.migrated, stats.tokens, stats.errors)
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
      for _, cls in ipairs(classifier) do
        if cls.bayes then
          cls = cls.bayes
        end
        if cls.backend and cls.backend == 'redis' then
          check_redis_classifier(cls, obj)
        end
      end
    else
      if classifier.bayes then

        classifier = classifier.bayes
        if classifier[1] then
          for _, cls in ipairs(classifier) do
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
    opts.file = { opts.file }
  elseif type(opts.file) == 'none' then
    opts.file = {}
  end

  if command == 'dump' then
    dump_handler(opts)
  elseif command == 'restore' then
    restore_handler(opts)
  elseif command == 'migrate' then
    migrate_handler(opts)
  else
    parser:error('command %s is not implemented', command)
  end
end

return {
  name = 'statistics_dump',
  aliases = { 'stat_dump', 'bayes_dump' },
  handler = handler,
  description = parser._description
}
