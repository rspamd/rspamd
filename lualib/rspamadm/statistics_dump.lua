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

parser:option "-S --classifier"
    :description "Classifier name (required when multiple classifiers configured)"
    :argname("<name>")

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

    -- Derive classifier name: explicit name > first symbol
    local cls_name = cls.name
    if not cls_name then
      if symbols[1] then
        cls_name = symbols[1].symbol
      else
        cls_name = 'unknown'
      end
    end

    table.insert(classifiers, {
      name = cls_name,
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
  local up_addr = up:get_addr()
  if not up_addr then
    rspamd_logger.errx("cannot connect to redis %s: address not resolved yet",
        up:get_name())
    return false, nil
  end
  local ret, conn = rspamd_redis.connect_sync({
    host = up_addr,
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

-- Maximum commands per pipeline exec() to avoid Lua stack overflow
local pipeline_max = 1000

local append_redis_hash_hmset
local exec_redis_commands

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

    -- Pipeline HGETALL in chunks to avoid stack overflow
    for chunk_start = 1, #elts, pipeline_max do
      local chunk_end = math.min(chunk_start + pipeline_max - 1, #elts)
      for ei = chunk_start, chunk_end do
        conn:add_cmd('HGETALL', { elts[ei] })
      end
      local all_results = { conn:exec() }

      for i = 1, #all_results, 2 do
        local r, hash_content = all_results[i], all_results[i + 1]
        if r then
          local data = redis_map_zip(hash_content)
          tokens[#tokens + 1] = {
            key = elts[chunk_start + (i - 1) / 2],
            data = data,
          }
        end
      end
      all_results = nil
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

local function select_classifier(opts)
  if #classifiers == 0 then
    rspamd_logger.errx("no redis classifiers found in config")
    os.exit(1)
  end

  if #classifiers == 1 then
    return { classifiers[1] }
  end

  -- Multiple classifiers: require --classifier
  if not opts.classifier then
    local names = {}
    for _, cls in ipairs(classifiers) do
      local syms = {}
      for _, s in ipairs(cls.symbols) do
        syms[#syms + 1] = s.symbol
      end
      names[#names + 1] = string.format("  %s (symbols: %s)", cls.name, table.concat(syms, ', '))
    end
    rspamd_logger.errx("multiple classifiers found, use --classifier to select one:\n%s",
        table.concat(names, '\n'))
    os.exit(1)
  end

  for _, cls in ipairs(classifiers) do
    if cls.name == opts.classifier then
      return { cls }
    end
  end

  rspamd_logger.errx("classifier '%s' not found", opts.classifier)
  os.exit(1)
end

local function dump_handler(opts)
  local selected = select_classifier(opts)
  local patterns_seen = {}
  for _, cls in ipairs(selected) do
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
        local pat = string.format('%s_*', k)
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

local function estimate_redis_commands(obj, opts)
  local key, value = next(obj)

  if type(key) ~= 'string' or type(value) ~= 'table' then
    return 0
  end

  if not value[1] then
    local n = 0

    if opts.mode == 'replace' then
      return 1
    end

    for _ in pairs(value) do
      n = n + 1
    end

    return n
  end

  return #value
end

-- Send cmd_pipe commands to a single connection starting from start_idx.
-- Returns true on success, or (false, err, resume_idx) on failure where
-- resume_idx is the chunk start index that should be retried.
local function send_cmd_pipe(cmd_pipe, conn, start_idx)
  for i = start_idx, #cmd_pipe, pipeline_max do
    local chunk_end = math.min(i + pipeline_max - 1, #cmd_pipe)
    local added = 0

    for j = i, chunk_end do
      local is_ok, err = conn:add_cmd(cmd_pipe[j][1], cmd_pipe[j][2])

      if not is_ok then
        rspamd_logger.errx("cannot add command: %s with args: %s: %s",
            cmd_pipe[j][1], cmd_pipe[j][2], err)
        -- add_cmd failed: no commands from this chunk were sent to Redis,
        -- safe to retry from this chunk index
        return false, err, i
      end

      added = added + 1
    end

    if added > 0 then
      local ret, err = conn:exec()

      if not ret then
        local chunk_size = chunk_end - i + 1
        rspamd_logger.errx("cannot execute restore batch: %s; skipping %s commands in failed chunk to avoid double-counting",
            err, chunk_size)
        -- exec() failed: some commands in this chunk may have been applied,
        -- advance past this chunk to avoid double-counting
        return false, err, i + pipeline_max
      end
    end
  end

  return true
end

local function reconnect_all(selected)
  local new_conns = {}

  for _, cls in ipairs(selected) do
    local res, conn = lua_redis.redis_connect_sync(cls.redis_params, true)

    if not res then
      rspamd_logger.errx("cannot reconnect to redis server: %s", cls.redis_params)
      return nil
    end

    table.insert(new_conns, conn)
  end

  return new_conns
end

local max_retries = 3

local function flush_restore_batch(batch, conns, selected, opts)
  if #batch == 0 then
    return true, conns
  end

  local cmd_pipe = {}
  for _, cmd in ipairs(batch) do
    obj_to_redis_arguments(cmd, opts, cmd_pipe)
  end

  if opts.no_operation then
    for _, cmd in ipairs(cmd_pipe) do
      rspamd_logger.messagex('%s %s', cmd[1], table.concat(cmd[2], ' '))
    end
    clear_fcn(batch)
    return true, conns
  end

  for conn_idx, conn in ipairs(conns) do
    local resume_idx = 1

    for attempt = 1, max_retries do
      local ok, err, next_idx = send_cmd_pipe(cmd_pipe, conn, resume_idx)

      if ok then
        break
      end

      if attempt == max_retries then
        rspamd_logger.errx("batch failed after %s attempts: %s", max_retries, err)
        return false, conns
      end

      resume_idx = next_idx or resume_idx
      rspamd_logger.messagex("batch failed at command %s/%s, reconnecting (attempt %s/%s)",
          resume_idx, #cmd_pipe, attempt, max_retries)

      -- Brief pause before reconnecting to handle transient Redis unavailability
      os.execute("sleep 1")

      local new_conns = reconnect_all(selected)

      if not new_conns then
        rspamd_logger.errx("reconnection failed on attempt %s", attempt)
        return false, conns
      end

      conns = new_conns
      conn = conns[conn_idx]
    end
  end

  clear_fcn(batch)
  return true, conns
end

local function restore_handler(opts)
  local selected = select_classifier(opts)
  local files = opts.file or { '-' }
  local conns = {}
  local restore_pipeline_limit = math.max(100, math.min(opts.batch_size, pipeline_max))

  for _, cls in ipairs(selected) do
    local res, conn = lua_redis.redis_connect_sync(cls.redis_params, true)

    if not res then
      rspamd_logger.errx("cannot connect to redis server: %s", cls.redis_params)
      os.exit(1)
    end

    table.insert(conns, conn)
  end

  local batch = {}
  local pending_cmds = 0
  local total_lines = 0
  local total_cmds = 0
  local total_batches = 0
  local start_time = os.time()
  local last_report_time = start_time

  rspamd_logger.messagex("starting restore (batch_size=%s, pipeline_max=%s, mode=%s)",
      opts.batch_size, pipeline_max, opts.mode or 'add')

  for _, f in ipairs(files) do
    local fd
    if f ~= '-' then
      fd = io.open(f, 'r')
      io.input(fd)
    end

    rspamd_logger.messagex("processing file: %s", f)
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
      pending_cmds = pending_cmds + estimate_redis_commands(batch[#batch], opts)
      cur_line = cur_line + 1

      if #batch >= opts.batch_size or pending_cmds >= restore_pipeline_limit then
        local ok
        ok, conns = flush_restore_batch(batch, conns, selected, opts)
        if not ok then
          rspamd_logger.errx("restore failed at line %s (total restored: %s lines, %s commands in %s batches)",
              total_lines + cur_line, total_lines, total_cmds, total_batches)
          os.exit(1)
        end
        total_cmds = total_cmds + pending_cmds
        total_batches = total_batches + 1
        pending_cmds = 0

        -- Incremental GC after each batch to spread collection cost
        collectgarbage('step', 100)

        local now = os.time()
        if now - last_report_time >= 10 then
          local elapsed = now - start_time
          local rate = total_lines > 0 and math.floor(total_lines / elapsed) or 0
          rspamd_logger.messagex("restored %s lines, %s commands in %s batches (%s lines/sec, %s KB lua mem)",
              total_lines + cur_line - 1, total_cmds, total_batches, rate,
              math.floor(collectgarbage('count')))
          last_report_time = now
        end
      end
    end

    total_lines = total_lines + cur_line - 1

    if fd then
      fd:close()
    end

    -- Full GC between files
    collectgarbage('collect')
  end

  if #batch > 0 then
    local ok
    ok, conns = flush_restore_batch(batch, conns, selected, opts)
    if not ok then
      rspamd_logger.errx("restore failed on final batch (total restored: %s lines, %s commands)",
          total_lines, total_cmds)
      os.exit(1)
    end
    total_cmds = total_cmds + pending_cmds
    total_batches = total_batches + 1
  end

  local elapsed = os.time() - start_time
  if elapsed == 0 then
    elapsed = 1
  end
  rspamd_logger.messagex("restore complete: %s lines, %s commands in %s batches (%s sec, %s lines/sec)",
      total_lines, total_cmds, total_batches, elapsed, math.floor(total_lines / elapsed))
end

-- Migrate a single prefix's token keys from source to target using pipelined commands.
-- SCAN on source, pipeline HGETALL, pipeline HMSET to target, pipeline DEL on source.
-- Returns number of tokens migrated.
local function collect_prefix_token_keys(src_conn, prefixes, batch_size)
  local keys = {}
  local seen = {}

  for _, prefix in ipairs(prefixes) do
    local scan_pattern = string.format('%s_*', prefix)
    local cursor = "0"

    repeat
      src_conn:add_cmd('SCAN', { cursor, 'MATCH', scan_pattern,
                                 'COUNT', tostring(batch_size) })
      local ret, results = src_conn:exec()

      if not ret then
        rspamd_logger.errx("SCAN failed for %s: %s", prefix, results)
        return nil, true
      end

      cursor = results[1]
      local scanned = results[2]

      if scanned and #scanned > 0 then
        for _, k in ipairs(scanned) do
          if not seen[k] then
            seen[k] = true
            keys[#keys + 1] = k
          end
        end
      end
    until cursor == "0"
  end

  return keys, false
end

local function migrate_token_keys(src_conn, dst_conn, keys, no_delete)
  local total_tokens = 0

  for i = 1, #keys, pipeline_max do
    local chunk_end = math.min(i + pipeline_max - 1, #keys)

    for j = i, chunk_end do
      src_conn:add_cmd('HGETALL', { keys[j] })
    end

    local all_results = { src_conn:exec() }
    local dst_cmds = {}
    local src_del_cmds = {}

    for j = i, chunk_end do
      local idx = (j - i) * 2 + 1
      local hret, hdata = all_results[idx], all_results[idx + 1]

      if hret and append_redis_hash_hmset(dst_cmds, keys[j], hdata) then
        total_tokens = total_tokens + 1
        if not no_delete then
          src_del_cmds[#src_del_cmds + 1] = { 'DEL', { keys[j] } }
        end
      end
    end

    all_results = nil

    if not exec_redis_commands(dst_conn, dst_cmds) then
      return total_tokens, true
    end

    if not no_delete and not exec_redis_commands(src_conn, src_del_cmds) then
      return total_tokens, true
    end
  end

  return total_tokens, false
end

append_redis_hash_hmset = function(cmds, key, hash_data)
  if hash_data and #hash_data > 0 then
    local args = { key }
    for _, v in ipairs(hash_data) do
      args[#args + 1] = v
    end
    cmds[#cmds + 1] = { 'HMSET', args }
    return true
  end

  return false
end

exec_redis_commands = function(conn, cmds)
  if #cmds == 0 then
    return true
  end

  for i = 1, #cmds, pipeline_max do
    local chunk_end = math.min(i + pipeline_max - 1, #cmds)

    for j = i, chunk_end do
      local is_ok, err = conn:add_cmd(cmds[j][1], cmds[j][2])

      if not is_ok then
        rspamd_logger.errx("cannot add command: %s with args: %s: %s",
            cmds[j][1], cmds[j][2], err)
        return false
      end
    end

    local ret, err = conn:exec()
    if not ret then
      rspamd_logger.errx("cannot execute redis pipeline: %s", err)
      return false
    end
  end

  return true
end

local function migrate_prefix_group(prefixes, src_conn, dst_conn, sym_keys, batch_size, no_delete)
  local stats = {
    migrated = 0,
    tokens = 0,
    errors = 0,
  }

  if #prefixes == 0 then
    return stats
  end

  for i = 1, #prefixes, pipeline_max do
    local chunk_end = math.min(i + pipeline_max - 1, #prefixes)

    for j = i, chunk_end do
      src_conn:add_cmd('HGETALL', { prefixes[j] })
    end

    local all_results = { src_conn:exec() }
    local dst_meta_cmds = {}
    local dst_keys_cmds = {}
    local src_keys_cmds = {}
    local src_meta_del_cmds = {}

    for j = i, chunk_end do
      local idx = (j - i) * 2 + 1
      local prefix = prefixes[j]
      local hret, hdata = all_results[idx], all_results[idx + 1]

      if hret then
        append_redis_hash_hmset(dst_meta_cmds, prefix, hdata)
        dst_keys_cmds[#dst_keys_cmds + 1] = { 'SADD', { sym_keys, prefix } }
        if not no_delete then
          src_keys_cmds[#src_keys_cmds + 1] = { 'SREM', { sym_keys, prefix } }
          src_meta_del_cmds[#src_meta_del_cmds + 1] = { 'DEL', { prefix } }
        end
        stats.migrated = stats.migrated + 1
      else
        rspamd_logger.errx("cannot get prefix metadata for %s", prefix)
        stats.errors = stats.errors + 1
      end
    end

    all_results = nil

    if not exec_redis_commands(dst_conn, dst_meta_cmds) then
      stats.errors = stats.errors + (chunk_end - i + 1)
      return stats
    end

    local chunk_prefixes = {}
    for j = i, chunk_end do
      chunk_prefixes[#chunk_prefixes + 1] = prefixes[j]
    end

    local token_keys, scan_error = collect_prefix_token_keys(src_conn, chunk_prefixes, batch_size)
    if scan_error then
      stats.errors = stats.errors + #chunk_prefixes
      return stats
    end

    if token_keys and #token_keys > 0 then
      local tok_count, had_error = migrate_token_keys(src_conn, dst_conn, token_keys, no_delete)
      stats.tokens = stats.tokens + tok_count

      if had_error then
        stats.errors = stats.errors + #chunk_prefixes
        return stats
      end
    end

    if not exec_redis_commands(dst_conn, dst_keys_cmds) then
      stats.errors = stats.errors + (chunk_end - i + 1)
      return stats
    end

    if not no_delete then
      if not exec_redis_commands(src_conn, src_keys_cmds) then
        stats.errors = stats.errors + (chunk_end - i + 1)
        return stats
      end

      if not exec_redis_commands(src_conn, src_meta_del_cmds) then
        stats.errors = stats.errors + (chunk_end - i + 1)
        return stats
      end
    end
  end

  return stats
end

local function migrate_handler(opts)
  local selected = select_classifier(opts)
  local stats = {
    checked = 0,
    correct = 0,
    migrated = 0,
    tokens = 0,
    errors = 0,
  }

  for _, cls in ipairs(selected) do
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

    -- Build name→shard index for fast lookup
    local shard_by_name = {}
    for _, shard in ipairs(shard_map) do
      shard_by_name[shard.name] = shard
    end

    -- Phase 1: Collect all prefixes from all shards, determine migration plan
    for _, s in ipairs(cls.symbols) do
      local sym = s.symbol
      rspamd_logger.messagex("processing symbol: %s", sym)
      local sym_keys = string.format("%s_keys", sym)

      -- Collect prefixes per shard and classify
      local misplaced = {} -- { {prefix, src_shard, dst_shard}, ... }

      for shard_idx, shard in ipairs(shard_map) do
        shard.conn:add_cmd('SMEMBERS', { sym_keys })
        local ret, prefixes = shard.conn:exec()

        if not ret then
          rspamd_logger.errx("cannot get %s from shard %s: %s",
              sym_keys, shard.name, prefixes)
          stats.errors = stats.errors + 1
        elseif prefixes and #prefixes > 0 then
          rspamd_logger.messagex("  shard %s [%s/%s]: %s prefix(es)",
              shard.name, shard_idx, #shard_map, #prefixes)

          for _, prefix in ipairs(prefixes) do
            stats.checked = stats.checked + 1
            local target_up = write_servers:get_upstream_by_hash(prefix)
            if not target_up then
              rspamd_logger.errx('no upstream available for prefix %s; aborting redistribute scan',
                  prefix)
              return false
            end
            local target_name = target_up:get_name()

            if target_name == shard.name then
              stats.correct = stats.correct + 1
            else
              misplaced[#misplaced + 1] = {
                prefix = prefix,
                src = shard,
                dst = shard_by_name[target_name],
              }
            end
          end
        end
      end

      if #misplaced == 0 then
        rspamd_logger.messagex("  all prefixes on correct shards")
      else
        rspamd_logger.messagex("  %s prefix(es) need migration", #misplaced)
      end

      -- Phase 2: Migrate misplaced prefixes grouped by shard pair to reduce round-trips
      local grouped = {}

      for pi, m in ipairs(misplaced) do
        if not m.dst then
          rspamd_logger.errx("    cannot find target shard for prefix '%s'", m.prefix)
          stats.errors = stats.errors + 1
        else
          rspamd_logger.messagex("    [%s/%s] '%s': %s -> %s",
              pi, #misplaced, m.prefix, m.src.name, m.dst.name)

          stats.migrated = stats.migrated + 1

          if not opts.dry_run then
            local group_key = string.format('%s\0%s', m.src.name, m.dst.name)
            local group = grouped[group_key]

            if not group then
              group = {
                src = m.src,
                dst = m.dst,
                prefixes = {},
              }
              grouped[group_key] = group
            end

            group.prefixes[#group.prefixes + 1] = m.prefix
          end
        end

        if pi % 100 == 0 then
          collectgarbage('collect')
        end
      end

      if not opts.dry_run then
        for _, group in pairs(grouped) do
          rspamd_logger.messagex("  migrating %s prefix(es): %s -> %s",
              #group.prefixes, group.src.name, group.dst.name)
          local group_stats = migrate_prefix_group(group.prefixes,
              group.src.conn, group.dst.conn, sym_keys, opts.batch_size, opts.no_delete)
          stats.tokens = stats.tokens + group_stats.tokens
          stats.errors = stats.errors + group_stats.errors
        end
      end

      misplaced = nil
      collectgarbage('collect')
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
