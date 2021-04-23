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

local N = "statistics_dump"
local E = {}
local classifiers = {}

-- Define command line options
local parser = argparse()
    :name "rspamadm statistics_dump"
    :description "Dump/restore Rspamd statistics"
    :help_description_margin(30)
    :command_target("command")
    :require_command(true)

parser:option "-c --config"
      :description "Path to config file"
      :argname("<cfg>")
      :default(rspamd_paths["CONFDIR"] .. "/" .. "rspamd.conf")

-- Extract subcommand
local dump = parser:command "dump d"
                   :description "Dump bayes statistics"
dump:flag "-s --sort"
    :description "Sort output"
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
       :args "+"

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

local function dump_handler(opts)
  for _,cls in ipairs(classifiers) do
    local res,conn = lua_redis.redis_connect_sync(cls.redis_params, false)

    if not res then
      rspamd_logger.errx("cannot connect to redis server: %s", cls.redis_params)
      os.exit(1)
    end

    local cursor = 0

    repeat
      conn:add_cmd('SCAN', {tostring(cursor),
                            'MATCH', 'RS*_*',
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
          tokens[elts[(i + 1)/2]] = hash_content
        end
      end

      for hkey,tok in pairs(tokens) do
        rspamd_logger.messagex('%s: %s', hkey, tok)
      end

    until cursor == 0
  end
end

local function restore_handler(opts)

end

local function handler(args)
  local opts = parser:parse(args)

  local command = opts.command

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