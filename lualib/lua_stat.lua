--[[
Copyright (c) 2018, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

local logger = require "rspamd_logger"
local sqlite3 = require "rspamd_sqlite3"
local util = require "rspamd_util"
local lua_redis = require "lua_redis"
local exports = {}

local N = "stat_tools" -- luacheck: ignore (maybe unused)

-- Performs synchronous conversion of redis schema
local function convert_bayes_schema(redis_params,  symbol_spam, symbol_ham, expire)

  -- Old schema is the following one:
  -- Keys are named <symbol>[<user>]
  -- Elements are placed within hash:
  -- BAYES_SPAM -> {<id1>: <num_hits>, <id2>: <num_hits> ...}
  -- In new schema it is changed to a more extensible schema:
  -- Keys are named RS[<user>]_<id> -> {'H': <ham_hits>, 'S': <spam_hits>}
  -- So we can expire individual records, measure most popular elements by zranges,
  -- add new fields, such as tokens etc

  local res,conn = lua_redis.redis_connect_sync(redis_params, true)

  if not res then
    logger.errx("cannot connect to redis server")
    return false
  end

  -- KEYS[1]: key to check (e.g. 'BAYES_SPAM')
  -- KEYS[2]: hash key ('S' or 'H')
  -- KEYS[3]: expire
  local lua_script = [[
local keys = redis.call('SMEMBERS', KEYS[1]..'_keys')
local nconverted = 0

for _,k in ipairs(keys) do
  local elts = redis.call('HGETALL', k)
  local neutral_prefix = string.gsub(k, KEYS[1], 'RS')
  local real_key

  for i,v in ipairs(elts) do

    if i % 2 ~= 0 then
      real_key = v
    else
      local nkey = string.format('%s_%s', neutral_prefix, real_key)
      redis.call('HSET', nkey, KEYS[2], v)
      if KEYS[3] and tonumber(KEYS[3]) > 0 then
        redis.call('EXPIRE', nkey, KEYS[3])
      end
      nconverted = nconverted + 1
    end
  end
end

return nconverted
]]

  conn:add_cmd('EVAL', {lua_script, '3', symbol_spam, 'S', tostring(expire)})
  local ret
  ret, res = conn:exec()

  if not ret then
    logger.errx('error converting symbol %s: %s', symbol_spam, res)
    return false
  else
    logger.messagex('converted %s elements from symbol %s', res, symbol_spam)
  end

  conn:add_cmd('EVAL', {lua_script, '3', symbol_ham, 'H', tostring(expire)})
  ret, res = conn:exec()

  if not ret then
    logger.errx('error converting symbol %s: %s', symbol_ham, res)
    return false
  else
    logger.messagex('converted %s elements from symbol %s', res, symbol_ham)
  end

  -- We can now convert metadata: set + learned + version
  -- KEYS[1]: key to check (e.g. 'BAYES_SPAM')
  -- KEYS[2]: learn key (e.g. 'learns_spam' or 'learns_ham')
  lua_script = [[
local keys = redis.call('SMEMBERS', KEYS[1]..'_keys')

for _,k in ipairs(keys) do
  local learns = redis.call('HGET', k, 'learns')
  local neutral_prefix = string.gsub(k, KEYS[1], 'RS')

  redis.call('HSET', neutral_prefix, KEYS[2], learns)
  redis.call('SADD', KEYS[1]..'_keys', neutral_prefix)
  redis.call('SREM', KEYS[1]..'_keys', k)
  redis.call('DEL', k)
  redis.call('SET', KEYS[1]..'_version', '2')
end
]]

  conn:add_cmd('EVAL', {lua_script, '2', symbol_spam, 'learns_spam'})
  ret = conn:exec()

  if not ret then
    logger.errx('error converting metadata for symbol %s', symbol_spam)
    return false
  end

  conn:add_cmd('EVAL', {lua_script, '2', symbol_ham, 'learns_ham'})
  ret = conn:exec()

  if not ret then
    logger.errx('error converting metadata for symbol %s', symbol_ham)
    return false
  end

  return true
end

exports.convert_bayes_schema = convert_bayes_schema

-- It now accepts both ham and spam databases
-- parameters:
-- redis_params - how do we connect to a redis server
-- sqlite_db_spam - name for sqlite database with spam tokens
-- sqlite_db_ham - name for sqlite database with ham tokens
-- symbol_ham - name for symbol representing spam, e.g. BAYES_SPAM
-- symbol_spam - name for symbol representing ham, e.g. BAYES_HAM
-- learn_cache_spam - name for sqlite database with spam learn cache
-- learn_cache_ham - name for sqlite database with ham learn cache
-- reset_previous - if true, then the old database is flushed (slow)
local function convert_sqlite_to_redis(redis_params,
          sqlite_db_spam, sqlite_db_ham, symbol_spam, symbol_ham,
          learn_cache_db, expire, reset_previous)
  local nusers = 0
  local lim = 1000 -- Update each 1000 tokens
  local users_map = {}
  local converted = 0

  local db_spam = sqlite3.open(sqlite_db_spam)
  if not db_spam then
    logger.errx('Cannot open source db: %s', sqlite_db_spam)
    return false
  end
  local db_ham = sqlite3.open(sqlite_db_ham)
  if not db_ham then
    logger.errx('Cannot open source db: %s', sqlite_db_ham)
    return false
  end

  local res,conn = lua_redis.redis_connect_sync(redis_params, true)

  if not res then
    logger.errx("cannot connect to redis server")
    return false
  end

  if reset_previous then
    -- Do a more complicated cleanup
    -- execute a lua script that cleans up data
    local script = [[
local members = redis.call('SMEMBERS', KEYS[1]..'_keys')

for _,prefix in ipairs(members) do
  local keys = redis.call('KEYS', prefix..'*')
  redis.call('DEL', keys)
end
]]
    -- Common keys
    for _,sym in ipairs({symbol_spam, symbol_ham}) do
      logger.messagex('Cleaning up old data for %s', sym)
      conn:add_cmd('EVAL', {script, '1', sym})
      conn:exec()
      conn:add_cmd('DEL', {sym .. "_version"})
      conn:add_cmd('DEL', {sym .. "_keys"})
      conn:exec()
    end

    if learn_cache_db then
      -- Cleanup learned_cache
      logger.messagex('Cleaning up old data learned cache')
      conn:add_cmd('DEL', {"learned_ids"})
      conn:exec()
    end
  end

  local function convert_db(db, is_spam)
    -- Map users and languages
    local what = 'ham'
    if is_spam then
      what = 'spam'
    end

    local learns = {}
    db:sql('BEGIN;')
    -- Fill users mapping
    for row in db:rows('SELECT * FROM users;') do
      if row.id == '0' then
        users_map[row.id] = ''
      else
        users_map[row.id] = row.name
      end
      learns[row.id] = row.learns
      nusers = nusers + 1
    end

    -- Workaround for old databases
    for row in db:rows('SELECT * FROM languages') do
      if learns['0'] then
        learns['0'] = learns['0'] + row.learns
      else
        learns['0'] = row.learns
      end
    end

    local function send_batch(tokens, prefix)
      -- We use the new schema: RS[user]_token -> H=ham count
      --                                          S=spam count
      local hash_key = 'H'
      if is_spam then
        hash_key = 'S'
      end
      for _,tok in ipairs(tokens) do
        -- tok schema:
        -- tok[1] = token_id (uint64 represented as a string)
        -- tok[2] = token value (number)
        -- tok[3] = user_map[user_id] or ''
        local rkey = string.format('%s%s_%s', prefix, tok[3], tok[1])
        conn:add_cmd('HINCRBYFLOAT', {rkey, hash_key, tostring(tok[2])})

        if expire and expire ~= 0 then
          conn:add_cmd('EXPIRE', {rkey, tostring(expire)})
        end
      end

      return conn:exec()
    end
    -- Fill tokens, sending data to redis each `lim` records

    local ntokens = db:query('SELECT count(*) as c FROM tokens')['c']
    local tokens = {}
    local num = 0
    local total = 0

    for row in db:rows('SELECT token,value,user FROM tokens;') do
      local user = ''
      if row.user ~= 0 and users_map[row.user] then
        user = users_map[row.user]
      end

      table.insert(tokens, {row.token, row.value, user})
      num = num + 1
      total = total + 1
      if num > lim then
        -- TODO: we use the default 'RS' prefix, it can be false in case of
        -- classifiers with labels
        local ret,err_str = send_batch(tokens, 'RS')
        if not ret then
          logger.errx('Cannot send tokens to the redis server: ' .. err_str)
          db:sql('COMMIT;')
          return false
        end

        num = 0
        tokens = {}
      end

      io.write(string.format('Processed batch %s: %s/%s\r', what, total, ntokens))
    end
    -- Last batch
    if #tokens > 0 then
      local ret,err_str = send_batch(tokens, 'RS')
      if not ret then
        logger.errx('Cannot send tokens to the redis server: ' .. err_str)
        db:sql('COMMIT;')
        return false
      end

      io.write(string.format('Processed batch %s: %s/%s\r', what, total, ntokens))
    end
    io.write('\n')

    converted = converted + total

    -- Close DB
    db:sql('COMMIT;')
    local symbol = symbol_ham
    local learns_elt = "learns_ham"

    if is_spam then
      symbol = symbol_spam
      learns_elt = "learns_spam"
    end

    for id,learned in pairs(learns) do
      local user = users_map[id]
      if not conn:add_cmd('HSET', {'RS' .. user, learns_elt, learned}) then
        logger.errx('Cannot update learns for user: ' .. user)
        return false
      end
      if not conn:add_cmd('SADD', {symbol .. '_keys', 'RS' .. user}) then
        logger.errx('Cannot update learns for user: ' .. user)
        return false
      end
    end
    -- Set version
    conn:add_cmd('SET', {symbol..'_version', '2'})
    return conn:exec()
  end

  logger.messagex('Convert spam tokens')
  if not convert_db(db_spam, true) then
    return false
  end

  logger.messagex('Convert ham tokens')
  if not convert_db(db_ham, false) then
    return false
  end

  if learn_cache_db then
    logger.messagex('Convert learned ids from %s', learn_cache_db)
    local db = sqlite3.open(learn_cache_db)
    local ret = true
    local total = 0

    if not db then
      logger.errx('Cannot open cache database: ' .. learn_cache_db)
      return false
    end

    db:sql('BEGIN;')

    for row in db:rows('SELECT * FROM learns;') do
      local is_spam
      local digest = tostring(util.encode_base32(row.digest))

      if row.flag == '0' then
        is_spam = '-1'
      else
        is_spam = '1'
      end

      if not conn:add_cmd('HSET', {'learned_ids', digest, is_spam}) then
        logger.errx('Cannot add hash: ' .. digest)
        ret = false
      else
        total = total + 1
      end
    end
    db:sql('COMMIT;')

    if ret then
      conn:exec()
    end

    if ret then
      logger.messagex('Converted %s cached items from sqlite3 learned cache to redis',
        total)
    else
      logger.errx('Error occurred during sending data to redis')
    end
  end

  logger.messagex('Migrated %s tokens for %s users for symbols (%s, %s)',
      converted, nusers, symbol_spam, symbol_ham)
  return true
end

exports.convert_sqlite_to_redis = convert_sqlite_to_redis

-- Loads sqlite3 based classifiers and output data in form of array of objects:
-- [
--  {
--  symbol_spam = XXX
--  symbol_ham = YYY
--  db_spam = XXX.sqlite
--  db_ham = YYY.sqlite
--  learn_cahe = ZZZ.sqlite
--  per_user = true/false
--  label = str
--  }
-- ]
local function load_sqlite_config(cfg)
  local result = {}

  local function parse_classifier(cls)
    local tbl = {}
    if cls.cache then
      local cache = cls.cache
      if cache.type == 'sqlite3' and (cache.file or cache.path) then
        tbl.learn_cache = (cache.file or cache.path)
      end
    end

    if cls.per_user then
      tbl.per_user = cls.per_user
    end

    if cls.label then
      tbl.label = cls.label
    end

    local statfiles = cls.statfile
    for _,stf in ipairs(statfiles) do
      local path = (stf.file or stf.path or stf.db or stf.dbname)
      local symbol = stf.symbol or 'undefined'

      if not path then
        logger.errx('no path defined for statfile %s', symbol)
      else

        local spam
        if stf.spam then
          spam = stf.spam
        else
          if string.match(symbol:upper(), 'SPAM') then
            spam = true
          else
            spam = false
          end
        end

        if spam then
          tbl.symbol_spam = symbol
          tbl.db_spam = path
        else
          tbl.symbol_ham = symbol
          tbl.db_ham = path
        end
      end
    end

    if tbl.symbol_spam and tbl.symbol_ham and tbl.db_ham and tbl.db_spam then
      table.insert(result, tbl)
    end
  end

  local classifier = cfg.classifier

  if classifier then
    if classifier[1] then
      for _,cls in ipairs(classifier) do
        if cls.bayes then cls = cls.bayes end
        if cls.backend and cls.backend == 'sqlite3' then
          parse_classifier(cls)
        end
      end
    else
      if classifier.bayes then
        classifier = classifier.bayes
        if classifier[1] then
          for _,cls in ipairs(classifier) do
            if cls.backend and cls.backend == 'sqlite3' then
              parse_classifier(cls)
            end
          end
        else
          if classifier.backend and classifier.backend == 'sqlite3' then
            parse_classifier(classifier)
          end
        end
      end
    end
  end

  return result
end

exports.load_sqlite_config = load_sqlite_config

-- A helper method that suggests a user how to configure Redis based
-- classifier based on the existing sqlite classifier
local function redis_classifier_from_sqlite(sqlite_classifier, expire)
  local result = {
    new_schema = true,
    backend = 'redis',
    cache = {
      backend = 'redis'
    },
    statfile = {
      [sqlite_classifier.symbol_spam] = {
        spam = true
      },
      [sqlite_classifier.symbol_ham] = {
        spam = false
      }
    }
  }

  if expire then
    result.expire = expire
  end

  return {classifier = {bayes = result}}
end

exports.redis_classifier_from_sqlite = redis_classifier_from_sqlite

return exports
