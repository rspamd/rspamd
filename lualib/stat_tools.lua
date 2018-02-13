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
local redis = require "rspamd_redis"
local util = require "rspamd_util"
local lua_redis = require "lua_redis"
local exports = {}

local N = "stats_tools"

-- Performs synchronous conversation of redis schema
local function convert_bayes_schema(cfg, redis_params, key)

end

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
  local num = 0
  local total = 0
  local nusers = 0
  local lim = 1000 -- Update each 1000 tokens
  local users_map = {}


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


  local res,conn,addr = lua_redis.redis_connect_sync(redis_params, true)

  if not res then
    logger.errx("cannot connect to redis server")
    return false
  end

  if reset_previous then
    -- Do a more complicated cleanup
    -- execute a lua script that cleans up data
    local script = [[
local members = redis.call('SMEMBERS', KEYS[1])

for _,prefix in ipairs(members) do
  local keys = redis.call('KEYS', prefix..'*')
  redis.call('DEL', keys)
end
]]
    -- Common keys
    for _,sym in ipairs({symbol_spam, symbol_ham}) do
      logger.infox('Cleaning up old data for %s', sym)
      conn:add_cmd('EVAL', {script, '1', sym})
      conn:exec()
      conn:add_cmd('DEL', {sym .. "_version"})
      conn:add_cmd('DEL', {sym .. "_keys"})
      conn:exec()
    end

    if learn_cache_db then
      -- Cleanup learned_cache
      logger.infox('Cleaning up old data learned cache')
      conn:add_cmd('DEL', {"learned_ids"})
      conn:exec()
    end
  end

  local function convert_db(db, is_spam)
    -- Map users and languages
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
      for _,tok in tokens do
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

    local tokens = {}
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
    end
    -- Last batch
    if #tokens > 0 then
      local ret,err_str = send_batch(tokens, 'RS')
      if not ret then
        logger.errx('Cannot send tokens to the redis server: ' .. err_str)
        db:sql('COMMIT;')
        return false
      end
    end

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
      if user ~= '' then
        if not conn:add_cmd('SADD', {symbol .. '_keys', 'RS' .. user}) then
          logger.errx('Cannot update learns for user: ' .. user)
          return false
        end
      end
    end
    -- Set version
    conn:add_cmd('SET', {symbol..'_version', '2'})
    return conn:exec()
  end

  if not convert_db(db_spam, true) then
    return false
  end

  if not convert_db(db_ham, false) then
    return false
  end

  if learn_cache_db then
    logger.infox('Convert learned ids from %s', learn_cache_db)
    local db = sqlite3.open(learn_cache_db)
    local ret = true
    local err_str
    local converted = 0

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
        converted = converted + 1
      end
    end
    db:sql('COMMIT;')

    if ret then
      ret,err_str = conn:exec()
    end

    if ret then
      logger.infox('Converted %d cached items from sqlite3 learned cache to redis',
        converted)
    else
      logger.errx('Error occurred during sending data to redis: ' .. err_str)
    end
  end

  logger.infox('Migrated %d tokens for %d users for symbol %s',
      total, nusers, res['symbol'])
end

exports.convert_sqlite_to_redis = convert_sqlite_to_redis

return exports