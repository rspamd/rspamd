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
]] --

--[[[
-- @module lua_dynconf.legacy
-- One-time import of the data of the previous dynamic configuration implementations into dynconf
-- (the `actions` and `scores` modules):
--
--  * the JSON file of `options { dynamic_conf = ... }` (`$DBDIR/rspamd_dynamic`): an array of
--    `{metric, symbols = [{name, value}], actions = [{name, value}]}`; after a successful import the
--    file is renamed to `<path>.imported`;
--  * the Redis hash of the `dynamic_conf` Lua module (only when the dynconf backend is Redis and the
--    `dynamic_conf {}` section exists): field `d` is JSON
--    `{scores, actions, symbols_enabled, symbols_disabled}`; the two symbol lists are not imported (the
--    old implementation never applied them). The hash is not deleted, it only gets a marker field, so
--    that the import does not run again when somebody resets the overrides.
--
-- The import is started by the registry in the primary controller, after the first successful check of
-- the backend, and only for the modules that hold no override yet.
--]]

local logger = require "rspamd_logger"
local lua_redis = require "lua_redis"
local lua_util = require "lua_util"
local rspamd_util = require "rspamd_util"
local ucl = require "ucl"

local exports = {}

local N = "dynconf"
local ENOENT = 2
-- Do not slurp anything bigger than this (the files of the legacy implementation are small)
local MAX_SIZE = 16 * 1024 * 1024
local EPSILON = 1e-9
local IMPORT_MARKER = 'dynconf_imported'
local DEFAULT_REDIS_KEY = 'dynamic_conf'
local MODULE_ORDER = { 'actions', 'scores' }

local redis_params
local redis_key = DEFAULT_REDIS_KEY

-- The static state of an entry: `value|nil, overridden, known, masked` (see rspamd_config:dynconf_baseline)
local function default_lookup(module, key)
  local f = rspamd_config and rspamd_config.dynconf_baseline
  if type(f) ~= 'function' then
    return nil, false, false
  end
  return f(rspamd_config, module, key)
end

local function same_number(a, b)
  return math.abs(a - b) < EPSILON
end

local function is_number(v)
  return type(v) == 'number' and v == v and v ~= math.huge and v ~= -math.huge
end

-- A conversion result: the override tables per module and the reasons why entries were left out
local function new_result()
  return { overrides = {}, skipped = {}, counts = {} }
end

local function add_entry(res, module, key, value)
  if res.overrides[module] == nil then
    res.overrides[module] = {}
    res.counts[module] = 0
  end
  if res.overrides[module][key] == nil then
    res.counts[module] = res.counts[module] + 1
  end
  res.overrides[module][key] = value
end

local function skip(res, fmt, ...)
  res.skipped[#res.skipped + 1] = string.format(fmt, ...)
end

local function sorted_keys(t)
  local keys = {}
  for k in pairs(t) do
    keys[#keys + 1] = k
  end
  table.sort(keys)
  return keys
end

-- The name of an action as dynconf knows it: `add_header` and `add header` are one action, the second
-- spelling is the canonical one
local function action_name(name, lookup)
  local spaced = (name:gsub('_', ' '))
  local _, _, known = lookup('actions', spaced)
  if known then
    return spaced
  end
  _, _, known = lookup('actions', name)
  if known then
    return name
  end
  return nil
end

local function convert_score(res, name, value, lookup)
  if type(name) ~= 'string' or not is_number(value) then
    skip(res, 'score of %s is not a number', tostring(name))
    return
  end
  local base, _, known, masked = lookup('scores', name)
  if not known then
    skip(res, 'unknown symbol %s', name)
  elseif masked then
    -- A write of it would be refused, and would fail the whole import
    skip(res, 'the score of %s is defined with a higher priority (override.d, for example) than the ' ..
        'dynamic configuration has: it cannot be changed dynamically', name)
  elseif base ~= nil and same_number(value, base) then
    -- Nothing to override
    skip(res, 'the score of %s is the static one', name)
  else
    add_entry(res, 'scores', name, value)
  end
end

local function convert_action(res, name, value, lookup)
  if type(name) ~= 'string' then
    skip(res, 'an action without a name')
    return
  end
  if value == ucl.null then
    -- The legacy code could not apply it either: the threshold cannot be switched off dynamically
    skip(res, 'the threshold of the action %s is null', name)
    return
  end
  if not is_number(value) then
    skip(res, 'the threshold of the action %s is not a number', name)
    return
  end
  local canonical = action_name(name, lookup)
  if not canonical then
    skip(res, 'unknown action %s', name)
    return
  end
  local base, _, _, masked = lookup('actions', canonical)
  if masked then
    skip(res, 'the threshold of the action %s is defined with a higher priority (override.d, for example) ' ..
        'than the dynamic configuration has: it cannot be changed dynamically', name)
  elseif base ~= nil and same_number(value, base) then
    skip(res, 'the threshold of the action %s is the static one', name)
  else
    add_entry(res, 'actions', canonical, value)
  end
end

-- The number of the entries of `symbols_disabled` / `symbols_enabled`: an array of names, or a map
local function count_entries(t)
  local n = 0
  for _ in pairs(t) do
    n = n + 1
  end
  return n
end

--[[[
-- @function lua_dynconf.legacy.convert_file(doc, [lookup])
-- Converts a decoded legacy file (an array of metrics) to override tables. The entries of all metrics
-- are merged, a later entry wins. Unknown symbols and actions, null thresholds, entries that no override
-- can change (they are defined with a higher priority, in override.d) and values that equal the static
-- ones are left out.
-- `lookup(module, key)` returns `static_value|nil, overridden, known, masked` like
-- `rspamd_config:dynconf_baseline`.
-- @return {table} `{overrides = {actions = {...}, scores = {...}}, skipped = {strings}, counts = {...}}`
-- or `nil, error` if `doc` is not a legacy file
--]]
function exports.convert_file(doc, lookup)
  lookup = lookup or default_lookup
  if type(doc) ~= 'table' or (doc[1] == nil and next(doc) ~= nil) then
    return nil, 'the legacy dynamic configuration is not an array'
  end

  local res = new_result()
  local scores, actions = {}, {}

  for _, metric in ipairs(doc) do
    if type(metric) ~= 'table' or type(metric.metric) ~= 'string' then
      skip(res, 'an element without the `metric` attribute')
    else
      if type(metric.symbols) == 'table' then
        for _, sym in ipairs(metric.symbols) do
          if type(sym) == 'table' and sym.name ~= nil and sym.value ~= nil then
            scores[tostring(sym.name)] = sym.value
          else
            skip(res, 'a symbol without the `name` and `value` attributes')
          end
        end
      end
      if type(metric.actions) == 'table' then
        for _, act in ipairs(metric.actions) do
          if type(act) == 'table' and act.name ~= nil and act.value ~= nil then
            -- Both spellings of an action are one action: the later entry wins
            local name = tostring(act.name)
            actions[action_name(name, lookup) or name] = act.value
          else
            skip(res, 'an action without the `name` and `value` attributes')
          end
        end
      end
    end
  end

  for _, name in ipairs(sorted_keys(actions)) do
    convert_action(res, name, actions[name], lookup)
  end
  for _, name in ipairs(sorted_keys(scores)) do
    convert_score(res, name, scores[name], lookup)
  end

  return res
end

--[[[
-- @function lua_dynconf.legacy.convert_redis(doc, [lookup])
-- Converts the decoded `d` field of the hash of the `dynamic_conf` module. `symbols_disabled` and
-- `symbols_enabled` are not imported (the old implementation never applied them at runtime): they are
-- reported as skipped, whether they are arrays or maps.
-- @return {table} like `convert_file`, or `nil, error`
--]]
function exports.convert_redis(doc, lookup)
  lookup = lookup or default_lookup
  if type(doc) ~= 'table' then
    return nil, 'the legacy redis data is not an object'
  end

  local res = new_result()

  if type(doc.actions) == 'table' then
    for _, name in ipairs(sorted_keys(doc.actions)) do
      convert_action(res, name, doc.actions[name], lookup)
    end
  end
  if type(doc.scores) == 'table' then
    for _, name in ipairs(sorted_keys(doc.scores)) do
      convert_score(res, name, doc.scores[name], lookup)
    end
  end
  -- The previous implementation never applied these lists at runtime (an array raised an error in the
  -- loader, a map reached a function that only works before the cache is initialised), so there is no
  -- behaviour to carry over; switching symbols off now would be a surprise
  for _, field in ipairs({ 'symbols_disabled', 'symbols_enabled' }) do
    local list = doc[field]
    if type(list) == 'table' and next(list) ~= nil then
      skip(res, '%s (%d entries) is not imported: the previous implementation never applied it at runtime; ' ..
          'use `symbols.<name>.enabled = false` of dynconf to switch a symbol off',
          field, count_entries(list))
    end
  end

  return res
end

--[[[
-- @function lua_dynconf.legacy.read_file(path)
-- Reads and parses a legacy file.
-- @return {table} the decoded document; `nil` if the file does not exist; `nil, error` if it cannot be read
--]]
function exports.read_file(path)
  local f, ferr, errno = io.open(path, 'rb')
  if not f then
    if errno == ENOENT then
      return nil
    end
    return nil, string.format('cannot open %s: %s', path, ferr)
  end
  local data = f:read(MAX_SIZE + 1) or ''
  f:close()
  if #data > MAX_SIZE then
    return nil, string.format('%s is larger than %d bytes', path, MAX_SIZE)
  end

  local parser = ucl.parser()
  local ok, perr = parser:parse_text(data)
  if not ok then
    return nil, string.format('cannot parse %s: %s', path, perr)
  end
  local doc = parser:get_object()
  if doc == nil then
    return nil, string.format('%s is empty', path)
  end
  return doc
end

--[[[
-- @function lua_dynconf.legacy.configure()
-- Called at configuration load time when the dynconf backend is Redis: parses the Redis parameters of the
-- `dynamic_conf {}` section, if there is one. Without the section there is nothing to import from Redis.
--]]
function exports.configure()
  redis_params = nil
  redis_key = DEFAULT_REDIS_KEY

  local section = rspamd_config:get_all_opt('dynamic_conf')
  if type(section) ~= 'table' then
    return
  end
  if section.redis_key then
    redis_key = tostring(section.redis_key)
  end
  redis_params = lua_redis.parse_redis_server('dynamic_conf', section)
  if not redis_params then
    logger.warnx(rspamd_config, 'dynconf: the dynamic_conf section has no redis servers, ' ..
        'its data cannot be imported')
  end
end

-- Writes the override tables of the modules one after another; `done(err)` is called once, with the
-- errors of all the modules that have failed. A failure of a module does not stop the others: they
-- hold no override after it yet, and the next start tries again only for the ones that failed
local function write_modules(dynconf, ctx, overrides, done)
  local order = {}
  for _, module in ipairs(MODULE_ORDER) do
    if overrides[module] then
      order[#order + 1] = module
    end
  end

  local errors = {}
  local function step(i)
    if i > #order then
      done(#errors > 0 and table.concat(errors, '; ') or nil)
      return
    end
    local module = order[i]
    local ok, err = dynconf.update(module, overrides[module], ctx, function(serr)
      if serr then
        errors[#errors + 1] = string.format('%s: %s', module, serr)
      end
      step(i + 1)
    end)
    if not ok then
      errors[#errors + 1] = string.format('%s: %s', module, tostring(err))
      step(i + 1)
    end
  end

  step(1)
end

local function log_result(what, res)
  local parts = {}
  for _, module in ipairs(MODULE_ORDER) do
    if res.counts[module] then
      parts[#parts + 1] = string.format('%s %s', res.counts[module], module)
    end
  end
  logger.infox(rspamd_config, 'dynconf: imported %s: %s', what,
      #parts > 0 and table.concat(parts, ', ') or 'no usable entries')
  for _, reason in ipairs(res.skipped) do
    logger.infox(rspamd_config, 'dynconf: %s: skipped %s', what, reason)
  end
end

-- Keeps only the modules that may take part in the import
local function restrict(res, targets)
  for module in pairs(res.overrides) do
    if not targets[module] then
      skip(res, 'the %s module does not take the import', module)
      res.overrides[module] = nil
      res.counts[module] = nil
    end
  end
end

-- Imports the file of `options { dynamic_conf }`; `next()` continues with the next source
local function import_file(dynconf, opts, next_step)
  local path = opts.file
  if type(path) ~= 'string' or path == '' then
    next_step()
    return
  end

  local doc, rerr = exports.read_file(path)
  if doc == nil then
    if rerr then
      logger.errx(rspamd_config, 'dynconf: cannot import the legacy dynamic configuration: %s', rerr)
    end
    next_step()
    return
  end

  local res, cerr = exports.convert_file(doc, opts.lookup)
  if not res then
    logger.errx(rspamd_config, 'dynconf: cannot import %s: %s', path, cerr)
    next_step()
    return
  end
  restrict(res, opts.targets)

  write_modules(dynconf, opts.ctx, res.overrides, function(werr)
    if werr then
      -- The file stays where it is: the next start tries again for the modules that have no override
      logger.errx(rspamd_config, 'dynconf: cannot import %s: %s', path, werr)
    else
      log_result(path, res)
      local imported = path .. '.imported'
      local rok, rerr2 = os.rename(path, imported)
      if not rok then
        logger.errx(rspamd_config, 'dynconf: cannot rename %s to %s: %s (the overrides that have just ' ..
            'been stored are not imported again)', path, imported, rerr2)
      end
    end
    next_step()
  end)
end

-- Imports the Redis hash of the `dynamic_conf` module
local function import_redis(dynconf, opts, next_step)
  if not redis_params or not opts.redis then
    next_step()
    return
  end

  local function hmget_cb(err, data)
    if err then
      logger.errx(rspamd_config, 'dynconf: cannot read the legacy hash %s from redis: %s', redis_key, err)
      next_step()
      return
    end

    local payload = type(data) == 'table' and data[1]
    local marker = type(data) == 'table' and data[2]
    if not payload or lua_redis.is_null(payload) or payload == '' then
      -- Nothing was ever stored there
      next_step()
      return
    end
    if marker and not lua_redis.is_null(marker) then
      lua_util.debugm(N, rspamd_config, 'the legacy hash %s has been imported already', redis_key)
      next_step()
      return
    end

    local parser = ucl.parser()
    local pok, perr = parser:parse_text(tostring(payload))
    if not pok then
      logger.errx(rspamd_config, 'dynconf: cannot parse the legacy hash %s: %s', redis_key, perr)
      next_step()
      return
    end
    local res, cerr = exports.convert_redis(parser:get_object(), opts.lookup)
    if not res then
      logger.errx(rspamd_config, 'dynconf: cannot import the legacy hash %s: %s', redis_key, cerr)
      next_step()
      return
    end
    restrict(res, opts.targets)

    write_modules(dynconf, opts.ctx, res.overrides, function(werr)
      if werr then
        logger.errx(rspamd_config, 'dynconf: cannot import the legacy hash %s: %s', redis_key, werr)
        next_step()
        return
      end
      log_result('redis hash ' .. redis_key, res)
      -- The hash itself is left alone; the marker keeps the data from coming back after a reset
      local function marker_cb(merr)
        if merr then
          logger.errx(rspamd_config, 'dynconf: cannot mark the legacy hash %s as imported: %s',
              redis_key, merr)
        end
        next_step()
      end
      local sent = lua_redis.redis_make_request_taskless(opts.ev_base, rspamd_config, redis_params,
          redis_key, true, marker_cb, 'HSETNX',
          { redis_key, IMPORT_MARKER, string.format('%.0f', rspamd_util.get_time()) })
      if not sent then
        marker_cb('cannot send the request')
      end
    end)
  end

  local sent = lua_redis.redis_make_request_taskless(opts.ev_base, rspamd_config, redis_params,
      redis_key, false, hmget_cb, 'HMGET', { redis_key, 'd', IMPORT_MARKER })
  if not sent then
    hmget_cb('cannot send the request')
  end
end

--[[[
-- @function lua_dynconf.legacy.run(dynconf, opts)
-- Runs the import: first the legacy file, then (for the Redis backend) the Redis hash. Both write
-- through `dynconf.update`, so the data of the hash wins over the file for the same key.
-- `opts`:
--  * `targets` - set of the modules that take part (they exist, accept overrides and hold none yet);
--  * `file` - path of the legacy file (`options.dynamic_conf`), nil if there is none;
--  * `redis` - true if the Redis hash has to be imported;
--  * `ev_base`, `ctx` - event base for Redis requests and the context for `dynconf.update`;
--  * `lookup` - replacement of the baseline lookup (tests); `done(err)` - optional completion callback.
--]]
function exports.run(dynconf, opts)
  local steps = { import_file, import_redis }

  local function run_step(i)
    if i > #steps then
      if opts.done then
        opts.done()
      end
      return
    end
    -- A step that fails after it has called `continue` must not start the next one twice
    local continued = false
    local function continue()
      if not continued then
        continued = true
        run_step(i + 1)
      end
    end
    local ok, err = pcall(steps[i], dynconf, opts, continue)
    if not ok then
      logger.errx(rspamd_config, 'dynconf: legacy import failed: %s', err)
      continue()
    end
  end

  run_step(1)
end

return exports
