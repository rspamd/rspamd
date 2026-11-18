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
-- @module lua_task_profile
-- Sampling helper for exporters of per-symbol run times.
--
-- The operator selects a few symbols or groups; rspamd then records precise run times of the symcache
-- items that execute them on every scan. An exporter calls `collect` at the end of a scan and decides
-- whether to keep the record: either it is a random sample (reason 1), or a selected symbol ran at
-- least `slow_time` (reason 2).
--
-- Usage:
--   local lua_task_profile = require "lua_task_profile"
--   local profiler, err = lua_task_profile.new(rspamd_config, settings.profile)
--   ...
--   local reason, prof = profiler:collect(task)
--   if reason ~= 0 then ... prof.names, prof.times ... end
--]]

local rspamd_util = require "rspamd_util"

local exports = {}

exports.reason_names = { [0] = 'none', [1] = 'sampled', [2] = 'slow' }

local profiler_mt = {}
profiler_mt.__index = profiler_mt

local function is_number(v)
  -- Rejects NaN as well
  return type(v) == 'number' and v == v
end

local function check_names(name, list)
  if list == nil then
    return {}
  end
  if type(list) ~= 'table' then
    return nil, string.format('%s must be an array of strings', name)
  end
  local res = {}
  for i, v in ipairs(list) do
    if type(v) ~= 'string' or #v == 0 then
      return nil, string.format('%s[%d] must be a non-empty string', name, i)
    end
    res[#res + 1] = v
  end
  return res
end

-- lua_util.parse_time_interval ignores trailing text and reads 'm' as minutes,
-- so '500ms' would become 30000 seconds: parse the whole string here instead
local interval_units = {
  ms = 0.001, s = 1, m = 60, h = 3600, d = 86400, w = 7 * 86400, y = 365 * 86400,
}

local function parse_interval(str)
  local num, unit = str:match('^%s*([+-]?%d*%.?%d+)%s*(%a*)%s*$')
  if not num then
    return nil
  end
  local mult = 1
  if unit ~= '' then
    mult = interval_units[unit]
    if not mult then
      return nil
    end
  end
  local n = tonumber(num)
  if not n then
    return nil
  end
  return n * mult
end

--[[[
-- @function lua_task_profile.new(cfg, opts)
-- Creates a profiler and registers the selected symbols and groups in the symcache.
-- @param {rspamd_config} cfg configuration object
-- @param {table} opts options:
--   * sample_rate: probability in [0, 1] to keep a scan (default 0); use 0.1 for every 10th scan
--   * slow_time: seconds, a number or a string such as '2s' or '500ms' (units ms, s, m, h, d, w, y); keep a scan if a selected symbol ran at least that long (default 0 = off)
--   * max_slow_rate: at most this many slow records per second per worker (default 1, 0 = unlimited)
--   * groups, symbols: arrays of names of the groups/symbols to time (at least one is required)
--   * rng, now, seed: test hooks; `rng()` returns a number in [0, 1), `now()` returns seconds,
--     `seed` is the seed of the private generator
-- @return {profiler|nil, string|nil} nil, nil when the feature is off; nil, error on invalid options
--]]
exports.new = function(cfg, opts)
  opts = opts or {}
  if type(opts) ~= 'table' then
    return nil, 'profile options must be a table'
  end

  local sample_rate = opts.sample_rate
  if sample_rate == nil then
    sample_rate = 0
  end
  if not is_number(sample_rate) or sample_rate < 0 or sample_rate > 1 then
    return nil, 'sample_rate must be a number between 0 and 1 (a probability); ' ..
        'use 0.1 to keep every 10th scan'
  end

  local slow_time = opts.slow_time
  if slow_time == nil then
    slow_time = 0
  elseif type(slow_time) == 'string' then
    local parsed = parse_interval(slow_time)
    if parsed == nil then
      return nil, string.format('slow_time: cannot parse time interval "%s"', slow_time)
    end
    slow_time = parsed
  end
  if not is_number(slow_time) or slow_time < 0 then
    return nil, 'slow_time must be a non-negative number of seconds or a time interval string'
  end

  local max_slow_rate = opts.max_slow_rate
  if max_slow_rate == nil then
    max_slow_rate = 1
  end
  if not is_number(max_slow_rate) or max_slow_rate < 0 then
    return nil, 'max_slow_rate must be a number >= 0 (records per second, 0 = unlimited)'
  end

  if opts.rng ~= nil and type(opts.rng) ~= 'function' then
    return nil, 'rng must be a function'
  end
  if opts.now ~= nil and type(opts.now) ~= 'function' then
    return nil, 'now must be a function'
  end

  local groups, err = check_names('groups', opts.groups)
  if not groups then
    return nil, err
  end
  local symbols
  symbols, err = check_names('symbols', opts.symbols)
  if not symbols then
    return nil, err
  end

  if sample_rate == 0 and slow_time == 0 then
    return nil, nil
  end

  if #groups == 0 and #symbols == 0 then
    return nil, 'profiling needs at least one symbol or group: set "groups" or "symbols"'
  end

  cfg:register_profiled_symbols({ groups = groups, symbols = symbols })

  local self = setmetatable({
    sample_rate = sample_rate,
    slow_time = slow_time,
    max_slow_rate = max_slow_rate,
    groups = groups,
    symbols = symbols,
    now = opts.now or rspamd_util.get_time,
    rng = opts.rng,
    seed = opts.seed,
  }, profiler_mt)

  if max_slow_rate > 0 then
    self.capacity = math.max(1, max_slow_rate)
    self.tokens = self.capacity
    self.last_refill = self.now()
  end

  return self
end

-- Park-Miller generator. math.random has the same state in every worker (it is seeded before fork),
-- so a private generator seeded lazily after fork is used instead.
local function default_rng(self)
  local seed = self.seed
  if not seed then
    seed = tonumber(rspamd_util.random_hex(8), 16) or 1
  end
  seed = seed % 2147483646 + 1
  local function rnd()
    seed = (seed * 16807) % 2147483647
    return seed / 2147483647
  end
  return rnd
end

local function take_token(self)
  if self.max_slow_rate == 0 then
    return true
  end
  local now = self.now()
  local elapsed = now - self.last_refill
  if elapsed > 0 then
    self.tokens = math.min(self.capacity, self.tokens + elapsed * self.max_slow_rate)
  end
  self.last_refill = now
  if self.tokens >= 1 then
    self.tokens = self.tokens - 1
    return true
  end
  return false
end

--[[[
-- @method profiler:collect(task)
-- Decides at the end of a scan whether to keep the per-symbol timings.
-- @param {rspamd_task} task
-- @return {number, table|nil} reason (0 not kept, 1 sampled, 2 slow) and the table returned by
-- `task:get_symbols_profile()` (nil for reason 0)
--]]
function profiler_mt:collect(task)
  if not self.rng then
    self.rng = default_rng(self)
  end

  -- The coin is drawn on every call, before slowness is looked at: reason 1 is an unbiased sample
  local coin = self.rng()

  if self.sample_rate > 0 and coin < self.sample_rate then
    local prof = task:get_symbols_profile()
    if not prof then
      return 0, nil
    end
    return 1, prof
  end

  if self.slow_time > 0 then
    local prof = task:get_symbols_profile({ min_time = self.slow_time * 1000.0 })
    if prof and take_token(self) then
      return 2, prof
    end
  end

  return 0, nil
end

return exports
