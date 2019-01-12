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

--[[[
-- @module lua_scanners_common
-- This module contains common external scanners functions
--]]

local rspamd_logger = require "rspamd_logger"
local lua_util = require "lua_util"
local lua_redis = require "lua_redis"
local fun = require "fun"

local exports = {}

local function match_patterns(default_sym, found, patterns, dyn_weight)
  if type(patterns) ~= 'table' then return default_sym, dyn_weight end
  if not patterns[1] then
    for sym, pat in pairs(patterns) do
      if pat:match(found) then
        return sym, '1'
      end
    end
    return default_sym, dyn_weight
  else
    for _, p in ipairs(patterns) do
      for sym, pat in pairs(p) do
        if pat:match(found) then
          return sym, '1'
        end
      end
    end
    return default_sym, dyn_weight
  end
end

local function yield_result(task, rule, vname, N, dyn_weight)
  local all_whitelisted = true
  if not dyn_weight then dyn_weight = 1.0 end
  if type(vname) == 'string' then
    local symname, symscore = match_patterns(rule.symbol, vname, rule.patterns, dyn_weight)
    if rule.whitelist and rule.whitelist:get_key(vname) then
      rspamd_logger.infox(task, '%s: "%s" is in whitelist', rule.log_prefix, vname)
      return
    end
    task:insert_result(symname, symscore, vname)
    rspamd_logger.infox(task, '%s: %s found: "%s"', rule.log_prefix, rule.detection_category, vname)
  elseif type(vname) == 'table' then
    for _, vn in ipairs(vname) do
      local symname, symscore = match_patterns(rule.symbol, vn, rule.patterns, dyn_weight)
      if rule.whitelist and rule.whitelist:get_key(vn) then
        rspamd_logger.infox(task, '%s: "%s" is in whitelist', rule.log_prefix, vn)
      else
        all_whitelisted = false
        task:insert_result(symname, symscore, vn)
        rspamd_logger.infox(task, '%s: %s found: "%s"',
            rule.log_prefix, rule.detection_category, vn)
      end
    end
  end
  if rule.action then
    if type(vname) == 'table' then
      if all_whitelisted then return end
      vname = table.concat(vname, '; ')
    end
    task:set_pre_result(rule.action,
        lua_util.template(rule.message or 'Rejected', {
          SCANNER = rule.name,
          VIRUS = vname,
        }), N)
  end
end

local function message_not_too_large(task, content, rule)
  local max_size = tonumber(rule.max_size)
  if not max_size then return true end
  if #content > max_size then
    rspamd_logger.infox(task, "skip %s check as it is too large: %s (%s is allowed)",
        rule.log_prefix, #content, max_size)
    return false
  end
  return true
end

local function need_av_check(task, content, rule)
  return message_not_too_large(task, content, rule)
end

local function check_av_cache(task, digest, rule, fn)
  local key = digest

  local function redis_av_cb(err, data)
    if data and type(data) == 'string' then
      -- Cached
      data = rspamd_str_split(data, '\t')
      local threat_string = rspamd_str_split(data[1], '\v')
      local score = data[2] or rule.default_score
      if threat_string[1] ~= 'OK' then
        lua_util.debugm(rule.module_name, task, '%s: got cached threat result for %s: %s',
          rule.log_prefix, key, threat_string[1])
        yield_result(task, rule, threat_string, score)
      else
        lua_util.debugm(rule.module_name, task, '%s: got cached negative result for %s: %s',
          rule.log_prefix, key, threat_string[1])
      end
    else
      if err then
        rspamd_logger.errx(task, 'got error checking cache: %s', err)
      end
      fn()
    end
  end

  if rule.redis_params then

    key = rule.prefix .. key

    if lua_redis.redis_make_request(task,
        rule.redis_params, -- connect params
        key, -- hash key
        false, -- is write
        redis_av_cb, --callback
        'GET', -- command
        {key} -- arguments)
    ) then
      return true
    end
  end

  return false
end

local function save_av_cache(task, digest, rule, to_save, dyn_weight)
  local key = digest

  local function redis_set_cb(err)
    -- Do nothing
    if err then
      rspamd_logger.errx(task, 'failed to save %s cache for %s -> "%s": %s',
          rule.detection_category, to_save, key, err)
    else
      lua_util.debugm(rule.module_name, task, '%s: saved cached result for %s: %s', rule.log_prefix, key, to_save)
    end
  end

  if type(to_save) == 'table' then
    to_save = table.concat(to_save, '\v')
  end

  local value = table.concat({to_save, dyn_weight}, '\t')

  if rule.redis_params and rule.prefix then
    key = rule.prefix .. key

    lua_redis.redis_make_request(task,
        rule.redis_params, -- connect params
        key, -- hash key
        true, -- is write
        redis_set_cb, --callback
        'SETEX', -- command
        { key, rule.cache_expire or 0, value }
    )
  end

  return false
end

local function text_parts_min_words(task, min_words)
  local filter_func = function(p)
    return p:get_words_count() >= min_words
  end

  return fun.any(filter_func, task:get_text_parts())

end


exports.yield_result = yield_result
exports.match_patterns = match_patterns
exports.need_av_check = need_av_check
exports.check_av_cache = check_av_cache
exports.save_av_cache = save_av_cache
exports.text_parts_min_words = text_parts_min_words

setmetatable(exports, {
  __call = function(t, override)
    for k, v in pairs(t) do
      if _G[k] ~= nil then
        local msg = 'function ' .. k .. ' already exists in global scope.'
        if override then
          _G[k] = v
          print('WARNING: ' .. msg .. ' Overwritten.')
        else
          print('NOTICE: ' .. msg .. ' Skipped.')
        end
      else
        _G[k] = v
      end
    end
  end,
})

return exports
