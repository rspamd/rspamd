--[[
Copyright (c) 2018, Vsevolod Stakhov <vsevolod@highsecure.ru>
Copyright (c) 2019, Carsten Rosenberg <c.rosenberg@heinlein-support.de>

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
local rspamd_regexp = require "rspamd_regexp"
local lua_util = require "lua_util"
local lua_redis = require "lua_redis"
local fun = require "fun"

local exports = {}

local function log_clean(task, rule, msg)

  msg = msg or 'message or mime_part is clean'

  if rule.log_clean then
    rspamd_logger.infox(task, '%s: %s', rule.log_prefix, msg)
  else
    lua_util.debugm(rule.name, task, '%s: %s', rule.log_prefix, msg)
  end

end

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

local function yield_result(task, rule, vname, dyn_weight, is_fail)
  local all_whitelisted = true
  local patterns
  local symbol
  local threat_table = {}
  local threat_info

  -- This should be more generic
  if not is_fail then
    patterns = rule.patterns
    symbol = rule.symbol
    threat_info = rule.detection_category .. 'found'
    if not dyn_weight then dyn_weight = 1.0 end
  elseif is_fail == 'fail' then
    patterns = rule.patterns_fail
    symbol = rule.symbol_fail
    threat_info = "FAILED with error"
    dyn_weight = 0.0
  elseif is_fail == 'encrypted' then
    patterns = rule.patterns
    symbol = rule.symbol_encrypted
    threat_info = "Scan has returned that input was encrypted"
    dyn_weight = 1.0
  end

  if type(vname) == 'string' then
    table.insert(threat_table, vname)
  elseif type(vname) == 'table' then
    threat_table = vname
  end

  for _, tm in ipairs(threat_table) do
    local symname, symscore = match_patterns(symbol, tm, patterns, dyn_weight)
    if rule.whitelist and rule.whitelist:get_key(tm) then
      rspamd_logger.infox(task, '%s: "%s" is in whitelist', rule.log_prefix, tm)
    else
      all_whitelisted = false
      task:insert_result(symname, symscore, tm)
      rspamd_logger.infox(task, '%s: result - %s: "%s - score: %s"',
          rule.log_prefix, threat_info, tm, symscore)
    end
  end

  if rule.action and is_fail ~= 'fail' and not all_whitelisted then
    threat_table = table.concat(threat_table, '; ')
    task:set_pre_result(rule.action,
        lua_util.template(rule.message or 'Rejected', {
          SCANNER = rule.name,
          VIRUS = threat_table,
        }), rule.name)
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
        lua_util.debugm(rule.name, task, '%s: got cached threat result for %s: %s - score: %s',
          rule.log_prefix, key, threat_string[1], score)
        yield_result(task, rule, threat_string, score)
      else
        lua_util.debugm(rule.name, task, '%s: got cached negative result for %s: %s',
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
  if not dyn_weight then dyn_weight = 1.0 end

  local function redis_set_cb(err)
    -- Do nothing
    if err then
      rspamd_logger.errx(task, 'failed to save %s cache for %s -> "%s": %s',
          rule.detection_category, to_save, key, err)
    else
      lua_util.debugm(rule.name, task, '%s: saved cached result for %s: %s - score %s',
        rule.log_prefix, key, to_save, dyn_weight)
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

local function create_regex_table(patterns)
  local regex_table = {}
  if patterns[1] then
    for i, p in ipairs(patterns) do
      if type(p) == 'table' then
        local new_set = {}
        for k, v in pairs(p) do
          new_set[k] = rspamd_regexp.create_cached(v)
        end
        regex_table[i] = new_set
      else
        regex_table[i] = {}
      end
    end
  else
    for k, v in pairs(patterns) do
      regex_table[k] = rspamd_regexp.create_cached(v)
    end
  end
  return regex_table
end

local function match_filter(task, found, patterns)
  if type(patterns) ~= 'table' then return false end
  if not patterns[1] then
    for _, pat in pairs(patterns) do
      if pat:match(found) then
        return true
      end
    end
    return false
  else
    for _, p in ipairs(patterns) do
      for _, pat in ipairs(p) do
        if pat:match(found) then
          return true
        end
      end
    end
    return false
  end
end

-- borrowed from mime_types.lua
-- ext is the last extension, LOWERCASED
-- ext2 is the one before last extension LOWERCASED
local function gen_extension(fname)
  local filename_parts = rspamd_str_split(fname, '.')

  local ext = {}
  for n = 1, 2 do
      ext[n] = #filename_parts > n and string.lower(filename_parts[#filename_parts + 1 - n]) or nil
  end
  return ext[1],ext[2],filename_parts
end

local function check_parts_match(task, rule)

  local filter_func = function(p)
    local mtype,msubtype = p:get_type()
    local dmtype,dmsubtype = p:get_detected_type()
    local fname = p:get_filename()
    local ext, ext2
    local extension_check = false
    local content_type_check = false
    local text_part_min_words_check = true

    if rule.scan_all_mime_parts == false then
    -- check file extension and filename regex matching
      if fname ~= nil then
        ext,ext2 = gen_extension(fname)
        if match_filter(task, ext, rule.mime_parts_filter_ext)
          or match_filter(task, ext2, rule.mime_parts_filter_ext) then
          lua_util.debugm(rule.name, task, '%s: extension matched: %s', rule.log_prefix, ext)
          extension_check = true
        end
        if match_filter(task, fname, rule.mime_parts_filter_regex) then
          content_type_check = true
        end
      end
      -- check content type string regex matching
      if mtype ~= nil and msubtype ~= nil then
        local ct = string.format('%s/%s', mtype, msubtype):lower()
        if match_filter(task, ct, rule.mime_parts_filter_regex) then
          lua_util.debugm(rule.name, task, '%s: regex content-type: %s', rule.log_prefix, ct)
          content_type_check = true
        end
      end
      -- check detected content type (libmagic) regex matching
      if dmtype ~= nil and dmsubtype ~= nil then
        local ct = string.format('%s/%s', mtype, msubtype):lower()
        if match_filter(task, ct, rule.mime_parts_filter_regex) then
          lua_util.debugm(rule.name, task, '%s: regex detected libmagic content-type: %s', rule.log_prefix, ct)
          content_type_check = true
        end
      end
      -- check filenames in archives
      if p:is_archive() then
        local arch = p:get_archive()
        local filelist = arch:get_files_full()
        for _,f in ipairs(filelist) do
          ext,ext2 = gen_extension(f.name)
          if match_filter(task, ext, rule.mime_parts_filter_ext)
            or match_filter(task, ext2, rule.mime_parts_filter_ext) then
            lua_util.debugm(rule.name, task, '%s: extension matched in archive: %s', rule.log_prefix, ext)
            extension_check = true
          end
          if match_filter(task, f.name, rule.mime_parts_filter_regex) then
            content_type_check = true
          end
        end
      end
    end

    -- check text_part has more words than text_part_min_words_check
    if rule.text_part_min_words and p:is_text() then
      text_part_min_words_check = p:get_words_count() >= tonumber(rule.text_part_min_words)
    end

    return (rule.scan_image_mime and p:is_image())
        or (rule.scan_text_mime and text_part_min_words_check)
        or (p:is_attachment() and rule.scan_all_mime_parts ~= false)
        or extension_check
        or content_type_check
  end

  return fun.filter(filter_func, task:get_parts())
end

local function check_metric_results(task, rule)

  if rule.action ~= 'reject' then
    local metric_result = task:get_metric_score('default')
    local metric_action = task:get_metric_action('default')
    local has_pre_result = task:has_pre_result()

    if rule.symbol_type == 'postfilter' and metric_action == 'reject' then
      return true, 'result is already reject'
    elseif metric_result[1] > metric_result[2]*2 then
      return true, 'score > 2 * reject_level: ' .. metric_result[1]
    elseif has_pre_result and metric_action == 'reject' then
      return true, 'pre_result reject is set'
    else
      return false, 'undecided'
    end
  else
    return false, 'dynamic_scan is not possible with config `action=reject;`'
  end
end

exports.log_clean = log_clean
exports.yield_result = yield_result
exports.match_patterns = match_patterns
exports.need_av_check = need_av_check
exports.check_av_cache = check_av_cache
exports.save_av_cache = save_av_cache
exports.create_regex_table = create_regex_table
exports.check_parts_match = check_parts_match
exports.check_metric_results = check_metric_results

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
