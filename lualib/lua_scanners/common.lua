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
local lua_magic_types = require "lua_magic/types"
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

local function yield_result(task, rule, vname, dyn_weight, is_fail, maybe_part)
  local all_whitelisted = true
  local patterns
  local symbol
  local threat_table
  local threat_info
  local flags

  if type(vname) == 'string' then
    threat_table = {vname}
  elseif type(vname) == 'table' then
    threat_table = vname
  end


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
  elseif is_fail == 'macro' then
    patterns = rule.patterns
    symbol = rule.symbol_macro
    threat_info = "Scan has returned that input contains macros"
    dyn_weight = 1.0
  end


  for _, tm in ipairs(threat_table) do
    local symname, symscore = match_patterns(symbol, tm, patterns, dyn_weight)
    if rule.whitelist and rule.whitelist:get_key(tm) then
      rspamd_logger.infox(task, '%s: "%s" is in whitelist', rule.log_prefix, tm)
    else
      all_whitelisted = false
      rspamd_logger.infox(task, '%s: result - %s: "%s - score: %s"',
          rule.log_prefix, threat_info, tm, symscore)

      if maybe_part and rule.show_attachments and maybe_part:get_filename() then
        local fname = maybe_part:get_filename()
        task:insert_result(symname, symscore, string.format("%s|%s",
            tm, fname))
      else
        task:insert_result(symname, symscore, tm)
      end

    end
  end

  if rule.action and is_fail ~= 'fail' and not all_whitelisted then
    threat_table = table.concat(threat_table, '; ')
    if rule.action ~= 'reject' then
      flags = 'least'
    end
    task:set_pre_result(rule.action,
        lua_util.template(rule.message or 'Rejected', {
          SCANNER = rule.name,
          VIRUS = threat_table,
        }), rule.name, nil, nil, flags)
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

local function message_not_too_small(task, content, rule)
  local min_size = tonumber(rule.min_size)
  if not min_size then return true end
  if #content < min_size then
    rspamd_logger.infox(task, "skip %s check as it is too small: %s (%s is allowed)",
        rule.log_prefix, #content, min_size)
    return false
  end
  return true
end

local function message_min_words(task, rule)
  if rule.text_part_min_words and tonumber(rule.text_part_min_words) > 0 then
    local text_part_above_limit = false
    local text_parts = task:get_text_parts()

    local filter_func = function(p)
      return p:get_words_count() >= tonumber(rule.text_part_min_words)
    end

    fun.each(function(p)
      text_part_above_limit = true
    end, fun.filter(filter_func, text_parts))

    if not text_part_above_limit then
      rspamd_logger.infox(task, '%s: #words in all text parts is below text_part_min_words limit: %s',
        rule.log_prefix, rule.text_part_min_words)
    end

    return text_part_above_limit
  else
    return true
  end
end

local function dynamic_scan(task, rule)
  if rule.dynamic_scan then
    if rule.action ~= 'reject' then
      local metric_result = task:get_metric_score('default')
      local metric_action = task:get_metric_action('default')
      local has_pre_result = task:has_pre_result()
      -- ToDo: needed?
      -- Sometimes leads to FPs
      --if rule.symbol_type == 'postfilter' and metric_action == 'reject' then
      --  rspamd_logger.infox(task, '%s: aborting: %s', rule.log_prefix, "result is already reject")
      --  return false
      --elseif metric_result[1] > metric_result[2]*2 then
      if metric_result[1] > metric_result[2]*2 then
        rspamd_logger.infox(task, '%s: aborting: %s', rule.log_prefix, 'score > 2 * reject_level: ' .. metric_result[1])
        return false
      elseif has_pre_result and metric_action == 'reject' then
        rspamd_logger.infox(task, '%s: aborting: %s', rule.log_prefix, 'pre_result reject is set')
        return false
      else
        return true, 'undecided'
      end
    else
      return true, 'dynamic_scan is not possible with config `action=reject;`'
    end
  else
    return true
  end
end

local function need_check(task, content, rule, digest, fn, maybe_part)

  local uncached = true
  local key = digest

  local function redis_av_cb(err, data)
    if data and type(data) == 'string' then
      -- Cached
      data = lua_util.str_split(data, '\t')
      local threat_string = lua_util.str_split(data[1], '\v')
      local score = data[2] or rule.default_score

      if threat_string[1] ~= 'OK' then
        if threat_string[1] == 'MACRO' then
          yield_result(task, rule, 'File contains macros',
              0.0, 'macro', maybe_part)
        elseif threat_string[1] == 'ENCRYPTED' then
          yield_result(task, rule, 'File is encrypted',
              0.0, 'encrypted', maybe_part)
        else
          lua_util.debugm(rule.name, task, '%s: got cached threat result for %s: %s - score: %s',
              rule.log_prefix, key, threat_string[1], score)
          yield_result(task, rule, threat_string, score, false, maybe_part)
        end

      else
        lua_util.debugm(rule.name, task, '%s: got cached negative result for %s: %s',
          rule.log_prefix, key, threat_string[1])
      end
      uncached = false
    else
      if err then
        rspamd_logger.errx(task, 'got error checking cache: %s', err)
      end
    end

    local f_message_not_too_large = message_not_too_large(task, content, rule)
    local f_message_not_too_small = message_not_too_small(task, content, rule)
    local f_message_min_words = message_min_words(task, rule)
    local f_dynamic_scan = dynamic_scan(task, rule)

    if uncached and
      f_message_not_too_large and
      f_message_not_too_small and
      f_message_min_words and
      f_dynamic_scan then

      fn()

    end

  end

  if rule.redis_params and not rule.no_cache then

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

local function save_cache(task, digest, rule, to_save, dyn_weight, maybe_part)
  local key = digest
  if not dyn_weight then dyn_weight = 1.0 end

  local function redis_set_cb(err)
    -- Do nothing
    if err then
      rspamd_logger.errx(task, 'failed to save %s cache for %s -> "%s": %s',
          rule.detection_category, to_save, key, err)
    else
      lua_util.debugm(rule.name, task, '%s: saved cached result for %s: %s - score %s - ttl %s',
        rule.log_prefix, key, to_save, dyn_weight, rule.cache_expire)
    end
  end

  if type(to_save) == 'table' then
    to_save = table.concat(to_save, '\v')
  end

  local value_tbl = {to_save, dyn_weight}
  if maybe_part and rule.show_attachments and maybe_part:get_filename() then
    local fname = maybe_part:get_filename()
    table.insert(value_tbl, fname)
  end
  local value = table.concat(value_tbl, '\t')

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

local function match_filter(task, rule, found, patterns, pat_type)
  if type(patterns) ~= 'table' or not found then
    return false
  end
  if not patterns[1] then
    for _, pat in pairs(patterns) do
      if pat_type == 'ext' and tostring(pat) == tostring(found) then
        return true
      elseif pat_type == 'regex' and pat:match(found) then
        return true
      end
    end
    return false
  else
    for _, p in ipairs(patterns) do
      for _, pat in ipairs(p) do
        if pat_type == 'ext' and tostring(pat) == tostring(found) then
          return true
        elseif pat_type == 'regex' and pat:match(found) then
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
  local filename_parts = lua_util.str_split(fname, '.')

  local ext = {}
  for n = 1, 2 do
      ext[n] = #filename_parts > n and string.lower(filename_parts[#filename_parts + 1 - n]) or nil
  end
  return ext[1],ext[2],filename_parts
end

local function check_parts_match(task, rule)

  local filter_func = function(p)
    local mtype,msubtype = p:get_type()
    local detected_ext = p:get_detected_ext()
    local fname = p:get_filename()
    local ext, ext2

    if rule.scan_all_mime_parts == false then
    -- check file extension and filename regex matching
      --lua_util.debugm(rule.name, task, '%s: filename: |%s|%s|', rule.log_prefix, fname)
      if fname ~= nil then
        ext,ext2 = gen_extension(fname)
        --lua_util.debugm(rule.name, task, '%s: extension, fname: |%s|%s|%s|', rule.log_prefix, ext, ext2, fname)
        if match_filter(task, rule, ext, rule.mime_parts_filter_ext, 'ext')
            or match_filter(task, rule, ext2, rule.mime_parts_filter_ext, 'ext') then
          lua_util.debugm(rule.name, task, '%s: extension matched: |%s|%s|', rule.log_prefix, ext, ext2)
          return true
        elseif match_filter(task, rule, fname, rule.mime_parts_filter_regex, 'regex') then
          lua_util.debugm(rule.name, task, '%s: filname regex matched', rule.log_prefix)
          return true
        end
      end
      -- check content type string regex matching
      if mtype ~= nil and msubtype ~= nil then
        local ct = string.format('%s/%s', mtype, msubtype):lower()
        if match_filter(task, rule, ct, rule.mime_parts_filter_regex, 'regex') then
          lua_util.debugm(rule.name, task, '%s: regex content-type: %s', rule.log_prefix, ct)
          return true
        end
      end
      -- check detected content type (libmagic) regex matching
      if detected_ext then
        local magic = lua_magic_types[detected_ext] or {}
        if match_filter(task, rule, detected_ext, rule.mime_parts_filter_ext, 'ext') then
          lua_util.debugm(rule.name, task, '%s: detected extension matched: |%s|', rule.log_prefix, detected_ext)
          return true
        elseif magic.ct and match_filter(task, rule, magic.ct, rule.mime_parts_filter_regex, 'regex') then
          lua_util.debugm(rule.name, task, '%s: regex detected libmagic content-type: %s',
              rule.log_prefix, magic.ct)
          return true
        end
      end
      -- check filenames in archives
      if p:is_archive() then
        local arch = p:get_archive()
        local filelist = arch:get_files_full(1000)
        for _,f in ipairs(filelist) do
          ext,ext2 = gen_extension(f.name)
          if match_filter(task, rule, ext, rule.mime_parts_filter_ext, 'ext')
              or match_filter(task, rule, ext2, rule.mime_parts_filter_ext, 'ext') then
            lua_util.debugm(rule.name, task, '%s: extension matched in archive: |%s|%s|', rule.log_prefix, ext, ext2)
            --lua_util.debugm(rule.name, task, '%s: extension matched in archive: %s', rule.log_prefix, ext)
            return true
          elseif match_filter(task, rule, f.name, rule.mime_parts_filter_regex, 'regex') then
            lua_util.debugm(rule.name, task, '%s: filename regex matched in archive', rule.log_prefix)
            return true
          end
        end
      end
    end

    -- check text_part has more words than text_part_min_words_check
    if rule.scan_text_mime and rule.text_part_min_words and p:is_text() and
        p:get_words_count() >= tonumber(rule.text_part_min_words) then
      return true
    end

    if rule.scan_image_mime and p:is_image() then
      return true
    end

    if rule.scan_all_mime_parts ~= false then
      if detected_ext then
        -- We know what to scan!
        local magic = lua_magic_types[detected_ext] or {}

        if p:is_attachment() or magic.av_check ~= false then
          return true
        end
      elseif p:is_attachment() then
        -- Just rely on attachment property
        return true
      end
    end

    return false
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
exports.condition_check_and_continue = need_check
exports.save_cache = save_cache
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
