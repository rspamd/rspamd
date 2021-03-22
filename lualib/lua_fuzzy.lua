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
-- @module lua_fuzzy
-- This module contains helper functions for supporting fuzzy check module
--]]


local N = "lua_fuzzy"
local lua_util = require "lua_util"
local rspamd_regexp = require "rspamd_regexp"
local fun = require "fun"
local rspamd_logger = require "rspamd_logger"
local ts = require("tableshape").types

-- Filled by C code, indexed by number in this table
local rules = {}

-- Pre-defined rules options
local policies = {
  recommended = {
    min_bytes = 1024,
    min_height = 500,
    min_width = 500,
    min_length = 64,
    text_multiplier = 4.0, -- divide min_bytes by 4 for texts
    mime_types = {"application/*"},
    scan_archives = true,
    short_text_direct_hash = true,
    text_shingles = true,
    skip_images = false,
  }
}

local default_policy = policies.recommended

local policy_schema = ts.shape{
  min_bytes = ts.number + ts.string / tonumber,
  min_height = ts.number + ts.string / tonumber,
  min_width = ts.number + ts.string / tonumber,
  min_length = ts.number + ts.string / tonumber,
  text_multiplier = ts.number,
  mime_types = ts.array_of(ts.string),
  scan_archives = ts.boolean,
  short_text_direct_hash = ts.boolean,
  text_shingles = ts.boolean,
  skip_images = ts.boolean,
}


local exports = {}


--[[[
-- @function lua_fuzzy.register_policy(name, policy)
-- Adds a new policy with name `name`. Must be valid, checked using policy_schema
--]]
exports.register_policy = function(name, policy)
  if policies[name] then
    rspamd_logger.warnx(rspamd_config, "overriding policy %s", name)
  end

  local parsed_policy,err = policy_schema:transform(policy)

  if not parsed_policy then
    rspamd_logger.errx(rspamd_config, 'invalid fuzzy rule policy %s: %s',
        name, err)

    return
  else
    policies.name = parsed_policy
  end
end

--[[[
-- @function lua_fuzzy.process_rule(rule)
-- Processes fuzzy rule (applying policies or defaults if needed). Returns policy id
--]]
exports.process_rule = function(rule)
  local processed_rule = lua_util.shallowcopy(rule)
  local policy = default_policy

  if processed_rule.policy then
    policy = policies[processed_rule.policy]
  end

  if policy then
    processed_rule = lua_util.override_defaults(policy, processed_rule)
  else
    rspamd_logger.warnx(rspamd_config, "unknown policy %s", processed_rule.policy)
  end

  if processed_rule.mime_types then
    processed_rule.mime_types = fun.totable(fun.map(function(gl)
      return rspamd_regexp.import_glob(gl, 'i')
    end, processed_rule.mime_types))
  end

  table.insert(rules, processed_rule)
  return #rules
end

local function check_length(task, part, rule)
  local bytes = part:get_length()
  local length_ok = bytes > 0

  local id = part:get_id()
  lua_util.debugm(N, task, 'check size of part %s', id)

  if length_ok and rule.min_bytes > 0 then

    local adjusted_bytes = bytes

    if part:is_text() then
      bytes = part:get_text():get_length()
      if rule.text_multiplier then
        adjusted_bytes = bytes * rule.text_multiplier
      end
    end

    if rule.min_bytes > adjusted_bytes then
      lua_util.debugm(N, task, 'skip part of length %s (%s adjusted) ' ..
          'as it has less than %s bytes',
          bytes, adjusted_bytes, rule.min_bytes)
      length_ok = false
    else
      lua_util.debugm(N, task, 'allow part of length %s (%s adjusted)',
          bytes, adjusted_bytes, rule.min_bytes)
    end
  else
    lua_util.debugm(N, task, 'allow part %s, no length limits', id)
  end

  return length_ok
end

local function check_text_part(task, part, rule, text)
  local allow_direct,allow_shingles = false,false

  local id = part:get_id()
  lua_util.debugm(N, task, 'check text part %s', id)
  local wcnt = text:get_words_count()

  if rule.text_shingles then
    -- Check number of words
    local min_words = rule.min_length or 0
    if min_words < 32 then
      min_words = 32 -- Minimum for shingles
    end
    if wcnt < min_words then
      lua_util.debugm(N, task, 'text has less than %s words: %s; disable shingles',
          rule.min_length, wcnt)
      allow_shingles = false
    else
      lua_util.debugm(N, task, 'allow shingles in text %s, %s words',
          id, wcnt)
      allow_shingles = true
    end

    if not rule.short_text_direct_hash and not allow_shingles then
      allow_direct = false
    else
      if not allow_shingles then
        lua_util.debugm(N, task,
            'allow direct hash for short text %s, %s words',
            id, wcnt)
        allow_direct = check_length(task, part, rule)
      else
        allow_direct = wcnt > 0
      end
    end
  else
    lua_util.debugm(N, task,
        'disable shingles in text %s', id)
    allow_direct = check_length(task, part, rule)
  end

  return allow_direct,allow_shingles
end

--local function has_sane_text_parts(task)
--  local text_parts = task:get_text_parts() or {}
--  return fun.any(function(tp) return tp:get_words_count() > 32 end, text_parts)
--end

local function check_image_part(task, part, rule, image)
  if rule.skip_images then
    lua_util.debugm(N, task, 'skip image part as images are disabled')
    return false,false
  end

  local id = part:get_id()
  lua_util.debugm(N, task, 'check image part %s', id)

  if rule.min_width > 0 or rule.min_height > 0 then
    -- Check dimensions
    local min_width = rule.min_width or rule.min_height
    local min_height = rule.min_height or rule.min_width
    local height = image:get_height()
    local width = image:get_width()

    if height and width then
      if height < min_height or width < min_width then
        lua_util.debugm(N, task, 'skip image part %s as it does not meet minimum sizes: %sx%s < %sx%s',
                id, width, height, min_width, min_height)
        return false, false
      else
        lua_util.debugm(N, task, 'allow image part %s: %sx%s',
            id, width, height)
      end
    end
  end

  return check_length(task, part, rule),false
end

local function mime_types_check(task, part, rule)
  local t,st = part:get_type()

  if not t then return false, false end

  local ct = string.format('%s/%s', t, st)

  local detected_ct
  t,st = part:get_detected_type()
  if t then
    detected_ct = string.format('%s/%s', t, st)
  else
    detected_ct = ct
  end

  local id = part:get_id()
  lua_util.debugm(N, task, 'check binary part %s: %s', id, ct)

  -- For bad mime mime parts we implicitly enable fuzzy check
  local mime_trace = (task:get_symbol('MIME_TRACE') or {})[1]
  local opts = {}

  if mime_trace then
    opts = mime_trace.options or opts
  end
  opts = fun.tomap(fun.map(function(opt)
    local elts = lua_util.str_split(opt, ':')
    return elts[1],elts[2]
  end, opts))

  if opts[id] and opts[id] == '-' then
    lua_util.debugm(N, task, 'explicitly check binary part %s: bad mime type %s', id, ct)
    return check_length(task, part, rule),false
  end

  if rule.mime_types then

    if fun.any(function(gl_re)
      if gl_re:match(ct) or (detected_ct and gl_re:match(detected_ct)) then
        return true
      else
        return false
      end
    end, rule.mime_types) then
      lua_util.debugm(N, task, 'found mime type match for part %s: %s (%s detected)',
          id, ct, detected_ct)
      return check_length(task, part, rule),false
    end

    return false, false
  end

  return false,false
end

exports.check_mime_part = function(task, part, rule_id)
  local rule = rules[rule_id]

  if not rule then
    rspamd_logger.errx(task, 'cannot find rule with id %s', rule_id)

    return false,false
  end

  if part:is_text() then
    return check_text_part(task, part, rule, part:get_text())
  end

  if part:is_image() then
    return check_image_part(task, part, rule, part:get_image())
  end

  if part:is_archive() and rule.scan_archives then
    -- Always send archives
    lua_util.debugm(N, task, 'check archive part %s', part:get_id())

    return true,false
  end

  if part:is_specific() then
    local sp = part:get_specific()

    if type(sp) == 'table' and sp.fuzzy_hashes then
      lua_util.debugm(N, task, 'check specific part %s', part:get_id())
      return true,false
    end
  end

  if part:is_attachment() then
    return mime_types_check(task, part, rule)
  end

  return false,false
end

exports.cleanup_rules = function()
  rules = {}
end

return exports
