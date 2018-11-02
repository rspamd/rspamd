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
    min_length = 32,
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
  scan_archives = ts.bool,
  short_text_direct_hash = ts.bool,
  text_shingles = ts.bool,
  skip_imagess = ts.bool,
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

    if policy then
      processed_rule = lua_util.override_defaults(policy, processed_rule)
    else
      rspamd_logger.warnx(rspamd_config, "unknown policy %s", processed_rule.policy)
    end
  end

  table.insert(rules, processed_rule)
  return #rules
end

local function check_length(task, part, rule)
  local length_ok = true

  if rule.min_bytes then
    local bytes = part:get_length()
    local adjusted_bytes = bytes

    if part:is_text() then
      if rule.text_multiplier then
        adjusted_bytes = bytes * rule.text_multiplier
      end
    end

    if rule.min_bytes > adjusted_bytes then
      lua_util.debugm(N, task, 'skip part of length %s (%s adjusted)' ..
          'as it has less than %s bytes',
          bytes, adjusted_bytes, rule.min_bytes)
      length_ok = false
    end
  end

  return length_ok
end

local function check_text_part(task, part, rule, text)
  local allow_direct,allow_shingles = false,false

  if rule.text_shingles then
    -- Check number of words
    local wcnt = text:get_words_count()
    if rule.min_length and wcnt < rule.min_length then
      lua_util.debugm(N, task, 'text has less than %s words: %s',
          rule.min_length, wcnt)
      allow_shingles = false
    else
      allow_shingles = true
    end

    if not rule.short_text_direct_hash and not allow_shingles then
      allow_direct = false
    else
      allow_direct = check_length(task, part, rule)
    end

  else
    allow_direct = check_length(task, part, rule)
  end

  return allow_direct,allow_shingles
end

local function check_image_part(task, part, rule, image)
  if rule.skip_images then
    lua_util.debugm(N, task, 'skip image part as images are disabled')
    return false,false
  end

  if rule.min_width or rule.min_height then
    -- Check dimensions
    local min_width = rule.min_width or rule.min_height
    local min_height = rule.min_height or rule.min_width
    local height = image:get_height()
    local width = image:get_width()

    if height and width then
      if height < min_height or width < min_width then
        lua_util.debugm(N, task, 'skip image part as it does not meet minimum sizes: %sx%s < %sx%s',
          width, height, min_width, min_height)

        return false, false
      end
    end
  end

  return check_length(task, part, rule),false
end

local function mime_types_check(task, part, rule)
  return true,true -- TODO: add checks
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
    return true,false
  end

  return mime_types_check(task, part, rule)
end

return exports