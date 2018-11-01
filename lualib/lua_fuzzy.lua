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
    min_length = 100, -- short words multiplier
    text_multiplier = 4.0, -- divide min_bytes by 4 for texts
    mime_types = {"*"},
    short_text_direct_hash = true,
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
  short_text_direct_hash = ts.bool,
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

return exports