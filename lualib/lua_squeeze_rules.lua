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

local exports = {}
local logger = require 'rspamd_logger'

-- Squeezed rules part
local squeezed_rules = {} -- plain vector of all rules squeezed
local squeezed_symbols = {} -- indexed by name of symbol
local squeezed_deps = {} -- squeezed deps
local SN = 'lua_squeeze'
local squeeze_function_id

local function lua_squeeze_function(task)
  if not squeezed_symbols then
    for k,v in pairs(squeezed_symbols) do
      if not squeezed_exceptions[k] then
        logger.debugm(SN, task, 'added squeezed rule: %s', k)
        table.insert(squeezed_rules, v)
      else
        logger.debugm(SN, task, 'skipped squeezed rule: %s', k)
      end
    end

    squeezed_symbols = nil
  end

  for _,func in ipairs(squeezed_rules) do
    local ret = func(task)

    if ret then
      -- Function has returned something, so it is rule, not a plugin
      logger.errx(task, 'hui: %s', ret)
    end
  end
end

exports.squeeze_rule = function(s, func)
  if s then
    if not squeezed_symbols[s] then
      squeezed_symbols[s] = {
        cb = func,
        order = 0,
      }
      logger.debugm(SN, rspamd_config, 'squeezed rule: %s', s)
    else
      logger.warnx(rspamd_config, 'duplicate symbol registered: %s, skip', s)
    end
  else
    -- Unconditionally add function to the squeezed rules
    logger.debugm(SN, rspamd_config, 'squeezed unnamed rule: %s', #squeezed_rules)
    table.insert(squeezed_rules, func)
  end

  if not squeeze_function_id then
    squeeze_function_id = rspamd_config:register_symbol{
      type = 'callback',
      callback = lua_squeeze_function,
      name = 'LUA_SQUEEZE',
      description = 'Meta rule for Lua rules that can be squeezed',
      no_squeeze = true, -- to avoid infinite recursion
    }
  end

  return squeeze_function_id
end

exports.squeeze_dependency = function(from, to)
  logger.debugm(SN, rspamd_config, 'squeeze dep %s->%s', to, from)

  if not squeezed_deps[to] then
    squeezed_deps[to] = {}
  end

  if not squeezed_symbols[to][from] then
    squeezed_symbols[to][from] = true
  else
    logger.warnx('duplicate dependency %s->%s', to, from)
  end

  return true
end

return exports