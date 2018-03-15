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
local squeeze_sym = 'LUA_SQUEEZE'
local squeeze_function_ids = {}

local function lua_squeeze_function(task)
  for _,data in ipairs(squeezed_rules) do
    local ret = {data[1](task)}

    if #ret ~= 0 then
      local first = ret[1]
      local sym = data[2]
      -- Function has returned something, so it is rule, not a plugin
      if type(first) == 'boolean' then
        if first then
          table.remove(ret, 1)
          task:insert_result(sym, 1.0, ret)
        end
      elseif type(first) == 'number' then
        table.remove(ret, 1)
        task:insert_result(sym, first, ret)
      else
        task:insert_result(sym, 1.0, ret)
      end
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
    local id = tostring(#squeezed_rules)
    logger.debugm(SN, rspamd_config, 'squeezed unnamed rule: %s', id)
    table.insert(squeezed_rules, {func, 'unnamed: ' .. id})
  end

  if not squeeze_function_ids[1] then
    squeeze_function_ids[1] = rspamd_config:register_symbol{
      type = 'callback',
      callback = lua_squeeze_function,
      name = squeeze_sym,
      description = 'Meta rule for Lua rules that can be squeezed',
      no_squeeze = true, -- to avoid infinite recursion
    }
  end

  return squeeze_function_ids[1]
end

exports.squeeze_dependency = function(child, parent)
  logger.debugm(SN, rspamd_config, 'squeeze dep %s->%s', child, parent)

  if not squeezed_deps[parent] then
    squeezed_deps[parent] = {}
  end

  if not squeezed_deps[parent][child] then
    squeezed_deps[parent][child] = true
  else
    logger.warnx(rspamd_config, 'duplicate dependency %s->%s', child, parent)
  end

  return true
end

local function get_ordered_symbol_name(order)
  if order == 0 then
    return squeeze_sym
  end

  return squeeze_sym .. tostring(order)
end

local function register_topology_symbol(order)
  local ord_sym = get_ordered_symbol_name(order)

  squeeze_function_ids[order + 1] = rspamd_config:register_symbol{
    type = 'callback',
    callback = lua_squeeze_function,
    name = ord_sym,
    description = 'Meta rule for Lua rules that can be squeezed, order ' .. tostring(order),
    no_squeeze = true, -- to avoid infinite recursion
  }

  local parent = get_ordered_symbol_name(order - 1)
  logger.debugm(SN, rspamd_config, 'registered new order of deps: %s->%s',
      ord_sym, parent)
  rspamd_config:register_dependency(ord_sym, parent, true)
end

exports.squeeze_init = function()
  local max_topology_order = 0

  for parent,children in pairs(squeezed_deps) do
    if not squeezed_symbols[parent] then
      -- Trivial case, external dependnency
      logger.debugm(SN, rspamd_config, 'register external squeezed dependency on %s',
          parent)
      rspamd_config:register_dependency(squeeze_sym, parent, true)
    else
      -- Not so trivial case
      local ps = squeezed_symbols[parent]

      for cld,_ in pairs(children) do
        if squeezed_symbols[cld] then
          -- Cross dependency
          logger.debugm(SN, rspamd_config, 'cross dependency in squeezed symbols %s->%s',
              cld, parent)
          local order = math.max(ps.order + 1, squeezed_symbols[cld].order)
          squeezed_symbols[cld].order = order
          if order > max_topology_order then
            -- Need to register new callback symbol to handle deps
            register_topology_symbol(order)
            max_topology_order = order
          end
        else
          -- External symbol depends on a squeezed one
          local parent_symbol = get_ordered_symbol_name(ps.order)
          rspamd_config:register_dependency(cld, parent_symbol, true)
          logger.debugm(SN, rspamd_config, 'register squeezed dependency for external symbol %s->%s',
              cld, parent_symbol)
        end
      end
    end
  end

  -- We have now all deps being registered, so we can register virtual symbols
  -- and create squeezed rules
  for k,v in pairs(squeezed_symbols) do
    local parent_symbol = get_ordered_symbol_name(v.order)
    logger.debugm(SN, rspamd_config, 'added squeezed rule: %s (%s)', k, parent_symbol)
    rspamd_config:register_symbol{
      type = 'virtual',
      name = k,
      parent = squeeze_function_ids[v.order + 1],
      no_squeeze = true, -- to avoid infinite recursion
    }
    table.insert(squeezed_rules, {v.cb,k})
  end
end

return exports