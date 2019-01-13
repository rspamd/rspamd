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
local lua_util = require 'lua_util'

-- Squeezed rules part
local squeezed_rules = {{}} -- plain vector of all rules squeezed
local squeezed_symbols = {} -- indexed by name of symbol
local squeezed_deps = {} -- squeezed deps
local squeezed_rdeps = {} -- squeezed reverse deps
local SN = 'lua_squeeze'
local squeeze_sym = 'LUA_SQUEEZE'
local squeeze_function_ids = {}
local squeezed_groups = {}

local function gen_lua_squeeze_function(order)
  return function(task)
    local symbols_disabled = task:cache_get('squeezed_disable')
    local mime_task = task:has_flag('mime')
    for _,data in ipairs(squeezed_rules[order]) do
      local disable = false
      if symbols_disabled and symbols_disabled[data[2]] then
        disable = true
      end

      if data[3] and data[3].flags.mime then
        if not mime_task then
          disable = true
        end
      end

      if not disable then
        local function real_call()
          return {data[1](task)}
        end

        -- Too expensive to call :(
        lua_util.debugm(SN, task, 'call for: %s', data[2])
        local status, ret = pcall(real_call)

        if not status then
          logger.errx(task, 'error in squeezed rule %s: %s', data[2], ret)
        else
          if #ret ~= 0 then
            local first = ret[1]
            local sym = data[2]
            -- Function has returned something, so it is rule, not a plugin
            if type(first) == 'boolean' then
              if first then
                table.remove(ret, 1)

                local second = ret[1]

                if type(second) == 'number' then
                  table.remove(ret, 1)
                  if second ~= 0 then
                    if type(ret[1]) == 'table' then
                      task:insert_result(sym, second, ret[1])
                    else
                      task:insert_result(sym, second, ret)
                    end
                  end
                else
                  if type(ret[1]) == 'table' then
                    task:insert_result(sym, 1.0, ret[1])
                  else
                    task:insert_result(sym, 1.0, ret)
                  end
                end
              end
            elseif type(first) == 'number' then
              table.remove(ret, 1)

              if first ~= 0 then
                if type(ret[1]) == 'table' then
                  task:insert_result(sym, first, ret[1])
                else
                  task:insert_result(sym, first, ret)
                end
              end
            else
              if type(ret[1]) == 'table' then
                task:insert_result(sym, 1.0, ret[1])
              else
                task:insert_result(sym, 1.0, ret)
              end
            end
          end
        end
      else
        lua_util.debugm(SN, task, 'skip symbol due to settings: %s', data[2])
      end


      end
  end
end

exports.squeeze_rule = function(s, func, flags)
  if s then
    if not squeezed_symbols[s] then
      squeezed_symbols[s] = {
        cb = func,
        order = 0,
        sym = s,
        flags = flags or {}
      }
      lua_util.debugm(SN, rspamd_config, 'squeezed rule: %s', s)
    else
      logger.warnx(rspamd_config, 'duplicate symbol registered: %s, skip', s)
    end
  else
    -- Unconditionally add function to the squeezed rules
    local id = tostring(#squeezed_rules)
    lua_util.debugm(SN, rspamd_config, 'squeezed unnamed rule: %s', id)
    table.insert(squeezed_rules[1], {func, 'unnamed: ' .. id, squeezed_symbols[s]})
  end

  if not squeeze_function_ids[1] then
    squeeze_function_ids[1] = rspamd_config:register_symbol{
      type = 'callback',
      flags = 'squeezed',
      callback = gen_lua_squeeze_function(1),
      name = squeeze_sym,
      description = 'Meta rule for Lua rules that can be squeezed',
      no_squeeze = true, -- to avoid infinite recursion
    }
  end

  return squeeze_function_ids[1]
end

exports.squeeze_dependency = function(child, parent)
  lua_util.debugm(SN, rspamd_config, 'squeeze dep %s->%s', child, parent)

  if not squeezed_deps[parent] then
    squeezed_deps[parent] = {}
  end

  if not squeezed_deps[parent][child] then
    squeezed_deps[parent][child] = true
  else
    logger.warnx(rspamd_config, 'duplicate dependency %s->%s', child, parent)
  end

  if not squeezed_rdeps[child] then
    squeezed_rdeps[child] = {}
  end

  if not squeezed_rdeps[child][parent] then
    squeezed_rdeps[child][parent] = true
  end

  return true
end

local function get_ordered_symbol_name(order)
  if order == 1 then
    return squeeze_sym
  end

  return squeeze_sym .. tostring(order)
end

local function register_topology_symbol(order)
  local ord_sym = get_ordered_symbol_name(order)

  squeeze_function_ids[order] = rspamd_config:register_symbol{
    type = 'callback',
    flags = 'squeezed',
    callback = gen_lua_squeeze_function(order),
    name = ord_sym,
    description = 'Meta rule for Lua rules that can be squeezed, order ' .. tostring(order),
    no_squeeze = true, -- to avoid infinite recursion
  }

  local parent = get_ordered_symbol_name(order - 1)
  lua_util.debugm(SN, rspamd_config, 'registered new order of deps: %s->%s',
      ord_sym, parent)
  rspamd_config:register_dependency(ord_sym, parent, true)
end

exports.squeeze_init = function()
  -- Do topological sorting
  for _,v in pairs(squeezed_symbols) do
    local function visit(node, order)

      if order > node.order then
        node.order = order
        lua_util.debugm(SN, rspamd_config, "symbol: %s, order: %s", node.sym, order)
      else
        return
      end

      if squeezed_deps[node.sym] then
        for dep,_ in pairs(squeezed_deps[node.sym]) do
          if squeezed_symbols[dep] then
            visit(squeezed_symbols[dep], order + 1)
          end
        end
      end
    end

    if v.order == 0 then
      visit(v, 1)
    end
  end

  for parent,children in pairs(squeezed_deps) do
    if not squeezed_symbols[parent] then
      -- Trivial case, external dependnency

      for s,_ in pairs(children) do

        if squeezed_symbols[s] then
          -- External dep depends on a squeezed symbol
          lua_util.debugm(SN, rspamd_config, 'register external squeezed dependency on %s',
              parent)
          rspamd_config:register_dependency(squeeze_sym, parent, true)
        else
          -- Generic rspamd symbols dependency
          lua_util.debugm(SN, rspamd_config, 'register external dependency %s -> %s',
              s, parent)
          rspamd_config:register_dependency(s, parent, true)
        end
      end
    else
      -- Not so trivial case
      local ps = squeezed_symbols[parent]

      for cld,_ in pairs(children) do
        if squeezed_symbols[cld] then
          -- Cross dependency
          lua_util.debugm(SN, rspamd_config, 'cross dependency in squeezed symbols %s->%s',
              cld, parent)
          local order = squeezed_symbols[cld].order
          if not squeeze_function_ids[order] then
            -- Need to register new callback symbol to handle deps
            for i = 1, order do
              if not squeeze_function_ids[i] then
                register_topology_symbol(i)
              end
            end
          end
        else
          -- External symbol depends on a squeezed one
          local parent_symbol = get_ordered_symbol_name(ps.order)
          rspamd_config:register_dependency(cld, parent_symbol, true)
          lua_util.debugm(SN, rspamd_config, 'register squeezed dependency for external symbol %s->%s',
              cld, parent_symbol)
        end
      end
    end
  end

  -- We have now all deps being registered, so we can register virtual symbols
  -- and create squeezed rules
  for k,v in pairs(squeezed_symbols) do
    local parent_symbol = get_ordered_symbol_name(v.order)
    lua_util.debugm(SN, rspamd_config, 'added squeezed rule: %s (%s): %s',
        k, parent_symbol, v)
    rspamd_config:register_symbol{
      type = 'virtual',
      name = k,
      flags = 'squeezed',
      parent = squeeze_function_ids[v.order],
      no_squeeze = true, -- to avoid infinite recursion
    }
    local metric_sym = rspamd_config:get_metric_symbol(k)

    if metric_sym then
      v.group = metric_sym.group
      v.groups = metric_sym.groups
      v.score = metric_sym.score
      v.description = metric_sym.description

      if v.group then
        if not squeezed_groups[v.group] then
          lua_util.debugm(SN, rspamd_config, 'added squeezed group: %s', v.group)
          squeezed_groups[v.group] = {}
        end

        table.insert(squeezed_groups[v.group], k)

      end
      if v.groups then
        for _,gr in ipairs(v.groups) do
          if not squeezed_groups[gr] then
            lua_util.debugm(SN, rspamd_config, 'added squeezed group: %s', gr)
            squeezed_groups[gr] = {}
          end

          table.insert(squeezed_groups[gr], k)
        end
      end
    else
      lua_util.debugm(SN, rspamd_config, 'no metric symbol found for %s, maybe bug', k)
    end
    if not squeezed_rules[v.order] then
      squeezed_rules[v.order] = {}
    end
    table.insert(squeezed_rules[v.order], {v.cb,k,v})
  end
end

exports.handle_settings = function(task, settings)
  local symbols_disabled = {}
  local symbols_enabled = {}
  local found = false

  if settings.default then settings = settings.default end

  local function disable_all()
    for k,_ in pairs(squeezed_symbols) do
      if not symbols_enabled[k] then
        symbols_disabled[k] = true
      end
    end
  end

  if settings.symbols_enabled then
    disable_all()
    found = true
    for _,s in ipairs(settings.symbols_enabled) do
      if squeezed_symbols[s] then
        lua_util.debugm(SN, task, 'enable symbol %s as it is in `symbols_enabled`', s)
        symbols_enabled[s] = true
        symbols_disabled[s] = nil
      end
    end
  end

  if settings.groups_enabled then
    disable_all()
    found = true
    for _,gr in ipairs(settings.groups_enabled) do
      if squeezed_groups[gr] then
        for _,sym in ipairs(squeezed_groups[gr]) do
          lua_util.debugm(SN, task, 'enable symbol %s as it is in `groups_enabled`', sym)
          symbols_enabled[sym] = true
          symbols_disabled[sym] = nil
        end
      end
    end
  end

  if settings.symbols_disabled then
    found = true
    for _,s in ipairs(settings.symbols_disabled) do
      lua_util.debugm(SN, task, 'try disable symbol %s as it is in `symbols_disabled`', s)
      if not symbols_enabled[s] then
        symbols_disabled[s] = true
        lua_util.debugm(SN, task, 'disable symbol %s as it is in `symbols_disabled`', s)
      end
    end
  end

  if settings.groups_disabled then
    found = true
    for _,gr in ipairs(settings.groups_disabled) do
      lua_util.debugm(SN, task, 'try disable group %s as it is in `groups_disabled`: %s', gr)
      if squeezed_groups[gr] then
        for _,sym in ipairs(squeezed_groups[gr]) do
          if not symbols_enabled[sym] then
            lua_util.debugm(SN, task, 'disable symbol %s as it is in `groups_disabled`', sym)
            symbols_disabled[sym] = true
          end
        end
      end
    end
  end

  if found then
    task:cache_set('squeezed_disable', symbols_disabled)
  end
end

return exports