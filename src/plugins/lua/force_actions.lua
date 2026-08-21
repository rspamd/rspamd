--[[
Copyright (c) 2017-2026, Vsevolod Stakhov <vsevolod@rspamd.com>

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

-- A plugin that forces actions

if confighelp then
  return
end

local E = {}
local N = 'force_actions'
local selector_cache = {}

local fun = require "fun"
local lua_util = require "lua_util"
local rspamd_cryptobox_hash = require "rspamd_cryptobox_hash"
local rspamd_expression = require "rspamd_expression"
local rspamd_logger = require "rspamd_logger"
local lua_selectors = require "lua_selectors"

-- Composite symbols are only resolved after normal filters have run, so a
-- 'normal' symbol cannot depend on them via register_dependency (the cache
-- rejects such cross-stage deps). Any rule referencing a composite atom must
-- therefore be registered as a postfilter instead.
-- Such a rule is still starved if any earlier pre-result was set without
-- `process_all`, since that suppresses composite evaluation entirely.
local function has_composite_atom(atoms)
  for _, a in ipairs(atoms) do
    -- get_symbol_flags returns an array of flag names, not a keyed map
    for _, fl in ipairs(rspamd_config:get_symbol_flags(a) or {}) do
      if fl == 'composite' then
        return true
      end
    end
  end
  return false
end

-- Passthrough priority band from src/libmime/scan_result.h:
-- 0 = low, 1 = normal (default), 2 = high, 3 = critical (used by the core for
-- broken messages). The C side stores it as unsigned int, so a negative value
-- would wrap around and outrank everything.
local min_priority, max_priority = 0, 3
local named_priorities = {
  low = 0,
  normal = 1,
  high = 2,
  critical = 3,
}

local function check_priority(name, priority)
  if priority == nil then
    return nil
  end

  if type(priority) == 'string' then
    local named = named_priorities[string.lower(priority)]

    if named then
      return named
    end

    -- UCL may hand us a quoted number
    local as_number = tonumber(priority)

    if not as_number then
      rspamd_logger.warnx(rspamd_config,
          'force_actions rule %1: unknown priority name "%2", expected one of low/normal/high/critical; ignored',
          name, priority)
      return nil
    end

    priority = as_number
  end

  if type(priority) ~= 'number' then
    rspamd_logger.warnx(rspamd_config, 'force_actions rule %1: priority must be a number or a name, got %2; ignored',
        name, type(priority))
    return nil
  end

  -- NaN is the only number that does not compare equal to itself
  if priority ~= priority then
    rspamd_logger.warnx(rspamd_config, 'force_actions rule %1: priority is NaN; ignored', name)
    return nil
  end

  local adjusted = math.floor(priority)

  if adjusted ~= priority then
    rspamd_logger.warnx(rspamd_config, 'force_actions rule %1: priority %2 is not an integer, adjusted to %3',
        name, priority, adjusted)
  end

  if adjusted < min_priority or adjusted > max_priority then
    local clamped = math.max(min_priority, math.min(max_priority, adjusted))
    rspamd_logger.warnx(rspamd_config,
        'force_actions rule %1: priority %2 is out of the allowed range [%3..%4], adjusted to %5',
        name, adjusted, min_priority, max_priority, clamped)
    adjusted = clamped
  end

  return adjusted
end

-- Params table fields:
-- expr, act, pool, message, subject, raction, honor, limit, flags, priority
local function gen_cb(params)

  local function parse_atom(str)
    local atom = table.concat(fun.totable(fun.take_while(function(c)
      if string.find(', \t()><+!|&\n', c, 1, true) then
        return false
      end
      return true
    end, fun.iter(str))), '')
    return atom
  end

  local function process_atom(atom, task)
    local f_ret = task:has_symbol(atom)
    if f_ret then
      f_ret = math.abs(task:get_symbol(atom)[1].score)
      if f_ret < 0.001 then
        -- Adjust some low score to distinguish from pure zero
        f_ret = 0.001
      end
      return f_ret
    end
    return 0
  end

  local e, err = rspamd_expression.create(params.expr, { parse_atom, process_atom }, params.pool)
  if err then
    rspamd_logger.errx(rspamd_config, 'Couldnt create expression [%1]: %2', params.expr, err)
    return
  end

  return function(task)

    local function process_message_selectors(repl, selector_expr)
      -- create/reuse selector to extract value for this placeholder
      local selector = selector_cache[selector_expr]
      if not selector then
        selector_cache[selector_expr] = lua_selectors.create_selector_closure(rspamd_config, selector_expr, '', true)
        selector = selector_cache[selector_expr]
        if not selector then
          rspamd_logger.errx(task, 'could not create selector [%1]', selector_expr)
          return "((could not create selector))"
        end
      end
      local extracted = selector(task)
      if extracted then
        if type(extracted) == 'table' then
          extracted = table.concat(extracted, ',')
        end
      else
        rspamd_logger.errx(task, 'could not extract value with selector [%1]', selector_expr)
        extracted = '((error extracting value))'
      end
      return extracted
    end

    local cact = task:get_metric_action()
    if not params.message and not params.subject and params.act and cact == params.act then
      return false
    end
    if params.honor and params.honor[cact] then
      return false
    elseif params.raction and not params.raction[cact] then
      return false
    end

    local ret = e:process(task)
    lua_util.debugm(N, task, "expression %s returned %s", params.expr, ret)
    if (not params.limit and ret > 0) or (ret > (params.limit or 0)) then
      if params.subject then
        task:set_metric_subject(params.subject)
      end

      local flags = params.flags or ""

      if type(params.message) == 'string' then
        -- process selector expressions in the message
        local message = string.gsub(params.message, '(${(.-)})', process_message_selectors)
        task:set_pre_result { action = params.act, message = message, module = N, flags = flags,
                              priority = params.priority }
      else
        task:set_pre_result { action = params.act, module = N, flags = flags, priority = params.priority }
      end
      return true, params.act
    end

  end, e:atoms()

end

local function configure_module()
  local opts = rspamd_config:get_all_opt(N)
  if not opts then
    return false
  end
  if type(opts.actions) == 'table' then
    rspamd_logger.warnx(rspamd_config, 'Processing legacy config')
    for action, expressions in pairs(opts.actions) do
      if type(expressions) == 'table' then
        for _, expr in ipairs(expressions) do
          local message, subject
          if type(expr) == 'table' then
            subject = expr[3]
            message = expr[2]
            expr = expr[1]
          else
            message = (opts.messages or E)[expr]
          end
          if type(expr) == 'string' then
            -- expr, act, pool, message, subject, raction, honor, limit, flags
            local cb, atoms = gen_cb { expr = expr,
                                       act = action,
                                       pool = rspamd_config:get_mempool(),
                                       message = message,
                                       subject = subject }
            if cb and atoms then
              local h = rspamd_cryptobox_hash.create()
              h:update(expr)
              local name = 'FORCE_ACTION_' .. string.upper(string.sub(h:hex(), 1, 12))
              local composite_dep = has_composite_atom(atoms)
              local t = {
                name = name,
                callback = cb,
                flags = 'empty',
                group = N,
              }
              if composite_dep then
                t.type = 'postfilter'
                t.priority = lua_util.symbols_priorities.high
              else
                t.type = 'normal'
              end
              rspamd_config:register_symbol(t)
              if t.type == 'normal' then
                for _, a in ipairs(atoms) do
                  rspamd_config:register_dependency(name, a)
                end
                rspamd_logger.infox(rspamd_config, 'Registered symbol %1 <%2> with dependencies [%3]',
                    name, expr, table.concat(atoms, ','))
              else
                rspamd_logger.infox(rspamd_config,
                    'Registered symbol %1 <%2> as postfilter (expression uses composite symbol(s))', name, expr)
              end
            end
          end
        end
      end
    end
  elseif type(opts.rules) == 'table' then
    -- Register in a stable order: pairs() over a UCL object is arbitrary, and
    -- registration order leaks into the symcache ordering heuristics.
    local rule_names = {}
    for name in pairs(opts.rules) do
      table.insert(rule_names, name)
    end
    table.sort(rule_names)

    for _, name in ipairs(rule_names) do
      local sett = opts.rules[name]
      local action = sett.action
      local expr = sett.expression

      if action and expr then
        local flags = {}
        if sett.least then
          table.insert(flags, "least")
        end
        if sett.process_all then
          table.insert(flags, "process_all")
        end
        local raction = lua_util.list_to_hash(sett.require_action)
        local honor = lua_util.list_to_hash(sett.honor_action)
        local priority = check_priority(name, sett.priority)
        if priority and sett.least then
          rspamd_logger.warnx(rspamd_config,
              'force_actions rule %1: `least` is set, so `priority` cannot outrank a non-least rule ' ..
              '(any non-least result always wins); it only orders this rule against other `least` rules',
              name)
        end
        local cb, atoms = gen_cb { expr = expr,
                                   act = action,
                                   pool = rspamd_config:get_mempool(),
                                   message = sett.message,
                                   subject = sett.subject,
                                   raction = raction,
                                   honor = honor,
                                   limit = sett.limit,
                                   priority = priority,
                                   flags = table.concat(flags, ',') }
        if cb and atoms then
          local composite_dep = has_composite_atom(atoms)
          local t = {}
          if (raction or honor or composite_dep) then
            t.type = 'postfilter'
            t.priority = lua_util.symbols_priorities.high
          else
            t.type = 'normal'
            if not sett.least then
              t.augmentations = { 'passthrough', 'important' }
            end
          end
          t.name = 'FORCE_ACTION_' .. name
          t.callback = cb
          t.flags = 'empty, ignore_passthrough'
          t.group = N
          rspamd_config:register_symbol(t)
          if t.type == 'normal' then
            for _, a in ipairs(atoms) do
              rspamd_config:register_dependency(t.name, a)
            end
            rspamd_logger.infox(rspamd_config,
                'Registered symbol %1 <%2> with dependencies [%3]; action %4, passthrough priority %5',
                t.name, expr, table.concat(atoms, ','), action, priority or 1)
          elseif composite_dep and not (raction or honor) then
            rspamd_logger.infox(rspamd_config,
                'Registered symbol %1 <%2> as postfilter (expression uses composite symbol(s)); ' ..
                'action %3, passthrough priority %4', t.name, expr, action, priority or 1)
          else
            rspamd_logger.infox(rspamd_config,
                'Registered symbol %1 <%2> as postfilter; action %3, passthrough priority %4',
                t.name, expr, action, priority or 1)
          end
        end
      end
    end
  end
end

configure_module()
