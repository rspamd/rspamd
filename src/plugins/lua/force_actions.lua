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

-- Composites are resolved after normal filters, so a rule referencing one must
-- be a postfilter. Only the composites registered before this module is
-- configured are seen here, and a composite with a postfilter atom is resolved
-- after all postfilters, so a rule still cannot use it. A rule is also starved
-- by an earlier pre-result without `process_all`, as that suppresses composites.
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
-- What set_pre_result uses for a rule without a priority
local default_priority = named_priorities.normal
-- Per task: the action a matching rule left to the score (see gen_cb)
local kept_cache_key = 'force_actions_kept'

local function add_flag(flags, flag)
  if flags == '' then
    return flag
  elseif flags:find(flag, 1, true) then
    return flags
  end
  return flags .. ',' .. flag
end

-- Options of the FORCE_ACTION_* symbol
local function rule_options(action, priority)
  if priority then
    return { action, string.format('priority:%s', priority) }
  end
  return { action }
end

-- The SMTP reply of the pre-result that selects the action, if it is this one
local function selected_reply(task, action)
  local _, pre_action, pre_message, _, pre_flags = task:has_pre_result(true)
  if pre_action == action and not (pre_flags or ''):find('no_smtp_message', 1, true) then
    return pre_message
  end
end

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

  -- LuaJIT also reads quoted "inf" as a number, while Lua 5.3+ does not
  if priority == math.huge or priority == -math.huge then
    rspamd_logger.warnx(rspamd_config, 'force_actions rule %1: priority is not finite; ignored', name)
    return nil
  end

  local adjusted = math.floor(priority)

  if adjusted == 0 then
    -- LuaJIT keeps the sign of -0.0
    adjusted = 0
  end

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
-- expr, act, pool, message, subject, raction, honor, limit, flags, priority,
-- least; outranked and overridable are set once all rules are registered
local function gen_cb(params)
  params.flags = params.flags or ''

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
    if params.honor and params.honor[cact] then
      return false
    elseif params.raction and not params.raction[cact] then
      return false
    end

    -- Forcing the selected action changes nothing, while recording it would
    -- make the verdict passthrough. A rule with its own priority records it
    -- anyway to outrank the results set later, but the require/honor_action
    -- rules run last, so there is nothing left for them to outrank.
    local already_selected = not params.message and not params.subject
        and params.act and cact == params.act
    local keep_only = already_selected and (not params.priority or params.raction or params.honor)
    if keep_only and not params.overridable then
      return false
    end

    local ret = e:process(task)
    lua_util.debugm(N, task, "expression %s returned %s", params.expr, ret)
    if (not params.limit and ret > 0) or (ret > (params.limit or 0)) then
      local rank = params.priority or default_priority
      local kept = task:cache_get(kept_cache_key)

      if keep_only then
        -- A rule below this one may still match and change the action, so
        -- remember that the action is wanted at this priority, unless a rule
        -- above did so for the action that is still selected
        if not kept or kept.action ~= cact or rank >= kept.rank then
          task:cache_set(kept_cache_key, { action = params.act, rank = rank, priority = params.priority,
                                           flags = add_flag(params.flags, 'process_all'),
                                           symbol = params.symbol })
        end
        return false
      end

      -- A least result only raises the action, as before, whatever the priority
      if kept and not kept.recorded and not params.least and kept.action == cact
          and kept.action ~= params.act and rank < kept.rank then
        -- This rule would override the action kept by a rule above it
        kept.recorded = true
        task:set_pre_result { action = kept.action, message = selected_reply(task, kept.action), module = N,
                              flags = kept.flags, priority = kept.priority }
        task:insert_result(kept.symbol, 1.0, rule_options(kept.action, kept.priority))
      end

      if params.subject then
        task:set_metric_subject(params.subject)
      end

      local flags = params.flags
      -- Do not cut the scan short when competing for the selected action, or
      -- when a rule with a higher priority may still match
      if already_selected or params.outranked then
        flags = add_flag(flags, 'process_all')
      end

      local message
      if type(params.message) == 'string' then
        -- process selector expressions in the message
        message = string.gsub(params.message, '(${(.-)})', process_message_selectors)
      elseif already_selected then
        -- This result may outrank the one for the same action, keep its reply
        message = selected_reply(task, params.act)
      end

      -- A least rule without priority stays below the least results of the
      -- other modules (e.g. DMARC), as before
      local priority = params.priority
      if not priority and params.least then
        priority = named_priorities.low
      end

      task:set_pre_result { action = params.act, message = message, module = N, flags = flags,
                            priority = priority }

      return true, rule_options(params.act, params.priority)
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
    -- Stable order, as for the rules below; it decides between the actions
    -- matching at once
    local action_names = {}
    for action in pairs(opts.actions) do
      table.insert(action_names, action)
    end
    table.sort(action_names)

    for _, action in ipairs(action_names) do
      local expressions = opts.actions[action]
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
                -- Right after the composites, see the rules below
                t.type = 'postfilter'
                t.priority = lua_util.symbols_priorities.low
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

    local priorities = {}
    for _, name in ipairs(rule_names) do
      priorities[name] = check_priority(name, opts.rules[name].priority)
    end
    -- The require/honor_action rules share one postfilter level, which runs in
    -- the registration order: the higher priorities have to see the action
    -- before the lower ones change it
    local function late_rank(name)
      local sett = opts.rules[name]
      if sett.require_action or sett.honor_action then
        return priorities[name] or (sett.least and named_priorities.low or default_priority)
      end
      return -1
    end
    table.sort(rule_names, function(a, b)
      local ra, rb = late_rank(a), late_rank(b)
      if ra ~= rb then
        return ra > rb
      end
      return a < b
    end)

    local registered = {}
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
        local priority = priorities[name]
        if priority and sett.least then
          rspamd_logger.warnx(rspamd_config,
              'force_actions rule %1: `least` is set, so `priority` cannot outrank a non-least rule ' ..
              '(any non-least result always wins); it only orders this rule against other `least` rules',
              name)
        end
        local params = { expr = expr,
                         act = action,
                         pool = rspamd_config:get_mempool(),
                         message = sett.message,
                         subject = sett.subject,
                         raction = raction,
                         honor = honor,
                         limit = sett.limit,
                         priority = priority,
                         least = sett.least,
                         flags = table.concat(flags, ',') }
        local cb, atoms = gen_cb(params)
        if cb and atoms then
          local composite_dep = has_composite_atom(atoms)
          local t = {}
          if raction or honor then
            -- Acts on the action selected by everything else, so runs late
            t.type = 'postfilter'
            t.priority = lua_util.symbols_priorities.high
          elseif composite_dep then
            -- Right after the composites: before the postfilters acting on the
            -- selected action (e.g. greylisting) and the require/honor_action rules
            t.type = 'postfilter'
            t.priority = lua_util.symbols_priorities.low
          else
            t.type = 'normal'
            if not sett.least then
              t.augmentations = { 'passthrough', 'important' }
            end
          end
          t.name = 'FORCE_ACTION_' .. name
          params.symbol = t.name
          t.callback = cb
          t.flags = 'empty, ignore_passthrough'
          t.group = N
          rspamd_config:register_symbol(t)
          table.insert(registered, { params = params, main = t.type == 'normal' })

          local effective_priority = priority or (sett.least and named_priorities.low or default_priority)

          if t.type == 'normal' then
            for _, a in ipairs(atoms) do
              rspamd_config:register_dependency(t.name, a)
            end
            rspamd_logger.infox(rspamd_config,
                'Registered symbol %1 <%2> with dependencies [%3]; action %4, passthrough priority %5',
                t.name, expr, table.concat(atoms, ','), action, effective_priority)
          elseif composite_dep and not (raction or honor) then
            rspamd_logger.infox(rspamd_config,
                'Registered symbol %1 <%2> as postfilter (expression uses composite symbol(s)); ' ..
                'action %3, passthrough priority %4', t.name, expr, action, effective_priority)
          else
            rspamd_logger.infox(rspamd_config,
                'Registered symbol %1 <%2> as postfilter; action %3, passthrough priority %4',
                t.name, expr, action, effective_priority)
          end
        end
      end
    end

    for _, r in ipairs(registered) do
      local p = r.params
      local rank = p.priority or default_priority
      for _, other in ipairs(registered) do
        local o = other.params
        local other_rank = o.priority or default_priority
        -- A match without `process_all` stops the symbols that have not run
        -- yet, composites included, so a rule above it might never match (a
        -- least one cannot outrank it anyway). The postfilter rules run once
        -- all of their atoms are known, so they cannot be starved that way.
        if r.main and not o.least and other_rank > rank then
          p.outranked = true
        end
        -- A rule below this one could still change the selected action (a
        -- least one only raises it, whatever the priorities)
        if not p.least and not o.least and other_rank < rank and o.act ~= p.act then
          p.overridable = true
        end
      end
    end
  end
end

configure_module()
