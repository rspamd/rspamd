--[[
Copyright (c) 2017, Andrew Lewis <nerf@judo.za.org>
Copyright (c) 2017, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

-- Params table fields:
-- expr, act, pool, message, subject, raction, honor, limit, flags
local function gen_cb(params)

  local function parse_atom(str)
    local atom = table.concat(fun.totable(fun.take_while(function(c)
      if string.find(', \t()><+!|&\n', c) then
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

  local e, err = rspamd_expression.create(params.expr, {parse_atom, process_atom}, params.pool)
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

    local cact = task:get_metric_action('default')
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
        task:set_pre_result{action = params.act, message = message, module = N, flags = flags}
      else
        task:set_pre_result{action = params.act, module = N, flags = flags}
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
            local cb, atoms = gen_cb{expr = expr,
                                     act = action,
                                     pool = rspamd_config:get_mempool(),
                                     message = message,
                                     subject = subject}
            if cb and atoms then
              local h = rspamd_cryptobox_hash.create()
              h:update(expr)
              local name = 'FORCE_ACTION_' .. string.upper(string.sub(h:hex(), 1, 12))
              rspamd_config:register_symbol({
                type = 'normal',
                name = name,
                callback = cb,
                flags = 'empty',
              })
              for _, a in ipairs(atoms) do
                rspamd_config:register_dependency(name, a)
              end
              rspamd_logger.infox(rspamd_config, 'Registered symbol %1 <%2> with dependencies [%3]',
                  name, expr, table.concat(atoms, ','))
            end
          end
        end
      end
    end
  elseif type(opts.rules) == 'table' then
    for name, sett in pairs(opts.rules) do
      local action = sett.action
      local expr = sett.expression

      if action and expr then
        local flags = {}
        if sett.least then table.insert(flags, "least") end
        if sett.process_all then table.insert(flags, "process_all") end
        local raction = lua_util.list_to_hash(sett.require_action)
        local honor = lua_util.list_to_hash(sett.honor_action)
        local cb, atoms = gen_cb{expr = expr,
                                 act = action,
                                 pool = rspamd_config:get_mempool(),
                                 message = sett.message,
                                 subject = sett.subject,
                                 raction = raction,
                                 honor = honor,
                                 limit = sett.limit,
                                 flags = table.concat(flags, ',')}
        if cb and atoms then
          local t = {}
          if (raction or honor) then
            t.type = 'postfilter'
            t.priority = 10
          else
            t.type = 'normal'
          end
          t.name = 'FORCE_ACTION_' .. name
          t.callback = cb
          t.flags = 'empty'
          rspamd_config:register_symbol(t)
          if t.type == 'normal' then
            for _, a in ipairs(atoms) do
              rspamd_config:register_dependency(t.name, a)
            end
            rspamd_logger.infox(rspamd_config, 'Registered symbol %1 <%2> with dependencies [%3]',
                t.name, expr, table.concat(atoms, ','))
          else
            rspamd_logger.infox(rspamd_config, 'Registered symbol %1 <%2> as postfilter', t.name, expr)
          end
        end
      end
    end
  end
end

configure_module()
