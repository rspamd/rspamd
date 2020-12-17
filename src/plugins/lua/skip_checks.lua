--[[
Copyright (c) 2020, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

-- A plugin that skips checks based on results of other symbols

if confighelp then
  return
end

local N = 'skip_checks'

local fun = require "fun"
local lua_util = require "lua_util"
local rspamd_expression = require "rspamd_expression"
local rspamd_logger = require "rspamd_logger"
local ts = require("tableshape").types

local rule_schema = ts.shape{
  expression = ts.string,
  target = ts.string,
}

-- Params table fields:
-- expr, target, pool
local function generate_expression(params)

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
    local ret = task:has_symbol(atom)
    if ret then
      return 1
    end
    return 0
  end

  local e, err = rspamd_expression.create(params.expr, {parse_atom, process_atom}, params.pool)
  if err then
    rspamd_logger.errx(rspamd_config, 'Couldnt create expression [%1]: %2', params.expr, err)
    return
  end

  return e
end

local function generate_condition(params)
  return function(task)

    local ret = params.e:process(task)
    lua_util.debugm(N, task, "expression %s returned %s", params.expr, ret)
    if ret > 0 then
      return false
    end
    return true
  end
end

local function configure_module()
  local opts = rspamd_config:get_all_opt(N)
  if not opts then
    return false
  end
  if type(opts.rules) ~= 'table' then
    return false
  end
  for name, rule in pairs(opts.rules) do
    local ok, err = rule_schema:transform(rule)
    if not ok then
      rspamd_logger.errx(rspamd_config, 'Bad config for %s: %s', name, err)
      return false
    end
    local expr = rule.expression
    local target = rule.target
    local e = generate_expression({
      expr = expr,
      pool = rspamd_config:get_mempool(),
      target = target,
    })
    local atoms
    if e then
      atoms = e:atoms()
    end
    if atoms then
      for _, a in ipairs(atoms) do
        rspamd_config:register_dependency(target, a)
      end
      local condition = generate_condition({
        e = e,
	expr = expr,
      })
      rspamd_config:add_condition(target, condition)
    end
  end
end

configure_module()
