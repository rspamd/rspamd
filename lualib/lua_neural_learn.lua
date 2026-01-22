--[[
Copyright (c) 2024, Vsevolod Stakhov <vsevolod@rspamd.com>

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

--[[
Neural network autolearn helpers.

This module provides configurable autolearn conditions for neural networks,
particularly useful for LLM-based providers where automatic learning needs
careful control.

Similar to lua_bayes_learn.lua, this provides:
- Guards system for pluggable checks
- Expression-based conditions (rspamd_expression)
- Score/action/symbol-based thresholds
- Hooks for custom logic via rspamd_plugins

Usage in neural.lua:
  local neural_learn = require "lua_neural_learn"
  local can_learn, reason = neural_learn.can_autolearn(task, rule, 'spam')
]]--

local lua_util = require "lua_util"
local rspamd_expression = require "rspamd_expression"
local rspamd_logger = require "rspamd_logger"

local N = "lua_neural_learn"

local exports = {}

-- Global defaults that can be overridden via configure()
local global_defaults = {}

-- Registered guards (callbacks that can block learning)
local autolearn_guards = {}

-- Cached compiled expressions per rule
local expression_cache = {}

-- Default autolearn settings
local default_autolearn_settings = {
  -- Master enable/disable
  enabled = false,

  -- Require minimum score magnitude for learning
  spam_score = nil,        -- e.g., 6.0 - learn spam if score >= 6.0
  ham_score = nil,         -- e.g., -2.0 - learn ham if score <= -2.0

  -- Require specific actions
  spam_action = nil,       -- e.g., 'reject' - only learn spam on reject
  ham_action = nil,        -- e.g., 'no action' - only learn ham on no action

  -- Expression-based conditions (rspamd_expression syntax)
  -- Examples:
  --   "BAYES_SPAM & !WHITELIST_SENDER"
  --   "DMARC_POLICY_REJECT | (RBL_SPAMHAUS_SBL & SURBL_MULTI)"
  spam_condition = nil,
  ham_condition = nil,

  -- Required symbols (all must be present)
  spam_symbols = nil,      -- e.g., {'BAYES_SPAM', 'DKIM_VALID'}
  ham_symbols = nil,

  -- Forbidden symbols (any blocks learning)
  skip_symbols = nil,      -- e.g., {'WHITELIST_SENDER', 'GREYLIST'}

  -- Minimum symbol weight sum
  spam_symbol_weight = nil, -- e.g., 5.0 - sum of spam_symbols scores >= 5.0
  ham_symbol_weight = nil,  -- e.g., -3.0 - sum of ham_symbols scores <= -3.0

  -- Probability-based check (skip if already confident)
  probability_check = {
    enabled = false,
    variable = 'neural_prob',  -- mempool variable name
    spam_min = 0.95,           -- skip if already 95% spam
    ham_max = 0.05,            -- skip if already 95% ham
  },

  -- Rate limiting
  rate_limit = {
    enabled = false,
    max_daily = 1000,          -- per class per day
    redis_prefix = 'neural_autolearn',
  },

  -- Sampling (probabilistic training reduction)
  sampling = {
    spam_prob = 1.0,           -- 1.0 = always, 0.5 = 50% chance
    ham_prob = 1.0,
  },

  -- Exclusion conditions (matching RBL module naming)
  exclude_local = false,       -- exclude local network messages from autolearn
  exclude_users = true,        -- exclude authenticated users from autolearn
}

-- Helper: convert array to set
local function as_set(tbl)
  if not tbl then
    return nil
  end
  local res = {}
  for _, v in ipairs(tbl) do
    res[v] = true
  end
  return res
end

-- Helper: merge options with defaults
local function merge_options(defaults, overrides)
  local merged = lua_util.override_defaults(defaults, global_defaults)
  if overrides then
    merged = lua_util.override_defaults(merged, overrides)
  end
  return merged
end

-- Guard execution
local function execute_guards(task, learn_type, ctx)
  for _, guard in ipairs(autolearn_guards) do
    local ok, reason = guard.cb(task, learn_type, ctx)
    if not ok then
      return false, reason or guard.name
    end
  end
  return true
end

--- Register a guard callback for autolearn decisions
-- @param name string guard name
-- @param cb function(task, learn_type, ctx) -> bool, reason
-- @param opts table optional {priority = number}
function exports.register_guard(name, cb, opts)
  if type(name) == 'function' then
    cb = name
    name = string.format('guard_%d', #autolearn_guards + 1)
  end

  if type(cb) ~= 'function' then
    rspamd_logger.errx(rspamd_config, '%s: guard callback must be a function', N)
    return nil
  end

  local guard = {
    name = name,
    cb = cb,
    priority = opts and opts.priority or 0,
  }

  autolearn_guards[#autolearn_guards + 1] = guard
  table.sort(autolearn_guards, function(a, b)
    return (a.priority or 0) > (b.priority or 0)
  end)

  lua_util.debugm(N, rspamd_config, 'registered autolearn guard: %s', name)
  return name
end

--- Unregister a guard by name
function exports.unregister_guard(name)
  for i = #autolearn_guards, 1, -1 do
    if autolearn_guards[i].name == name then
      table.remove(autolearn_guards, i)
      return true
    end
  end
  return false
end

--- Configure global defaults
-- @param opts table of default overrides
function exports.configure(opts)
  if opts then
    global_defaults = lua_util.override_defaults(global_defaults, opts)
    lua_util.debugm(N, rspamd_config, 'configured neural autolearn defaults')
  end
end

-- Compile and cache expression
local function get_expression(rule_name, expr_str, pool)
  local cache_key = rule_name .. ':' .. expr_str
  if expression_cache[cache_key] then
    return expression_cache[cache_key]
  end

  local function parse_atom(str)
    local atom = ''
    for c in str:gmatch('.') do
      if c:match('[%w_]') then
        atom = atom .. c
      else
        break
      end
    end
    return atom
  end

  local function process_atom(atom, task)
    if task:has_symbol(atom) then
      local sym = task:get_symbol(atom)
      if sym and sym[1] then
        local score = math.abs(sym[1].score or 0)
        return score > 0.001 and score or 0.001
      end
      return 0.001
    end
    return 0
  end

  local expr, err = rspamd_expression.create(expr_str, { parse_atom, process_atom }, pool)
  if err then
    rspamd_logger.errx(rspamd_config, '%s: cannot create expression [%s]: %s', N, expr_str, err)
    return nil
  end

  expression_cache[cache_key] = expr
  return expr
end

-- Check if all required symbols are present
local function check_required_symbols(task, symbols)
  if not symbols or #symbols == 0 then
    return true
  end
  for _, sym in ipairs(symbols) do
    if not task:has_symbol(sym) then
      return false, string.format('missing required symbol: %s', sym)
    end
  end
  return true
end

-- Check if any forbidden symbols are present
local function check_forbidden_symbols(task, symbols)
  if not symbols then
    return true
  end
  local skip_set = as_set(symbols)
  if not skip_set then
    return true
  end
  for sym, _ in pairs(skip_set) do
    if task:has_symbol(sym) then
      return false, string.format('has forbidden symbol: %s', sym)
    end
  end
  return true
end

-- Calculate sum of symbol scores
local function get_symbols_weight(task, symbols)
  if not symbols or #symbols == 0 then
    return 0
  end
  local total = 0
  for _, sym in ipairs(symbols) do
    local s = task:get_symbol(sym)
    if s and s[1] then
      total = total + (s[1].score or 0)
    end
  end
  return total
end

--- Main function: determine if a message should be autolearned
-- @param task rspamd_task
-- @param rule neural rule configuration
-- @param learn_type 'spam' or 'ham'
-- @param overrides optional per-call config overrides
-- @return bool can_learn, string reason
function exports.can_autolearn(task, rule, learn_type, overrides)
  local autolearn_opts = rule.autolearn or {}
  local opts = merge_options(default_autolearn_settings, autolearn_opts)

  if overrides then
    opts = merge_options(opts, overrides)
  end

  -- Master enable check
  if not opts.enabled then
    return false, 'autolearn disabled'
  end

  local score = task:get_metric_score()[1]
  local action = task:get_metric_action()

  local ctx = {
    task = task,
    rule = rule,
    learn_type = learn_type,
    score = score,
    action = action,
    options = opts,
  }

  -- Execute registered guards first
  local guard_ok, guard_reason = execute_guards(task, learn_type, ctx)
  if not guard_ok then
    return false, string.format('blocked by guard: %s', guard_reason)
  end

  -- Exclusion checks (matching RBL module naming)
  if opts.exclude_local and task:get_from_ip() and task:get_from_ip():is_local() then
    return false, 'local network message'
  end

  if opts.exclude_users and task:get_user() then
    return false, 'authenticated user'
  end

  -- Forbidden symbols check
  local skip_ok, skip_reason = check_forbidden_symbols(task, opts.skip_symbols)
  if not skip_ok then
    return false, skip_reason
  end

  -- Learn type specific checks
  if learn_type == 'spam' then
    -- Score threshold
    if opts.spam_score and score < opts.spam_score then
      return false, string.format('score %.2f < spam_score %.2f', score, opts.spam_score)
    end

    -- Action requirement
    if opts.spam_action and action ~= opts.spam_action then
      return false, string.format('action %s != required %s', action, opts.spam_action)
    end

    -- Required symbols
    local sym_ok, sym_reason = check_required_symbols(task, opts.spam_symbols)
    if not sym_ok then
      return false, sym_reason
    end

    -- Symbol weight threshold
    if opts.spam_symbol_weight then
      local weight = get_symbols_weight(task, opts.spam_symbols)
      if weight < opts.spam_symbol_weight then
        return false, string.format('spam symbol weight %.2f < %.2f', weight, opts.spam_symbol_weight)
      end
    end

    -- Expression condition
    if opts.spam_condition then
      local expr = get_expression(rule.prefix or 'default', opts.spam_condition, rspamd_config:get_mempool())
      if expr then
        local result = expr:process(task)
        if result <= 0 then
          return false, string.format('spam_condition not satisfied: %s', opts.spam_condition)
        end
      end
    end

  elseif learn_type == 'ham' then
    -- Score threshold
    if opts.ham_score and score > opts.ham_score then
      return false, string.format('score %.2f > ham_score %.2f', score, opts.ham_score)
    end

    -- Action requirement
    if opts.ham_action and action ~= opts.ham_action then
      return false, string.format('action %s != required %s', action, opts.ham_action)
    end

    -- Required symbols
    local sym_ok, sym_reason = check_required_symbols(task, opts.ham_symbols)
    if not sym_ok then
      return false, sym_reason
    end

    -- Symbol weight threshold
    if opts.ham_symbol_weight then
      local weight = get_symbols_weight(task, opts.ham_symbols)
      if weight > opts.ham_symbol_weight then
        return false, string.format('ham symbol weight %.2f > %.2f', weight, opts.ham_symbol_weight)
      end
    end

    -- Expression condition
    if opts.ham_condition then
      local expr = get_expression(rule.prefix or 'default', opts.ham_condition, rspamd_config:get_mempool())
      if expr then
        local result = expr:process(task)
        if result <= 0 then
          return false, string.format('ham_condition not satisfied: %s', opts.ham_condition)
        end
      end
    end
  end

  -- Probability check (skip if already confident)
  if opts.probability_check and opts.probability_check.enabled then
    local prob_var = opts.probability_check.variable or 'neural_prob'
    local prob = task:get_mempool():get_variable(prob_var, 'double')
    if prob then
      if learn_type == 'spam' and prob >= opts.probability_check.spam_min then
        return false, string.format('already confident spam: %.2f >= %.2f', prob, opts.probability_check.spam_min)
      elseif learn_type == 'ham' and prob <= opts.probability_check.ham_max then
        return false, string.format('already confident ham: %.2f <= %.2f', prob, opts.probability_check.ham_max)
      end
    end
  end

  -- Probabilistic sampling
  if opts.sampling then
    local sample_prob = learn_type == 'spam' and opts.sampling.spam_prob or opts.sampling.ham_prob
    if sample_prob and sample_prob < 1.0 then
      local coin = math.random()
      if coin > sample_prob then
        return false, string.format('sampled out: %.2f > %.2f', coin, sample_prob)
      end
    end
  end

  return true, nil
end

--- Determine learn type based on score/action/symbols
-- @param task rspamd_task
-- @param rule neural rule configuration
-- @return string learn_type ('spam', 'ham', or nil), string reason
function exports.get_learn_type(task, rule)
  local autolearn_opts = rule.autolearn or {}
  local opts = merge_options(default_autolearn_settings, autolearn_opts)

  if not opts.enabled then
    return nil, 'autolearn disabled'
  end

  -- Try spam first
  local spam_ok, spam_reason = exports.can_autolearn(task, rule, 'spam')
  if spam_ok then
    return 'spam', 'autolearn spam'
  end

  -- Try ham
  local ham_ok, ham_reason = exports.can_autolearn(task, rule, 'ham')
  if ham_ok then
    return 'ham', 'autolearn ham'
  end

  -- Neither qualifies
  return nil, spam_reason or ham_reason or 'no autolearn condition matched'
end

--- Set autolearn class in mempool (for integration with neural.lua)
-- @param task rspamd_task
-- @param learn_type 'spam' or 'ham'
function exports.set_autolearn_class(task, learn_type)
  task:get_mempool():set_variable('neural_autolearn_class', learn_type)
  lua_util.debugm(N, task, 'set neural autolearn class: %s', learn_type)
end

--- Get autolearn class from mempool
-- @param task rspamd_task
-- @return string learn_type or nil
function exports.get_autolearn_class(task)
  return task:get_mempool():get_variable('neural_autolearn_class')
end

--- Clear expression cache (useful for config reload)
function exports.clear_cache()
  expression_cache = {}
end

-- Register module in rspamd_plugins for user hooks
if rspamd_plugins then
  rspamd_plugins['neural_learn'] = {
    register_guard = exports.register_guard,
    unregister_guard = exports.unregister_guard,
    configure = exports.configure,
    can_autolearn = exports.can_autolearn,
    get_learn_type = exports.get_learn_type,
    set_autolearn_class = exports.set_autolearn_class,
    get_autolearn_class = exports.get_autolearn_class,
  }
end

return exports
