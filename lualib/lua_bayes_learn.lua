--[[
Copyright (c) 2022, Vsevolod Stakhov <vsevolod@rspamd.com>

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

-- This file contains functions to simplify bayes classifier auto-learning

local lua_util = require "lua_util"
local lua_verdict = require "lua_verdict"
local logger = require "rspamd_logger"
local N = "lua_bayes"

local exports = {}

local function as_set(tbl, case_sensitive)
  if not tbl then
    return nil
  end

  local res = {}

  for k, v in pairs(tbl) do
    if type(k) == 'number' then
      if type(v) == 'string' then
        res[case_sensitive and v or v:lower()] = true
      else
        res[v] = true
      end
    else
      if type(v) == 'boolean' then
        res[case_sensitive and k or k:lower()] = v
      else
        res[case_sensitive and k or k:lower()] = true
      end
    end
  end

  return res
end

local function merge_options(defaults, module_defaults, overrides)
  local merged = lua_util.override_defaults(defaults, module_defaults or {})

  if overrides then
    merged = lua_util.override_defaults(merged, overrides)
  end

  return merged
end

local function interpret_guard_result(res, reason, extra)
  local ok = res
  local msg = reason
  local meta = extra

  if type(res) == 'table' then
    ok = res.ok
    msg = res.reason or res.message or reason
    if res.meta then
      meta = res.meta
    else
      meta = res
    end

    if ok == nil then
      if res.allow ~= nil then
        ok = res.allow
      elseif res.block ~= nil then
        ok = not res.block
      end
    end

    if ok == nil then
      ok = true
    end

    if res.stop ~= nil then
      meta = meta or {}
      meta.stop = res.stop and true or nil
    end
  else
    if ok == nil then
      ok = true
    end
  end

  return ok, msg, meta
end

local function execute_guards(guards, ctx, default_reason)
  if not guards then
    return true
  end

  for _, guard in ipairs(guards) do
    local ok, msg, meta = interpret_guard_result(guard.cb(ctx), default_reason, nil)

    if not ok then
      if ctx.result then
        ctx.result.guard = guard.name
        ctx.result.reason = msg or default_reason
        if meta then
          ctx.result.meta = meta
        end
      end

      return false, msg, meta
    end

    if meta and meta.stop then
      return true, msg, meta
    end
  end

  return true
end

local function register_guard(registry, name, cb, opts)
  if type(name) == 'function' then
    cb = name
    name = nil
  end

  if type(cb) ~= 'function' then
    return nil, 'guard callback must be a function'
  end

  local guard = {
    name = name or string.format('guard_%d', (#registry) + 1),
    cb = cb,
    priority = opts and opts.priority or 0,
  }

  registry[#registry + 1] = guard
  table.sort(registry, function(a, b)
    return (a.priority or 0) > (b.priority or 0)
  end)

  return guard.name
end

local function unregister_guard(registry, name)
  for i = #registry, 1, -1 do
    if registry[i].name == name then
      table.remove(registry, i)
    end
  end
end

local can_learn_defaults = {}
local autolearn_defaults = {}

local can_learn_guards = {}
local autolearn_guards = {}

local default_can_learn_settings = {
  bypass_header = {
    enabled = true,
    header = 'Learn-Type',
    values = {'bulk'},
    behaviour = 'skip_probability',
    case_sensitive = false,
  },
  probability_check = {
    enabled = true,
    variable = 'bayes_prob',
    ctype = 'double',
    spam_min = 0.95,
    ham_max = 0.05,
    skip_for_unlearn = false,
    require_value = false,
  },
}

local default_autolearn_settings = {
  require_queue_id = true,
  check_local = true,
  check_authed = true,
  verdict_source = {
    name = 'bayes',
  },
  logging = {
    enabled = true,
  },
  thresholds = {
    spam = nil,
    ham = nil,
    junk = nil,
  },
  learn_verdict = false,
  balance = {
    enabled = false,
    min_balance = 0.9,
    spam_key = 'spam_learns',
    ham_key = 'ham_learns',
    value_type = 'int64',
  },
}

--- Allows global overrides for can_learn defaults (e.g. from config)
-- @param opts table of default overrides
exports.configure_can_learn = function(opts)
  if opts then
    can_learn_defaults = lua_util.override_defaults(can_learn_defaults, opts)
  end
end

--- Allows global overrides for autolearn defaults (e.g. from config)
-- @param opts table of default overrides
exports.configure_autolearn = function(opts)
  if opts then
    autolearn_defaults = lua_util.override_defaults(autolearn_defaults, opts)
  end
end

--- Register an extra guard for can_learn checks
-- @param name string or callback (name optional)
-- @param cb guard callback
-- @param opts optional table with priority
exports.register_can_learn_guard = function(name, cb, opts)
  return register_guard(can_learn_guards, name, cb, opts)
end

--- Remove a previously registered can_learn guard by name
exports.unregister_can_learn_guard = function(name)
  unregister_guard(can_learn_guards, name)
end

--- Register an extra guard for autolearn decisions
-- @param name string or callback (name optional)
-- @param cb guard callback
-- @param opts optional table with priority
exports.register_autolearn_guard = function(name, cb, opts)
  return register_guard(autolearn_guards, name, cb, opts)
end

--- Remove a previously registered autolearn guard by name
exports.unregister_autolearn_guard = function(name)
  unregister_guard(autolearn_guards, name)
end

local function format_probability_message(ctx, prob, cl)
  local pct = math.abs((prob - 0.5) * 200.0)

  return string.format('already in class %s; probability %.2f%%', cl, pct)
end

--- Determines if a message can be learned by Bayes
-- @param task rspamd_task
-- @param is_spam boolean indicates target class
-- @param is_unlearn boolean indicates unlearn operation
-- @param overrides optional per-call overrides
exports.can_learn = function(task, is_spam, is_unlearn, overrides)
  local opts = merge_options(default_can_learn_settings, can_learn_defaults, overrides)

  if opts.bypass_header and opts.bypass_header.values then
    opts.bypass_header._set = as_set(opts.bypass_header.values, opts.bypass_header.case_sensitive)
  end

  local ctx = {
    task = task,
    is_spam = is_spam,
    is_unlearn = is_unlearn,
    options = opts,
    state = {},
    result = {},
  }

  if overrides and overrides.guards then
    local ok, msg, meta = execute_guards(overrides.guards, ctx, 'blocked by can_learn guard')

    if not ok then
      return false, msg, ctx.result
    end

    if meta and meta.stop then
      return true, nil, ctx.result
    end
  end

  local ok, msg = execute_guards(can_learn_guards, ctx, 'blocked by can_learn guard')

  if not ok then
    return false, msg, ctx.result
  end

  local probability_opts = opts.probability_check
  local skip_probability = false

  if opts.bypass_header and opts.bypass_header.enabled ~= false then
    local header_name = opts.bypass_header.header or 'Learn-Type'
    local header_value = task:get_request_header(header_name)

    if header_value then
      header_value = tostring(header_value)
      if opts.bypass_header.case_sensitive ~= true then
        header_value = header_value:lower()
      end

      local matched
      if opts.bypass_header._set then
        matched = opts.bypass_header._set[header_value]
      else
        matched = false
      end

      if matched then
        if opts.bypass_header.behaviour == 'allow' then
          ctx.result.reason = 'bypass header matched'
          return true, nil, ctx.result
        elseif opts.bypass_header.behaviour == 'deny' then
          ctx.result.reason = opts.bypass_header.reason or 'bypass header denies learning'
          ctx.result.guard = 'bypass_header'
          return false, ctx.result.reason, ctx.result
        else
          skip_probability = true
        end
      end
    end
  end

  if ctx.state.skip_probability ~= nil then
    skip_probability = ctx.state.skip_probability
  end

  if probability_opts and probability_opts.enabled ~= false and not skip_probability then
    if is_unlearn and probability_opts.skip_for_unlearn then
      ctx.result.reason = 'probability check skipped for unlearn'
    else
      local prob

      if probability_opts.resolver and type(probability_opts.resolver) == 'function' then
        prob = probability_opts.resolver(ctx)
      else
        prob = task:get_mempool():get_variable(probability_opts.variable or 'bayes_prob',
            probability_opts.ctype or 'double')
      end

      ctx.result.probability = prob

      if prob == nil then
        if probability_opts.require_value then
          local reason = probability_opts.missing_reason or 'probability value is missing'
          ctx.result.guard = 'probability_check'
          ctx.result.reason = reason
          return false, reason, ctx.result
        end
      else
        local in_class
        local guard_msg

        if probability_opts.check and type(probability_opts.check) == 'function' then
          in_class, guard_msg = probability_opts.check(ctx, prob)
        else
          if is_spam then
            in_class = prob >= (probability_opts.spam_min or 0.95)
          else
            in_class = prob <= (probability_opts.ham_max or 0.05)
          end
        end

        if in_class then
          local cl = is_spam and 'spam' or 'ham'
          local reason

          if probability_opts.message_formatter and type(probability_opts.message_formatter) == 'function' then
            reason = probability_opts.message_formatter(ctx, prob, cl) or guard_msg
          end

          reason = reason or guard_msg or format_probability_message(ctx, prob, cl)

          ctx.result.guard = 'probability_check'
          ctx.result.reason = reason

          return false, reason, ctx.result
        end
      end
    end
  end

  ctx.result.guard = ctx.result.guard or 'can_learn'

  return true, nil, ctx.result
end

--- Decide if a message should be auto-learned and return class
-- @param task rspamd_task
-- @param conf classifier autolearn configuration
-- @param overrides optional per-call overrides
exports.autolearn = function(task, conf, overrides)
  local opts = merge_options(default_autolearn_settings, autolearn_defaults, overrides)
  opts = merge_options(opts, {}, conf)

  if opts.check_balance ~= nil then
    opts.balance = opts.balance or {}
    if opts.balance.enabled == nil then
      opts.balance.enabled = opts.check_balance and true or false
    end
  end

  if opts.min_balance ~= nil then
    opts.balance = opts.balance or {}
    if opts.balance.min_balance == nil then
      opts.balance.min_balance = opts.min_balance
    end
  end

  local external_options = opts.options
  if external_options ~= nil then
    opts.options = nil

    if type(external_options) == 'function' then
      local ok, res = pcall(external_options, task, opts)

      if ok and type(res) == 'table' then
        opts = merge_options(opts, {}, res)
      else
        lua_util.debugm(N, task, 'autolearn options callback failed: %s', res)
      end
    elseif type(external_options) == 'table' then
      opts = merge_options(opts, {}, external_options)
    else
      lua_util.debugm(N, task, 'autolearn options must be a table or function, got %s',
          type(external_options))
    end
  end

  local ctx = {
    task = task,
    conf = opts,
    state = {},
    result = {},
  }

  if overrides and overrides.guards then
    local ok, msg, meta = execute_guards(overrides.guards, ctx, 'blocked by autolearn guard')

    if not ok then
      return nil, msg, ctx.result
    end

    if meta and meta.stop then
      return ctx.result.decision, msg, ctx.result
    end
  end

  local ok, msg = execute_guards(autolearn_guards, ctx, 'blocked by autolearn guard')

  if not ok then
    return nil, msg, ctx.result
  end

  if opts.require_queue_id and not task:get_queue_id() then
    lua_util.debugm(N, task, 'no need to autolearn - queue id is missing')
    ctx.result.reason = 'queue id is missing'
    return nil, ctx.result.reason, ctx.result
  end

  local skip_conf = {opts.check_local, opts.check_authed}
  if lua_util.is_skip_local_or_authed(task, skip_conf) then
    lua_util.debugm(N, task, 'skip autolearn for local or authed network')
    ctx.result.reason = 'local or authed network'
    return nil, ctx.result.reason, ctx.result
  end

  local verdict_source = opts.verdict_source or {}
  local verdict, score

  if verdict_source.extractor and type(verdict_source.extractor) == 'function' then
    verdict, score = verdict_source.extractor(ctx)
  else
    verdict, score = lua_verdict.get_specific_verdict(verdict_source.name or 'bayes', task)
  end

  ctx.result.verdict = verdict
  ctx.result.score = score

  if verdict == 'passthrough' then
    lua_util.debugm(N, task, 'no need to autolearn - verdict: %s', verdict)
    ctx.result.reason = 'verdict passthrough'
    return nil, ctx.result.reason, ctx.result
  end

  local learn_spam, learn_ham = false, false

  local thresholds = opts.thresholds or {}
  thresholds.spam = thresholds.spam or opts.spam_threshold
  thresholds.ham = thresholds.ham or opts.ham_threshold
  thresholds.junk = thresholds.junk or opts.junk_threshold

  local log_opts = opts.logging or {}
  local function log_can_autolearn(verdict_name, score_value, threshold)
    if log_opts.enabled == false then
      return
    end

    local from = task:get_from('smtp')
    local mime_rcpts = 'undef'
    local mr = task:get_recipients('mime')
    if mr then
      local r_addrs = {}
      for _, r in ipairs(mr) do
        r_addrs[#r_addrs + 1] = r.addr
      end
      if #r_addrs > 0 then
        mime_rcpts = table.concat(r_addrs, ',')
      end
    end

    logger.info(task, 'id: %s, from: <%s>: can autolearn %s: score %s %s %s, mime_rcpts: <%s>',
        task:get_header('Message-Id') or '<undef>',
        from and from[1].addr or 'undef',
        verdict_name,
        string.format('%.2f', score_value or 0),
        verdict_name == 'ham' and '<=' or verdict_name == 'spam' and '>=' or '/',
        threshold,
        mime_rcpts)
  end

  if thresholds.spam and thresholds.ham then
    if verdict == 'spam' then
      if score and score >= thresholds.spam then
        log_can_autolearn(verdict, score, thresholds.spam)
        learn_spam = true
      end
    elseif verdict == 'junk' then
      if thresholds.junk and score and score >= thresholds.junk then
        log_can_autolearn(verdict, score, thresholds.junk)
        learn_spam = true
      end
    elseif verdict == 'ham' then
      if score and score <= thresholds.ham then
        log_can_autolearn(verdict, score, thresholds.ham)
        learn_ham = true
      end
    end
  elseif opts.learn_verdict then
    if verdict == 'spam' or verdict == 'junk' then
      learn_spam = true
    elseif verdict == 'ham' then
      learn_ham = true
    end
  elseif opts.evaluate and type(opts.evaluate) == 'function' then
    local decision = opts.evaluate(ctx)

    if decision == 'spam' then
      learn_spam = true
    elseif decision == 'ham' then
      learn_ham = true
    end
  end

  if opts.balance and opts.balance.enabled then
    local balance_opts = opts.balance
    local spam_learns = task:get_mempool():get_variable(balance_opts.spam_key or 'spam_learns', balance_opts.value_type or 'int64') or 0
    local ham_learns = task:get_mempool():get_variable(balance_opts.ham_key or 'ham_learns', balance_opts.value_type or 'int64') or 0

    local min_balance = balance_opts.min_balance or 0.9

    if spam_learns > 0 or ham_learns > 0 then
      local max_ratio = 1.0 / min_balance
      local spam_learns_ratio = spam_learns / (ham_learns + 1)
      if spam_learns_ratio > max_ratio and learn_spam then
        lua_util.debugm(N, task,
            'skip learning spam, balance is not satisfied: %s < %s; %s spam learns; %s ham learns',
            spam_learns_ratio, min_balance, spam_learns, ham_learns)
        learn_spam = false
        ctx.result.reason = 'spam balance check failed'
      end

      local ham_learns_ratio = ham_learns / (spam_learns + 1)
      if ham_learns_ratio > max_ratio and learn_ham then
        lua_util.debugm(N, task,
            'skip learning ham, balance is not satisfied: %s < %s; %s spam learns; %s ham learns',
            ham_learns_ratio, min_balance, spam_learns, ham_learns)
        learn_ham = false
        ctx.result.reason = 'ham balance check failed'
      end
    end
  end

  if learn_spam then
    ctx.result.decision = 'spam'
    return 'spam', nil, ctx.result
  elseif learn_ham then
    ctx.result.decision = 'ham'
    return 'ham', nil, ctx.result
  end

  return nil, ctx.result.reason, ctx.result
end

return exports