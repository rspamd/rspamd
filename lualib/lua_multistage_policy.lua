--[[
Copyright (c) 2026, Vsevolod Stakhov <vsevolod@rspamd.com>
Licensed under the Apache License, Version 2.0.
]]--

local matchers = require 'lua_settings_match'
local lua_util = require 'lua_util'

local fields = {
  ip = 'ip',
  from = 'address',
  rcpt = 'address',
  user = 'string',
  helo = 'string',
  hostname = 'string',
  settings_id = 'string',
  authenticated = 'boolean',
}

local policy_fields = {
  name = true, symbol = true, action = true, reason = true, match = true, except = true,
}

local function compile_scope(cfg, scope)
  if scope == nil then
    return function() return true end
  end

  if type(scope) ~= 'table' or next(scope) == nil then
    return nil, 'a policy scope must be a nonempty object'
  end

  local checks = {}

  for name, values in pairs(scope) do
    local kind = fields[name]

    if not kind then
      return nil, 'unsupported DATA scope field: ' .. tostring(name)
    end

    if kind == 'boolean' then
      if type(values) ~= 'boolean' then
        return nil, name .. ' must be a boolean'
      end

      checks[name] = function(value) return value == values end
    else
      values = type(values) == 'table' and values or { values }

      if #values == 0 or #values > 256 then
        return nil, name .. ' must contain between 1 and 256 values'
      end

      for index in pairs(values) do
        if type(index) ~= 'number' or index < 1 or index > #values or index % 1 ~= 0 then
          return nil, name .. ' must be a dense array'
        end
      end

      local alternatives = {}

      for _, value in ipairs(values) do
        if type(value) ~= 'string' or #value == 0 or #value > 1024 or value:find('%z') then
          return nil, name .. ' must contain bounded strings'
        end

        -- A missing or still loading exemption map must never mean "no
        -- exemption". Map-backed identity scopes need a readiness contract.
        if value:sub(1, 4) == 'map:' then
          return nil, 'DATA identity scopes currently require literals, CIDRs or regexps'
        end

        local expected, check

        if kind == 'address' then
          expected = matchers.process_email_condition(cfg, value)
          check = matchers.check_addr_setting
        elseif kind == 'ip' then
          local parsed = {}
          matchers.process_ip_condition(cfg, value, parsed)
          expected = parsed[1]
          check = matchers.check_ip_setting
        else
          expected = matchers.process_string_condition(cfg, value)
          check = matchers.check_string_setting
        end

        if not expected then
          return nil, 'invalid ' .. name .. ' condition: ' .. value
        end

        alternatives[#alternatives + 1] = function(actual)
          return actual ~= nil and actual ~= false and check(expected, actual)
        end
      end

      checks[name] = function(value)
        for _, check in ipairs(alternatives) do
          if check(value) then
            return true
          end
        end

        return false
      end
    end
  end

  return function(context)
    for name, check in pairs(checks) do
      if not check(context[name]) then
        return false
      end
    end

    return true
  end
end

local function policy_names(value, known)
  if value == nil then
    return nil
  end

  if type(value) ~= 'table' then
    return nil, 'policy selection must be an array of policy names'
  end

  local result = {}

  for i, name in pairs(value) do
    if type(i) ~= 'number' or i < 1 or i > #value or i % 1 ~= 0 or
        type(name) ~= 'string' or not known[name] then
      return nil, 'unknown policy in DATA settings: ' .. tostring(name)
    end

    result[name] = true
  end

  return result
end

local function compile(cfg, options)
  local policies, names, settings = {}, {}, {}

  for i, policy in ipairs(options.policies or {}) do
    if type(policy) ~= 'table' or type(policy.name) ~= 'string' or #policy.name == 0 then
      return nil, 'DATA policies require a nonempty name'
    end

    for key in pairs(policy) do
      if not policy_fields[key] then
        return nil, policy.name .. ': unsupported DATA policy field: ' .. tostring(key)
      end
    end

    if names[policy.name] then
      return nil, 'duplicate DATA policy name: ' .. policy.name
    end

    local matches, err = compile_scope(cfg, policy.match)

    if not matches then
      return nil, policy.name .. ': ' .. err
    end

    local except

    if policy.except ~= nil then
      except, err = compile_scope(cfg, policy.except)

      if not except then
        return nil, policy.name .. ': ' .. err
      end
    end

    policies[i] = { name = policy.name, action = policy.action, matches = matches, except = except }
    names[policy.name] = true
  end

  if options.settings ~= nil and type(options.settings) ~= 'table' then
    return nil, 'multistage.settings must be an object of named settings'
  end

  for name, setting in pairs(options.settings or {}) do
    if type(name) ~= 'string' or #name == 0 or #name > 128 or type(setting) ~= 'table' or
        type(setting.apply) ~= 'table' then
      return nil, 'DATA settings require a name, a scope and an apply object'
    end

    for key in pairs(setting) do
      if key ~= 'match' and key ~= 'apply' and key ~= 'priority' then
        return nil, name .. ': unsupported DATA settings field: ' .. tostring(key)
      end
    end

    local matches, err = compile_scope(cfg, setting.match)

    if not matches then
      return nil, name .. ': ' .. err
    end

    local priority = setting.priority

    if priority == nil then
      priority = 0
    end

    if type(priority) ~= 'number' or priority ~= priority or math.abs(priority) == math.huge then
      return nil, name .. ': priority must be a finite number'
    end

    for key in pairs(setting.apply) do
      if key ~= 'policies_enabled' and key ~= 'policies_disabled' then
        return nil, name .. ': unsupported DATA setting: ' .. tostring(key)
      end
    end

    local enabled, enable_error = policy_names(setting.apply.policies_enabled, names)
    local disabled, disable_error = policy_names(setting.apply.policies_disabled, names)

    if enable_error or disable_error then
      return nil, name .. ': ' .. (enable_error or disable_error)
    end

    settings[#settings + 1] = { name = name, priority = priority, matches = matches,
      enabled = enabled, disabled = disabled }

    if #settings > 128 then
      return nil, 'at most 128 DATA settings are supported'
    end
  end

  table.sort(settings, function(a, b)
    return a.priority == b.priority and a.name < b.name or a.priority < b.priority
  end)

  return function(task, eligible)
    local recipients = task:get_recipients('smtp') or {}

    if #recipients == 0 or #recipients > 256 then
      return nil
    end

    local context = {
      ip = task:get_from_ip(),
      from = task:get_from('smtp'),
      user = task:get_user(),
      authenticated = task:get_user() ~= nil,
      helo = task:get_helo(),
      hostname = task:get_hostname(),
      settings_id = task:get_metadata_field('settings_id'),
    }
    local selected, recipient

    for _, rcpt in ipairs(recipients) do
      context.rcpt = { rcpt }
      local enabled = lua_util.shallowcopy(names)

      for _, setting in ipairs(settings) do
        if setting.matches(context) then
          if setting.enabled then
            enabled = lua_util.shallowcopy(setting.enabled)
          end

          for name in pairs(setting.disabled or {}) do
            enabled[name] = nil
          end
        end
      end

      for i, policy in ipairs(policies) do
        if eligible[i] and enabled[policy.name] and policy.matches(context) and
            not (policy.except and policy.except(context)) then
          if policy.action == 'reject' then
            return i, rcpt.addr
          end

          if not selected then
            selected, recipient = i, rcpt.addr
          end
        end
      end
    end

    return selected, recipient
  end
end

return {
  compile = compile,
}
