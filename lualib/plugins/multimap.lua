--[[
Copyright (c) 2026, Vsevolod Stakhov <vsevolod@rspamd.com>
Licensed under the Apache License, Version 2.0.
]]--

local lua_selectors = require 'lua_selectors'
local lua_util = require 'lua_util'

local envelope_inputs = {
  connection = true,
  helo = true,
  sender = true,
  recipients = true,
}

local function addresses(task, kind)
  local values

  if kind == 'from' then
    values = task:get_from('smtp')
  else
    values = task:get_recipients('smtp')
  end

  local out = {}

  for _, value in ipairs(values or {}) do
    out[#out + 1] = { addr = value.addr, user = value.user or false,
      domain = value.domain or false, name = value.name or false }
  end

  return out
end

-- These rules only read envelope values and a synchronous native map. A
-- selector's prerequisites still control whether the scheduler can run it.
local function early_plan(cfg, rule)
  if rule.expression or rule.combined or rule.redis_key or type(rule.map_obj) ~= 'table' or
      rawget(rule.map_obj, '__external') or not rawget(rule.map_obj, 'get_data_digest') then
    return nil
  end

  local extract, inputs, dependencies
  dependencies = {}

  if rule.type == 'helo' then
    inputs = { 'helo' }
    extract = function(task) return task:get_helo() or false end
  elseif rule.type == 'ip' then
    inputs = { 'connection' }
    extract = function(task)
      local ip = task:get_from_ip()
      return ip and ip:is_valid() and ip:to_string() or false
    end
  elseif rule.type == 'hostname' then
    inputs = { 'connection' }
    extract = function(task) return task:get_hostname() or false end
  elseif rule.type == 'user' then
    inputs = { 'connection' }
    extract = function(task) return task:get_user() or false end
  elseif rule.type == 'asn' or rule.type == 'country' then
    inputs = { 'connection' }
    dependencies = { 'ASN_CHECK' }
    extract = function(task) return task:get_mempool():get_variable(rule.type) or false end
  elseif (rule.type == 'from' or rule.type == 'rcpt') and rule.extract_from == 'smtp' then
    inputs = { rule.type == 'from' and 'sender' or 'recipients' }
    extract = function(task) return addresses(task, rule.type) end
  elseif rule.type == 'selector' then
    inputs = lua_selectors.get_required_inputs(cfg, rule.selector_str)
    dependencies = lua_selectors.get_dependencies(cfg, rule.selector_str)
    extract = function(task) return rule.selector(task) or false end
  else
    return nil
  end

  for _, input in ipairs(inputs or { 'eom' }) do
    if not envelope_inputs[input] then
      return nil
    end
  end

  local function plan(task)
    return {
      value = extract(task),
      digest = rule.map_obj:get_data_digest() or false,
    }
  end

  return inputs, dependencies, plan
end

local function wrap_callback(cfg, rule, callback)
  local inputs, dependencies, plan = early_plan(cfg, rule)

  if not plan then
    return callback
  end

  local function run(task)
    if not task:is_checkpoint() then
      return callback(task)
    end

    local before = plan(task)
    callback(task)

    if before.digest and lua_util.table_cmp(before, plan(task)) then
      task:set_check_fact('map', before)
    end
  end

  local function replay(task, facts)
    -- Ordinary actions belong to the EOM policy layer. Run the matcher again
    -- there so that its pre-result and message callback are applied normally.
    return not rule.action and type(facts.map) == 'table' and facts.map.digest ~= false and
        lua_util.table_cmp(facts.map, plan(task))
  end

  return run, inputs, dependencies, replay
end

return {
  wrap_callback = wrap_callback,
}
