--[[
Copyright (c) 2026, Vsevolod Stakhov <vsevolod@rspamd.com>

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

-- Controller dynconf plugin: inspect and change dynamic module settings

local dynconf = require "lua_dynconf"
local ucl = require "ucl"
local rspamd_logger = require "rspamd_logger"

local function module_known(name)
  for _, m in ipairs(dynconf.modules()) do
    if m == name then
      return true
    end
  end
  return false
end

local function not_enabled(err)
  return type(err) == 'string' and err:find('not enabled', 1, true) ~= nil
end

local function handle_dump(_, conn, req_params)
  local module = req_params.module
  if module and module ~= '' and not module_known(module) then
    conn:send_error(404, 'unknown module')
    return
  end
  local opts = { redact = true }
  if module and module ~= '' then
    opts.module = module
  end
  conn:send_ucl({ success = true, data = dynconf.dump(opts) })
end

local function handle_schema(_, conn, req_params)
  local module = req_params.module
  if not module or module == '' then
    conn:send_error(400, 'missing module')
    return
  end
  if not module_known(module) then
    conn:send_error(404, 'unknown module')
    return
  end

  local info = dynconf.dump({ module = module, redact = true }).modules[module]
  if not info then
    conn:send_error(404, 'module has no schema')
    return
  end

  -- Modules that did not name a schema use the one the plugin published as `plugins.<name>`
  local schema_id = info.schema_id or ('plugins.' .. module)

  local ok, res = pcall(function()
    local registry = require("lua_shape.registry").global()
    local schema = registry:get(schema_id)
    if not schema then
      return nil
    end
    return require("lua_shape.jsonschema").from_schema(schema, { id = schema_id })
  end)
  if not ok then
    rspamd_logger.errx(rspamd_config, 'cannot export schema for %s: %s', module, res)
    conn:send_error(500, 'cannot export schema')
  elseif not res then
    conn:send_error(404, 'module has no schema')
  else
    conn:send_ucl({
      success = true,
      data = { schema = res, dynamic = info.dynamic },
    })
  end
end

-- Common tail of set/reset: `values` is nil for reset
local function do_write(task, conn, module, values)
  local ok, err = dynconf.set(module, values, { task = task }, function(serr)
    if serr then
      conn:send_error(500, tostring(serr))
    else
      conn:send_ucl({ success = true })
    end
  end)
  if not ok then
    if not_enabled(err) then
      conn:send_error(503, tostring(err))
    elseif type(err) == 'string' and err:find('does not support', 1, true) then
      conn:send_error(503, err)
    else
      conn:send_error(400, tostring(err))
    end
  end
end

local function check_module(conn, req_params)
  local module = req_params.module
  if not module or module == '' then
    conn:send_error(400, 'missing module')
    return nil
  end
  if not module_known(module) then
    conn:send_error(404, 'unknown module')
    return nil
  end
  return module
end

local function handle_set(task, conn, req_params)
  local module = check_module(conn, req_params)
  if not module then
    return
  end

  local parser = ucl.untrusted_parser()
  local ok, err = parser:parse_text(task:get_rawbody())
  if not ok then
    conn:send_error(400, err)
    return
  end
  local values = parser:get_object()
  if type(values) ~= 'table' then
    conn:send_error(400, 'override must be a JSON object')
    return
  end

  do_write(task, conn, module, values)
end

local function handle_reset(task, conn, req_params)
  local module = check_module(conn, req_params)
  if not module then
    return
  end
  do_write(task, conn, module, nil)
end

local function handle_reload(task, conn)
  local replied = false
  local started = dynconf.check_now(nil, function(cerr, applied)
    if replied then
      return
    end
    replied = true
    if cerr then
      if not_enabled(cerr) then
        conn:send_error(503, tostring(cerr))
      else
        conn:send_error(500, tostring(cerr))
      end
    else
      conn:send_ucl({ success = true, applied = applied })
    end
  end)
  if not started and not replied then
    -- check_now reports refusals through the callback; this is only a safety net
    replied = true
    conn:send_error(503, 'cannot start check')
  end
  rspamd_logger.debugx(task, 'dynconf reload requested')
end

-- The legacy WebUI endpoints /saveactions and /savesymbols ----------------------------------------
-- The controller routes them here (see src/controller.c): the request and the reply formats are the
-- ones the legacy dynamic configuration had, the thresholds and the scores are stored as the `actions`
-- and `scores` modules of dynconf.

local ACTION_NAMES = { 'reject', 'rewrite subject', 'add header', 'greylist' }
-- The subscriber accepts these spellings too, so an override can hold them (written by hand, or through
-- /plugins/dynconf/set). A change of the action has to take them out, or the override would name it twice
local ACTION_ALIASES = { ['rewrite subject'] = 'rewrite_subject', ['add header'] = 'add_header' }
local EPSILON = 1e-9

local function same_number(a, b)
  return math.abs(a - b) < EPSILON
end

-- The body of a legacy request: a JSON array, or nil after the error has been sent
local function parse_legacy_body(task, conn)
  -- The body comes from a client: the parser applies limits to its depth and size
  local parser = ucl.untrusted_parser()
  local ok, err = parser:parse_text(task:get_rawbody())
  if not ok then
    rspamd_logger.errx(task, 'cannot parse input: %s', err)
    conn:send_error(400, 'Cannot parse input')
    return nil
  end
  local obj = parser:get_object()
  if type(obj) ~= 'table' or #obj == 0 then
    rspamd_logger.errx(task, 'input is not an array')
    conn:send_error(400, 'Cannot parse input')
    return nil
  end
  return obj
end

local function client_name(task)
  local ip = task:get_client_ip()
  return ip and tostring(ip) or 'unknown'
end

-- Stores the changes of the override of a module and replies; `reject_error` is the reply for a refusal
-- (the legacy status and text, the reason that the subscriber gives is added to the text: a name that
-- does not exist, or a value that cannot be changed because a higher priority definition, `override.d`,
-- holds it)
local function save_patch(task, conn, module, patch, what, count, reject_error)
  local function reject(reason)
    local text = reject_error[2]
    if reason then
      text = string.format('%s: %s', text, reason)
    end
    conn:send_error(reject_error[1], text)
  end

  local ok, err = dynconf.update(module, patch, { task = task }, function(serr, rejected)
    if serr then
      rspamd_logger.errx(task, 'cannot save %s: %s', what, serr)
      if rejected then
        reject(tostring(serr))
      else
        conn:send_error(500, 'Save error')
      end
    else
      rspamd_logger.infox(task, '<%s> modified %s %s', client_name(task), count, what)
      conn:send_ucl({ success = true })
    end
  end)
  if not ok then
    rspamd_logger.errx(task, 'cannot save %s: %s', what, err)
    if not_enabled(err) then
      conn:send_error(503, 'Dynamic configuration is disabled')
    else
      reject(tostring(err))
    end
  end
end

-- The names of the override that the module holds now (the ones that a null of the request removes)
local function stored_names(module)
  return dynconf.override(module) or {}
end

-- body: [<reject>, <rewrite subject>, <add header>, <greylist>], a number or null for each
local function handle_saveactions(task, conn)
  local body = parse_legacy_body(task, conn)
  if not body then
    return
  end
  if #body ~= #ACTION_NAMES then
    rspamd_logger.errx(task, 'input is not an array of %s elements', #ACTION_NAMES)
    conn:send_error(400, 'Cannot parse input')
    return
  end

  local stored = stored_names('actions')
  local patch = {}
  local changed = 0
  for i, name in ipairs(ACTION_NAMES) do
    local value = body[i]
    if value ~= nil and type(value) ~= 'number' and value ~= ucl.null then
      conn:send_error(400, 'Cannot parse input')
      return
    end
    if value == ucl.null then
      value = nil
    end

    local base = rspamd_config:dynconf_baseline('actions', name)
    local has_override = stored[name] ~= nil or stored[ACTION_ALIASES[name] or name] ~= nil
    if value == nil then
      -- null has one meaning: the action goes back to its static threshold (or to none), whether the
      -- configuration has a threshold for it or not
      if has_override then
        patch[name] = false
        changed = changed + 1
      end
    elseif base ~= nil and same_number(value, base) then
      if has_override then
        patch[name] = false
        changed = changed + 1
      end
    else
      patch[name] = value
      changed = changed + 1
    end
  end

  if next(patch) == nil then
    conn:send_ucl({ success = true })
    return
  end
  for name, alias in pairs(ACTION_ALIASES) do
    if patch[name] ~= nil then
      patch[alias] = false
    end
  end
  save_patch(task, conn, 'actions', patch, 'actions', changed, { 500, 'Save error' })
end

-- body: [{"name": <symbol>, "value": <score>}, ...]
local function handle_savesymbols(task, conn)
  local body = parse_legacy_body(task, conn)
  if not body then
    return
  end

  local stored = stored_names('scores')
  local patch = {}
  local changed = 0
  for _, elt in ipairs(body) do
    -- The WebUI sends null for a score field that has been cleared
    local value
    if type(elt) == 'table' then
      value = elt.value
      -- A missing value is a malformed element, a null one is a cleared field
      if value == ucl.null then
        value = false
      end
    end
    if value == nil or type(elt.name) ~= 'string' or (value ~= false and type(value) ~= 'number') then
      rspamd_logger.errx(task, 'json array data error')
      conn:send_error(400, 'Cannot parse input')
      return
    end

    local base = rspamd_config:dynconf_baseline('scores', elt.name)
    local has_override = stored[elt.name] ~= nil
    if value == false or (base ~= nil and same_number(value, base)) then
      -- No value, or the static one: the score goes back to the static one. It is removed from the
      -- override whether the symbol is known now or not (a stale entry can be cleaned this way)
      if has_override then
        patch[elt.name] = false
        changed = changed + 1
      end
    else
      -- An unknown symbol, or one that cannot be changed, is refused by the subscriber
      patch[elt.name] = value
      changed = changed + 1
    end
  end

  if changed == 0 then
    rspamd_logger.errx(task, 'no symbols to save')
    conn:send_error(404, 'No symbols to save')
    return
  end
  save_patch(task, conn, 'scores', patch, 'symbols', changed, { 506, 'Add symbol failed' })
end

return {
  saveactions = {
    handler = handle_saveactions,
    enable = true,
    need_task = true,
  },
  savesymbols = {
    handler = handle_savesymbols,
    enable = true,
    need_task = true,
  },
  dump = {
    handler = handle_dump,
    enable = false,
  },
  schema = {
    handler = handle_schema,
    enable = false,
  },
  set = {
    handler = handle_set,
    enable = true,
    need_task = true,
  },
  -- These two do not read the body: with need_task the controller would refuse a POST without one
  reset = {
    handler = handle_reset,
    enable = true,
    need_task = false,
  },
  reload = {
    handler = handle_reload,
    enable = true,
    need_task = false,
  },
}
