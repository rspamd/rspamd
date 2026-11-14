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

  local parser = ucl.parser()
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

return {
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
