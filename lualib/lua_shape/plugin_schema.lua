local Registry = require "lua_shape.registry"

local M = {}
local global_registry = Registry.global()

function M.register(id, schema)
  if not id or not schema then
    error("plugin_schema.register requires id and schema")
  end

  if not global_registry:get(id) then
    global_registry:define(id, schema)
  end

  return global_registry:get(id)
end

return M
