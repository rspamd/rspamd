--[[
Copyright (c) 2025, Vsevolod Stakhov <vsevolod@rspamd.com>

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

-- Lua shape validation library - JSON Schema exporter
-- Converts lua_shape schemas to JSON Schema format

local exports = {}

-- Convert a schema node to JSON Schema
local function to_jsonschema_impl(schema, opts)
  opts = opts or {}

  if not schema or not schema.tag then
    return {}
  end

  local result = {}
  local schema_opts = schema.opts or {}

  -- Add description from doc
  if schema_opts.doc and schema_opts.doc.summary then
    result.description = schema_opts.doc.summary
  end

  local tag = schema.tag

  -- Scalar types
  if tag == "scalar" then
    local kind = schema.kind

    if kind == "string" then
      result.type = "string"

      if schema_opts.min_len then
        result.minLength = schema_opts.min_len
      end
      if schema_opts.max_len then
        result.maxLength = schema_opts.max_len
      end
      if schema_opts.pattern then
        result.pattern = schema_opts.pattern
      end

    elseif kind == "number" or kind == "integer" then
      result.type = kind == "integer" and "integer" or "number"

      if schema_opts.min then
        result.minimum = schema_opts.min
      end
      if schema_opts.max then
        result.maximum = schema_opts.max
      end

    elseif kind == "boolean" then
      result.type = "boolean"

    elseif kind == "enum" then
      if schema_opts.enum then
        result.enum = schema_opts.enum
      end

    elseif kind == "literal" then
      result.const = schema_opts.literal
    end

  -- Array type
  elseif tag == "array" then
    result.type = "array"

    if schema.item_schema then
      result.items = to_jsonschema_impl(schema.item_schema, opts)
    end

    if schema_opts.min_items then
      result.minItems = schema_opts.min_items
    end
    if schema_opts.max_items then
      result.maxItems = schema_opts.max_items
    end

  -- Table type
  elseif tag == "table" then
    result.type = "object"
    result.properties = {}
    result.required = {}

    -- Process fields
    for field_name, field_spec in pairs(schema.fields or {}) do
      result.properties[field_name] = to_jsonschema_impl(field_spec.schema, opts)

      -- Add to required if not optional
      if not field_spec.optional then
        table.insert(result.required, field_name)
      end

      -- Add default if present
      if field_spec.default ~= nil then
        result.properties[field_name].default = field_spec.default
      end

      -- Add origin metadata if present (for mixin tracking)
      if field_spec.origin and opts.include_origin then
        result.properties[field_name]["x-rspamd-origin"] = field_spec.origin
      end
    end

    -- Handle open/closed table
    if schema_opts.open == false then
      if schema_opts.extra then
        -- Allow additional properties matching extra schema
        result.additionalProperties = to_jsonschema_impl(schema_opts.extra, opts)
      else
        result.additionalProperties = false
      end
    else
      result.additionalProperties = true
    end

    -- Remove empty required array
    if #result.required == 0 then
      result.required = nil
    end

  -- one_of type
  elseif tag == "one_of" then
    result.oneOf = {}

    for _, variant in ipairs(schema.variants or {}) do
      local variant_schema = to_jsonschema_impl(variant.schema, opts)

      -- Add title if variant has a name
      if variant.name and opts.include_variant_names then
        variant_schema.title = variant.name
      end

      table.insert(result.oneOf, variant_schema)
    end

  -- Optional wrapper
  elseif tag == "optional" then
    result = to_jsonschema_impl(schema.inner, opts)

    -- Add null as allowed type
    if result.type then
      if type(result.type) == "string" then
        result.type = { result.type, "null" }
      else
        table.insert(result.type, "null")
      end
    end

    if schema.default ~= nil then
      result.default = schema.default
    end

  -- Transform wrapper
  elseif tag == "transform" then
    -- For JSON Schema, just export the inner schema
    -- Transform semantics don't apply to JSON Schema validation
    result = to_jsonschema_impl(schema.inner, opts)

  -- Reference
  elseif tag == "ref" then
    local ref_id = schema.ref_id
    result["$ref"] = "#/definitions/" .. ref_id
  end

  return result
end

-- Convert a schema to JSON Schema
function exports.from_schema(schema, opts)
  opts = opts or {}

  local result = {
    ["$schema"] = "http://json-schema.org/draft-07/schema#"
  }

  -- Add schema ID if provided
  if opts.id then
    result["$id"] = opts.id
  end

  -- Add title if provided
  if opts.title then
    result.title = opts.title
  end

  -- Convert schema
  local schema_json = to_jsonschema_impl(schema, opts)
  for k, v in pairs(schema_json) do
    result[k] = v
  end

  return result
end

-- Export all schemas from a registry
function exports.export_registry(registry, opts)
  opts = opts or {}
  -- local base_id = opts.base_id or "https://rspamd.com/schema/"

  local result = {
    ["$schema"] = "http://json-schema.org/draft-07/schema#",
    definitions = {}
  }

  local schemas = registry:export_all()

  for id, schema in pairs(schemas) do
    result.definitions[id] = to_jsonschema_impl(schema, opts)
  end

  return result
end

return exports
