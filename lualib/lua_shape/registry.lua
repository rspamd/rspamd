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

-- Lua shape validation library - Registry module
-- Provides schema registration and reference resolution

local Registry = {}
Registry.__index = Registry

-- Simple utility functions
local function shallowcopy(t)
  local result = {}
  for k, v in pairs(t) do
    result[k] = v
  end
  return result
end

-- Global registry instance
local global_registry = nil

-- Create a new registry
local function new()
  return setmetatable({
    schemas = {},
    resolved_cache = {}
  }, Registry)
end

-- Get or create global registry
function Registry.global()
  if not global_registry then
    global_registry = new()
  end
  return global_registry
end

-- Define a schema with an ID
function Registry:define(id, schema)
  if self.schemas[id] then
    error("Schema already defined: " .. id)
  end

  -- Set schema_id in opts if not already set
  if not schema.opts then
    schema.opts = {}
  end
  if not schema.opts.schema_id then
    schema.opts.schema_id = id
  end

  -- Resolve mixins if this is a table schema
  local resolved = self:resolve_schema(schema)

  self.schemas[id] = {
    id = id,
    original = schema,
    resolved = resolved
  }

  return resolved
end

-- Get a schema by ID
function Registry:get(id)
  local entry = self.schemas[id]
  if not entry then
    return nil
  end
  return entry.resolved
end

-- Resolve references and mixins in a schema
function Registry:resolve_schema(schema)
  if not schema then
    return nil
  end

  local tag = schema.tag

  -- If already resolved, return from cache
  -- Use the schema table itself as key (works with weak tables)
  if self.resolved_cache[schema] then
    return self.resolved_cache[schema]
  end

  -- Handle reference nodes
  if tag == "ref" then
    local ref_id = schema.ref_id
    local target = self.schemas[ref_id]
    if not target then
      error("Unresolved reference: " .. ref_id)
    end
    return target.resolved
  end

  -- Handle table nodes with mixins
  if tag == "table" then
    local opts = schema.opts or {}
    local mixins = opts.mixins or {}

    if #mixins > 0 then
      -- Merge mixin fields into table
      local merged_fields = shallowcopy(schema.fields or {})

      for _, mixin_def in ipairs(mixins) do
        if mixin_def._is_mixin then
          local mixin_schema = mixin_def.schema

          -- Resolve mixin schema if it's a reference
          if mixin_schema.tag == "ref" then
            mixin_schema = self:resolve_schema(mixin_schema)
          end

          -- Extract fields from mixin
          if mixin_schema.tag == "table" then
            local mixin_fields = mixin_schema.fields or {}
            local mixin_name = mixin_def.as or mixin_schema.opts.doc and
                                                mixin_schema.opts.doc.summary or
                                                "unknown"

            for field_name, field_spec in pairs(mixin_fields) do
              if merged_fields[field_name] then
                -- Conflict: host field overrides mixin
                merged_fields[field_name] = merged_fields[field_name]  -- Keep host field
                -- TODO: Add warning/logging
              else
                -- Add field from mixin with origin tracking
                local field_copy = shallowcopy(field_spec)
                field_copy.origin = {
                  mixin_name = mixin_name,
                  schema_id = mixin_schema.opts.schema_id
                }
                merged_fields[field_name] = field_copy
              end
            end
          end
        end
      end

      -- Create new table schema with merged fields
      local resolved = shallowcopy(schema)
      resolved.fields = merged_fields
      self.resolved_cache[schema] = resolved
      return resolved
    end
  end

  -- Handle array nodes - resolve item schema
  if tag == "array" then
    local resolved_item = self:resolve_schema(schema.item_schema)
    if resolved_item ~= schema.item_schema then
      local resolved = shallowcopy(schema)
      resolved.item_schema = resolved_item
      self.resolved_cache[schema] = resolved
      return resolved
    end
  end

  -- Handle one_of nodes - resolve variant schemas
  if tag == "one_of" then
    local variants = schema.variants or {}
    local resolved_variants = {}
    local changed = false

    for i, variant in ipairs(variants) do
      local resolved_variant_schema = self:resolve_schema(variant.schema)
      if resolved_variant_schema ~= variant.schema then
        changed = true
      end
      resolved_variants[i] = {
        name = variant.name,
        schema = resolved_variant_schema
      }
    end

    if changed then
      local resolved = shallowcopy(schema)
      resolved.variants = resolved_variants
      self.resolved_cache[schema] = resolved
      return resolved
    end
  end

  -- Handle optional/transform wrappers - resolve inner schema
  if tag == "optional" or tag == "transform" then
    local resolved_inner = self:resolve_schema(schema.inner)
    if resolved_inner ~= schema.inner then
      local resolved = shallowcopy(schema)
      resolved.inner = resolved_inner
      self.resolved_cache[schema] = resolved
      return resolved
    end
  end

  -- No changes needed
  return schema
end

-- List all registered schema IDs
function Registry:list()
  local ids = {}
  for id, _ in pairs(self.schemas) do
    table.insert(ids, id)
  end
  table.sort(ids)
  return ids
end

-- Export all schemas (for documentation or JSON Schema generation)
function Registry:export_all()
  local result = {}
  for id, entry in pairs(self.schemas) do
    result[id] = entry.resolved
  end
  return result
end

return Registry
