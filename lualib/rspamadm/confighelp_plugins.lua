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

-- Convert plugin schemas to UCL format for confighelp

local function convert_schema(node)
  if not node then return {} end

  local res = {}
  if node.summary then res.data = node.summary end
  if node.description and not res.data then res.data = node.description end
  if node.examples and node.examples[1] then res.example = node.examples[1] end
  if node.default ~= nil then res.default = node.default end
  if node.optional ~= nil then res.required = not node.optional end

  if node.type == 'scalar' then
    res.type = node.kind or 'string'
  elseif node.type == 'table' then
    res.type = 'object'
  else
    res.type = node.type
  end

  if node.type == 'table' then
    local mixins = {}
    local mixin_field_names = {}
    for _, group in ipairs(node.mixin_groups or {}) do
      local entry = { name = group.mixin_name or group.schema_id, schema_id = group.schema_id }
      table.insert(mixins, entry)
      for _, mixin_field in ipairs(group.fields or {}) do
        mixin_field_names[mixin_field.name] = true
      end
    end
    if #mixins > 0 then res.mixins = mixins end

    for _, field in ipairs(node.fields or {}) do
      if not mixin_field_names[field.name] then
        local child = convert_schema(field.schema)
        child.required = not field.optional
        if field.schema and field.schema.summary and not child.data then
          child.data = field.schema.summary
        end
        res[field.name] = child
      end
    end

    if node.extra_schema then
      local extra_child = convert_schema(node.extra_schema)
      if not extra_child.data then extra_child.data = 'Entry schema' end
      res['entry'] = extra_child
    end

  elseif node.type == 'array' and node.item_schema then
    res.item = convert_schema(node.item_schema)

  elseif node.type == 'one_of' then
    local variants = {}
    local common_fields = {}
    local idx = 1

    -- Extract fields common to all variants
    local first_variant_fields = nil
    local all_have_common = true
    for _, variant in ipairs(node.variants or {}) do
      if variant.type == 'table' and variant.fields then
        local field_map = {}
        for _, field in ipairs(variant.fields) do
          field_map[field.name] = field
        end
        if first_variant_fields == nil then
          first_variant_fields = field_map
        else
          -- Check which fields are common
          for fname, _ in pairs(first_variant_fields) do
            if not field_map[fname] then
              first_variant_fields[fname] = nil
            end
          end
        end
      else
        all_have_common = false
      end
    end

    -- Convert common fields
    if first_variant_fields and all_have_common then
      for fname, field in pairs(first_variant_fields) do
        local child = convert_schema(field.schema)
        child.required = not field.optional
        if field.schema and field.schema.summary and not child.data then
          child.data = field.schema.summary
        end
        common_fields[fname] = true
        res[fname] = child
      end
    end

    -- Convert variants, excluding common fields
    for _, variant in ipairs(node.variants or {}) do
      local vname = variant.name or ('variant_' .. tostring(idx))
      local converted_variant = convert_schema(variant)

      -- Remove common fields from variant
      for fname, _ in pairs(common_fields) do
        converted_variant[fname] = nil
      end

      variants[vname] = converted_variant
      idx = idx + 1
    end
    res.options = variants
  end

  return res
end

return function()
  local Registry = require 'lua_shape.registry'
  local docs = require 'lua_shape.docs'
  local ucl = require 'ucl'

  local reg = Registry.global()
  if not reg then return nil end

  local exported = docs.for_registry(reg)
  if not exported or not exported.schemas then return nil end

  local converted = {}
  for id, schema in pairs(exported.schemas) do
    converted[id] = convert_schema(schema)
  end

  return ucl.to_format({ schemas = converted }, 'json-compact')
end
