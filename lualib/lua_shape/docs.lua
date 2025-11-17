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

-- Lua shape validation library - Documentation IR generator
-- Generates structured documentation from schemas

local exports = {}

-- Extract documentation from opts
local function get_doc(opts)
  if not opts or not opts.doc then
    return {}
  end
  return opts.doc
end

-- Generate doc IR for a schema node
local function generate_doc_impl(schema, path)
  path = path or "(root)"

  if not schema or not schema.tag then
    return {
      type = "unknown",
      path = path
    }
  end

  local doc = get_doc(schema.opts)
  local result = {
    type = schema.tag,
    path = path,
    summary = doc.summary,
    description = doc.description,
    examples = doc.examples
  }

  local tag = schema.tag

  -- Scalar types
  if tag == "scalar" then
    result.kind = schema.kind
    result.constraints = {}

    local opts = schema.opts or {}

    if schema.kind == "string" then
      if opts.min_len then result.constraints.min_length = opts.min_len end
      if opts.max_len then result.constraints.max_length = opts.max_len end
      if opts.pattern then result.constraints.pattern = opts.pattern end

    elseif schema.kind == "number" or schema.kind == "integer" then
      if opts.min then result.constraints.minimum = opts.min end
      if opts.max then result.constraints.maximum = opts.max end
      if opts.integer then result.constraints.integer = true end

    elseif schema.kind == "enum" then
      if opts.enum then result.constraints.values = opts.enum end

    elseif schema.kind == "literal" then
      result.constraints.value = opts.literal
    end

  -- Array type
  elseif tag == "array" then
    result.item_schema = generate_doc_impl(schema.item_schema, path .. "[]")

    local opts = schema.opts or {}
    result.constraints = {}
    if opts.min_items then result.constraints.min_items = opts.min_items end
    if opts.max_items then result.constraints.max_items = opts.max_items end

  -- Table type
  elseif tag == "table" then
    result.fields = {}
    result.mixin_groups = {}

    local opts = schema.opts or {}
    result.open = opts.open ~= false
    result.extra_schema = opts.extra and generate_doc_impl(opts.extra, path .. ".*") or nil

    -- Group fields by origin (mixins)
    local origin_groups = {}
    local no_origin_fields = {}

    for field_name, field_spec in pairs(schema.fields or {}) do
      local field_doc = {
        name = field_name,
        optional = field_spec.optional or false,
        default = field_spec.default,
        schema = generate_doc_impl(field_spec.schema, path .. "." .. field_name)
      }

      if field_spec.origin then
        local origin_key = field_spec.origin.mixin_name or "unknown"
        if not origin_groups[origin_key] then
          origin_groups[origin_key] = {
            mixin_name = field_spec.origin.mixin_name,
            schema_id = field_spec.origin.schema_id,
            fields = {}
          }
        end
        table.insert(origin_groups[origin_key].fields, field_doc)
      else
        table.insert(no_origin_fields, field_doc)
      end
    end

    -- Add direct fields first
    result.fields = no_origin_fields

    -- Add mixin groups
    for _, group in pairs(origin_groups) do
      table.insert(result.mixin_groups, group)
    end

  -- one_of type
  elseif tag == "one_of" then
    result.variants = {}

    for i, variant in ipairs(schema.variants or {}) do
      local variant_doc = generate_doc_impl(variant.schema, path .. "::variant" .. i)
      variant_doc.name = variant.name or ("variant_" .. i)
      table.insert(result.variants, variant_doc)
    end

  -- Optional wrapper
  elseif tag == "optional" then
    result = generate_doc_impl(schema.inner, path)
    result.optional = true
    if schema.default ~= nil then
      result.default = schema.default
    end

  -- Transform wrapper
  elseif tag == "transform" then
    result = generate_doc_impl(schema.inner, path)
    result.has_transform = true

  -- Reference
  elseif tag == "ref" then
    result.ref_id = schema.ref_id
  end

  return result
end

-- Generate documentation IR for a schema
function exports.for_schema(schema, opts)
  opts = opts or {}

  local doc_tree = generate_doc_impl(schema, opts.root_path or "(root)")

  return {
    schema_doc = doc_tree,
    metadata = {
      generated_at = os.date("%Y-%m-%d %H:%M:%S"),
      generator = "rspamd_schema v1.0"
    }
  }
end

-- Generate documentation for all schemas in a registry
function exports.for_registry(registry, opts)
  opts = opts or {}

  local schemas = registry:export_all()
  local result = {
    schemas = {},
    metadata = {
      generated_at = os.date("%Y-%m-%d %H:%M:%S"),
      generator = "rspamd_schema v1.0"
    }
  }

  for id, schema in pairs(schemas) do
    result.schemas[id] = generate_doc_impl(schema, id)
  end

  return result
end

-- Simple markdown renderer (optional helper)
function exports.render_markdown(doc_tree, indent)
  indent = indent or 0
  local lines = {}
  local prefix = string.rep("  ", indent)

  if doc_tree.summary then
    table.insert(lines, prefix .. "**" .. doc_tree.summary .. "**")
  end

  if doc_tree.description then
    table.insert(lines, prefix .. doc_tree.description)
  end

  if doc_tree.type == "scalar" then
    local type_str = doc_tree.kind or "unknown"
    local constraint_strs = {}

    for k, v in pairs(doc_tree.constraints or {}) do
      table.insert(constraint_strs, k .. "=" .. tostring(v))
    end

    if #constraint_strs > 0 then
      type_str = type_str .. " (" .. table.concat(constraint_strs, ", ") .. ")"
    end

    table.insert(lines, prefix .. "Type: `" .. type_str .. "`")

  elseif doc_tree.type == "array" then
    table.insert(lines, prefix .. "Type: `array`")
    table.insert(lines, prefix .. "Items:")
    local item_lines = exports.render_markdown(doc_tree.item_schema, indent + 1)
    for _, line in ipairs(item_lines) do
      table.insert(lines, line)
    end

  elseif doc_tree.type == "table" then
    table.insert(lines, prefix .. "Type: `table`")

    if #doc_tree.fields > 0 then
      table.insert(lines, prefix .. "Fields:")
      for _, field in ipairs(doc_tree.fields) do
        local opt_str = field.optional and " (optional)" or " (required)"
        if field.default ~= nil then
          opt_str = opt_str .. ", default: " .. tostring(field.default)
        end
        table.insert(lines, prefix .. "  - **" .. field.name .. "**" .. opt_str)
        local field_lines = exports.render_markdown(field.schema, indent + 2)
        for _, line in ipairs(field_lines) do
          table.insert(lines, line)
        end
      end
    end

    if #doc_tree.mixin_groups > 0 then
      table.insert(lines, prefix .. "Mixins:")
      for _, group in ipairs(doc_tree.mixin_groups) do
        table.insert(lines, prefix .. "  - **" .. (group.mixin_name or "unknown") .. "**")
        for _, field in ipairs(group.fields) do
          local opt_str = field.optional and " (optional)" or " (required)"
          table.insert(lines, prefix .. "    - **" .. field.name .. "**" .. opt_str)
        end
      end
    end

  elseif doc_tree.type == "one_of" then
    table.insert(lines, prefix .. "Type: `one_of` (must match exactly one alternative)")
    table.insert(lines, prefix .. "Alternatives:")
    for _, variant in ipairs(doc_tree.variants or {}) do
      table.insert(lines, prefix .. "  - **" .. variant.name .. "**")
      local variant_lines = exports.render_markdown(variant, indent + 2)
      for _, line in ipairs(variant_lines) do
        table.insert(lines, line)
      end
    end
  end

  if doc_tree.examples then
    table.insert(lines, prefix .. "Examples:")
    for _, example in ipairs(doc_tree.examples) do
      table.insert(lines, prefix .. "  - `" .. tostring(example) .. "`")
    end
  end

  return lines
end

return exports
