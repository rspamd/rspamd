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

-- Lua shape validation library - Core module
-- Provides type constructors and validation logic

local T = {}

-- Simple utility functions
local function shallowcopy(t)
  local result = {}
  for k, v in pairs(t) do
    result[k] = v
  end
  return result
end

-- Check if table is array-like
local function is_array(t)
  if type(t) ~= "table" then
    return false
  end
  local count = 0
  for k, _ in pairs(t) do
    count = count + 1
    if type(k) ~= "number" or k < 1 or k ~= math.floor(k) or k > count then
      return false
    end
  end
  return count == #t
end

-- Error tree node constructor
local function make_error(kind, path, details)
  return {
    kind = kind,
    path = table.concat(path or {}, "."),
    details = details or {}
  }
end

-- Context for validation
local function make_context(mode, path)
  return {
    mode = mode or "check",
    path = path or {}
  }
end

-- Clone path for nested validation
local function clone_path(path)
  local result = {}
  for i, v in ipairs(path) do
    result[i] = v
  end
  return result
end

-- Forward declare schema_mt
local schema_mt

-- Schema node methods
local schema_methods = {
  -- Check if value matches schema
  check = function(self, value, ctx)
    ctx = ctx or make_context("check")
    return self._check(self, value, ctx)
  end,

  -- Transform value according to schema
  transform = function(self, value, ctx)
    ctx = ctx or make_context("transform")
    return self._check(self, value, ctx)
  end,

  -- Make schema optional
  optional = function(self, opts)
    opts = opts or {}
    return T.optional(self, opts)
  end,

  -- Add default value
  with_default = function(self, value)
    return T.default(self, value)
  end,

  -- Add documentation
  doc = function(self, doc_table)
    local new_opts = shallowcopy(self.opts or {})
    new_opts.doc = doc_table
    local result = shallowcopy(self)
    result.opts = new_opts
    return setmetatable(result, schema_mt)
  end,

  -- Transform with function
  transform_with = function(self, fn, opts)
    return T.transform(self, fn, opts)
  end
}

-- Schema node metatable
schema_mt = {
  __index = schema_methods
}

-- Create a new schema node
local function make_node(tag, data)
  local node = shallowcopy(data)
  node.tag = tag
  node.opts = node.opts or {}
  return setmetatable(node, schema_mt)
end

-- Scalar type validators

local function check_string(node, value, ctx)
  if type(value) ~= "string" then
    return false, make_error("type_mismatch", ctx.path, {
      expected = "string",
      got = type(value)
    })
  end

  local opts = node.opts or {}

  -- Length constraints
  if opts.min_len and #value < opts.min_len then
    return false, make_error("constraint_violation", ctx.path, {
      constraint = "min_len",
      expected = opts.min_len,
      got = #value
    })
  end

  if opts.max_len and #value > opts.max_len then
    return false, make_error("constraint_violation", ctx.path, {
      constraint = "max_len",
      expected = opts.max_len,
      got = #value
    })
  end

  -- Pattern matching
  if opts.pattern then
    if not string.match(value, opts.pattern) then
      return false, make_error("constraint_violation", ctx.path, {
        constraint = "pattern",
        pattern = opts.pattern
      })
    end
  end

  -- lpeg pattern (optional)
  if opts.lpeg then
    local lpeg = require "lpeg"
    if not lpeg.match(opts.lpeg, value) then
      return false, make_error("constraint_violation", ctx.path, {
        constraint = "lpeg_pattern"
      })
    end
  end

  return true, value
end

local function check_number(node, value, ctx)
  local num = tonumber(value)
  if not num then
    return false, make_error("type_mismatch", ctx.path, {
      expected = "number",
      got = type(value)
    })
  end

  local opts = node.opts or {}

  -- Integer constraint
  if opts.integer and num ~= math.floor(num) then
    return false, make_error("constraint_violation", ctx.path, {
      constraint = "integer",
      got = num
    })
  end

  -- Range constraints
  if opts.min and num < opts.min then
    return false, make_error("constraint_violation", ctx.path, {
      constraint = "min",
      expected = opts.min,
      got = num
    })
  end

  if opts.max and num > opts.max then
    return false, make_error("constraint_violation", ctx.path, {
      constraint = "max",
      expected = opts.max,
      got = num
    })
  end

  return true, num
end

local function check_boolean(node, value, ctx)
  if type(value) ~= "boolean" then
    return false, make_error("type_mismatch", ctx.path, {
      expected = "boolean",
      got = type(value)
    })
  end

  return true, value
end

local function check_enum(node, value, ctx)
  local opts = node.opts or {}
  local values = opts.enum or {}

  for _, v in ipairs(values) do
    if v == value then
      return true, value
    end
  end

  return false, make_error("enum_mismatch", ctx.path, {
    expected = values,
    got = value
  })
end

local function check_literal(node, value, ctx)
  local opts = node.opts or {}
  local expected = opts.literal

  if value ~= expected then
    return false, make_error("literal_mismatch", ctx.path, {
      expected = expected,
      got = value
    })
  end

  return true, value
end

-- Scalar type constructors

function T.string(opts)
  return make_node("scalar", {
    kind = "string",
    opts = opts or {},
    _check = check_string
  })
end

function T.number(opts)
  return make_node("scalar", {
    kind = "number",
    opts = opts or {},
    _check = check_number
  })
end

function T.integer(opts)
  opts = opts or {}
  opts.integer = true
  return make_node("scalar", {
    kind = "integer",
    opts = opts,
    _check = check_number
  })
end

function T.boolean(opts)
  return make_node("scalar", {
    kind = "boolean",
    opts = opts or {},
    _check = check_boolean
  })
end

local function check_callable(node, value, ctx)
  if type(value) ~= "function" then
    return false, make_error("type_mismatch", ctx.path, {
      expected = "function",
      got = type(value)
    })
  end

  return true, value
end

function T.callable(opts)
  return make_node("scalar", {
    kind = "callable",
    opts = opts or {},
    _check = check_callable
  })
end

function T.enum(values, opts)
  opts = opts or {}
  opts.enum = values
  return make_node("scalar", {
    kind = "enum",
    opts = opts,
    _check = check_enum
  })
end

function T.literal(value, opts)
  opts = opts or {}
  opts.literal = value
  return make_node("scalar", {
    kind = "literal",
    opts = opts,
    _check = check_literal
  })
end

-- Array type

local function check_array(node, value, ctx)
  if type(value) ~= "table" then
    return false, make_error("type_mismatch", ctx.path, {
      expected = "array",
      got = type(value)
    })
  end

  -- Check if it's array-like (no string keys, sequential numeric keys)
  if not is_array(value) then
    return false, make_error("type_mismatch", ctx.path, {
      expected = "array",
      got = "table with non-array keys"
    })
  end

  local opts = node.opts or {}
  local item_schema = node.item_schema
  local len = #value

  -- Length constraints
  if opts.min_items and len < opts.min_items then
    return false, make_error("constraint_violation", ctx.path, {
      constraint = "min_items",
      expected = opts.min_items,
      got = len
    })
  end

  if opts.max_items and len > opts.max_items then
    return false, make_error("constraint_violation", ctx.path, {
      constraint = "max_items",
      expected = opts.max_items,
      got = len
    })
  end

  -- Check each item
  local result = {}
  local errors = {}
  local has_errors = false

  for i, item in ipairs(value) do
    local item_ctx = make_context(ctx.mode, clone_path(ctx.path))
    table.insert(item_ctx.path, "[" .. i .. "]")

    local ok, val_or_err = item_schema:_check(item, item_ctx)
    if ok then
      result[i] = val_or_err
    else
      has_errors = true
      errors[i] = val_or_err
    end
  end

  if has_errors then
    return false, make_error("array_items_invalid", ctx.path, {
      errors = errors
    })
  end

  return true, result
end

function T.array(item_schema, opts)
  return make_node("array", {
    item_schema = item_schema,
    opts = opts or {},
    _check = check_array
  })
end

-- Table type

local function check_table(node, value, ctx)
  if type(value) ~= "table" then
    return false, make_error("type_mismatch", ctx.path, {
      expected = "table",
      got = type(value)
    })
  end

  local opts = node.opts or {}
  local fields = node.fields or {}
  local result = {}
  local errors = {}
  local has_errors = false

  -- Check declared fields
  for field_name, field_spec in pairs(fields) do
    local field_value = value[field_name]
    local field_ctx = make_context(ctx.mode, clone_path(ctx.path))
    table.insert(field_ctx.path, field_name)

    if field_value == nil then
      -- Missing field
      if field_spec.optional then
        -- Apply default in transform mode
        if ctx.mode == "transform" and field_spec.default ~= nil then
          local default_val = field_spec.default
          -- Support callable defaults: if default is a function, call it
          if type(default_val) == "function" then
            default_val = default_val()
          end
          result[field_name] = default_val
        end
      else
        has_errors = true
        errors[field_name] = make_error("required_field_missing", field_ctx.path, {
          field = field_name
        })
      end
    else
      -- Validate field
      local ok, val_or_err = field_spec.schema:_check(field_value, field_ctx)
      if ok then
        result[field_name] = val_or_err
      else
        has_errors = true
        errors[field_name] = val_or_err
      end
    end
  end

  -- Check for unknown fields
  if not opts.open then
    for key, val in pairs(value) do
      if not fields[key] then
        if opts.extra then
          -- Validate extra field
          local extra_ctx = make_context(ctx.mode, clone_path(ctx.path))
          table.insert(extra_ctx.path, key)
          local ok, val_or_err = opts.extra:_check(val, extra_ctx)
          if ok then
            result[key] = val_or_err
          else
            has_errors = true
            errors[key] = val_or_err
          end
        else
          has_errors = true
          local extra_ctx = make_context(ctx.mode, clone_path(ctx.path))
          table.insert(extra_ctx.path, key)
          errors[key] = make_error("unknown_field", extra_ctx.path, {
            field = key
          })
        end
      end
    end
  else
    -- Open table: copy unknown fields as-is
    for key, val in pairs(value) do
      if not fields[key] then
        result[key] = val
      end
    end
  end

  if has_errors then
    return false, make_error("table_invalid", ctx.path, {
      errors = errors
    })
  end

  return true, result
end

function T.table(fields, opts)
  opts = opts or {}

  -- Normalize fields: convert {key = schema} to {key = {schema = schema}}
  local normalized_fields = {}
  for key, val in pairs(fields) do
    if val.schema then
      -- Already normalized
      normalized_fields[key] = val
    else
      -- Assume val is a schema
      -- Check if schema is an optional wrapper
      local is_optional = val.tag == "optional"
      local inner_schema = is_optional and val.inner or val
      local default_value = is_optional and val.default or nil

      normalized_fields[key] = {
        schema = inner_schema,
        optional = is_optional,
        default = default_value
      }
    end
  end

  return make_node("table", {
    fields = normalized_fields,
    opts = opts,
    _check = check_table
  })
end

-- Optional wrapper

local function check_optional(node, value, ctx)
  if value == nil then
    if ctx.mode == "transform" and node.default ~= nil then
      local default_val = node.default
      -- Support callable defaults: if default is a function, call it
      if type(default_val) == "function" then
        default_val = default_val()
      end
      return true, default_val
    end
    return true, nil
  end

  return node.inner:_check(value, ctx)
end

function T.optional(schema, opts)
  opts = opts or {}
  return make_node("optional", {
    inner = schema,
    default = opts.default,
    opts = opts,
    _check = check_optional
  })
end

function T.default(schema, value)
  return T.optional(schema, { default = value })
end

-- Transform wrapper

local function check_transform(node, value, ctx)
  if ctx.mode == "transform" then
    -- Apply transformation
    local new_value = node.fn(value, ctx)
    -- Validate transformed value
    return node.inner:_check(new_value, ctx)
  else
    -- In check mode, just validate original value
    return node.inner:_check(value, ctx)
  end
end

function T.transform(schema, fn, opts)
  return make_node("transform", {
    inner = schema,
    fn = fn,
    opts = opts or {},
    _check = check_transform
  })
end

-- one_of type with intersection logic

-- Extract constraints from a schema for intersection computation
local function extract_constraints(schema)
  if not schema or not schema.tag then
    return nil
  end

  local tag = schema.tag

  if tag == "scalar" then
    return {
      type_name = schema.kind,
      constraints = schema.opts
    }
  elseif tag == "table" then
    local fields = {}
    for field_name, field_spec in pairs(schema.fields or {}) do
      fields[field_name] = {
        required = not field_spec.optional,
        type_name = field_spec.schema.tag == "scalar" and field_spec.schema.kind or field_spec.schema.tag,
        constraints = field_spec.schema.opts
      }
    end
    return {
      type_name = "table",
      fields = fields
    }
  elseif tag == "array" then
    return {
      type_name = "array",
      item_constraints = extract_constraints(schema.item_schema)
    }
  end

  return { type_name = tag }
end

-- Compute intersection of table-like variants
local function compute_intersection(variants)
  if not variants or #variants == 0 then
    return nil
  end

  -- Check if all variants are table-like
  local all_tables = true
  local constraints_list = {}

  for _, variant in ipairs(variants) do
    local constraints = extract_constraints(variant.schema)
    if not constraints or constraints.type_name ~= "table" then
      all_tables = false
      break
    end
    table.insert(constraints_list, constraints)
  end

  if not all_tables or #constraints_list == 0 then
    return nil
  end

  -- Find common required fields
  local result = {
    required_fields = {},
    optional_fields = {},
    conflicting_fields = {}
  }

  -- Collect all field names
  local all_fields = {}
  for _, c in ipairs(constraints_list) do
    for field_name, _ in pairs(c.fields or {}) do
      all_fields[field_name] = (all_fields[field_name] or 0) + 1
    end
  end

  -- Analyze each field
  for field_name, count in pairs(all_fields) do
    if count == #constraints_list then
      -- Field present in all variants
      local field_types = {}
      local all_required = true

      for _, c in ipairs(constraints_list) do
        local field = c.fields[field_name]
        if field then
          table.insert(field_types, field.type_name)
          if not field.required then
            all_required = false
          end
        end
      end

      -- Check if types are compatible
      local first_type = field_types[1]
      local compatible = true
      for _, ftype in ipairs(field_types) do
        if ftype ~= first_type then
          compatible = false
          break
        end
      end

      if compatible and all_required then
        result.required_fields[field_name] = first_type
      elseif compatible then
        result.optional_fields[field_name] = first_type
      else
        result.conflicting_fields[field_name] = field_types
      end
    end
  end

  return result
end

local function check_one_of(node, value, ctx)
  local variants = node.variants or {}
  local matching = {}
  local errors = {}

  for i, variant in ipairs(variants) do
    local variant_ctx = make_context(ctx.mode, clone_path(ctx.path))
    local ok, val_or_err = variant.schema:_check(value, variant_ctx)

    if ok then
      table.insert(matching, {
        index = i,
        name = variant.name or ("variant_" .. i),
        value = val_or_err
      })
    else
      errors[i] = {
        name = variant.name or ("variant_" .. i),
        error = val_or_err
      }
    end
  end

  if #matching == 0 then
    -- No variant matched - compute intersection for better error
    local intersection = compute_intersection(variants)
    return false, make_error("one_of_mismatch", ctx.path, {
      variants = errors,
      intersection = intersection
    })
  elseif #matching == 1 then
    -- Exactly one match - success
    return true, matching[1].value
  else
    -- Multiple matches - take first by default
    -- Could make this configurable (first wins vs ambiguity error)
    return true, matching[1].value
  end
end

function T.one_of(variants, opts)
  opts = opts or {}

  -- Normalize variants: allow bare schemas or {name=..., schema=...}
  local normalized_variants = {}
  for i, variant in ipairs(variants) do
    if variant.schema then
      normalized_variants[i] = variant
    else
      normalized_variants[i] = {
        name = opts.names and opts.names[i] or ("variant_" .. i),
        schema = variant
      }
    end
  end

  return make_node("one_of", {
    variants = normalized_variants,
    opts = opts,
    _check = check_one_of
  })
end

-- Reference placeholder (will be resolved by registry)

function T.ref(id, opts)
  return make_node("ref", {
    ref_id = id,
    opts = opts or {},
    _check = function(node, value, ctx)
      error("Unresolved reference: " .. id .. ". Use registry to resolve references.")
    end
  })
end

-- Mixin constructor

function T.mixin(schema, opts)
  opts = opts or {}
  return {
    _is_mixin = true,
    schema = schema,
    as = opts.as,
    doc = opts.doc
  }
end

-- Utility functions

-- Format error tree for human-readable output
local function format_error_impl(err, indent, lines)
  indent = indent or 0
  lines = lines or {}

  local prefix = string.rep("  ", indent)

  if err.kind == "type_mismatch" then
    local msg = string.format("%stype mismatch at %s: expected %s, got %s",
        prefix, err.path or "(root)",
        err.details.expected or "?",
        err.details.got or "?")
    table.insert(lines, msg)

  elseif err.kind == "constraint_violation" then
    local constraint = err.details.constraint or "?"
    local msg = string.format("%sconstraint violation at %s: %s",
        prefix, err.path or "(root)", constraint)
    if err.details.expected then
      msg = msg .. string.format(" (expected: %s, got: %s)",
          tostring(err.details.expected),
          tostring(err.details.got))
    end
    table.insert(lines, msg)

  elseif err.kind == "required_field_missing" then
    local msg = string.format("%srequired field missing: %s",
        prefix, err.path or err.details.field or "?")
    table.insert(lines, msg)

  elseif err.kind == "unknown_field" then
    local msg = string.format("%sunknown field: %s",
        prefix, err.path or err.details.field or "?")
    table.insert(lines, msg)

  elseif err.kind == "enum_mismatch" then
    local expected_str = table.concat(err.details.expected or {}, ", ")
    local msg = string.format("%senum mismatch at %s: expected one of [%s], got %s",
        prefix, err.path or "(root)",
        expected_str, tostring(err.details.got))
    table.insert(lines, msg)

  elseif err.kind == "literal_mismatch" then
    local msg = string.format("%sliteral mismatch at %s: expected %s, got %s",
        prefix, err.path or "(root)",
        tostring(err.details.expected),
        tostring(err.details.got))
    table.insert(lines, msg)

  elseif err.kind == "array_items_invalid" then
    local msg = string.format("%sarray items invalid at %s:", prefix, err.path or "(root)")
    table.insert(lines, msg)
    for _, item_err in pairs(err.details.errors or {}) do
      format_error_impl(item_err, indent + 1, lines)
    end

  elseif err.kind == "table_invalid" then
    local msg = string.format("%stable validation failed at %s:", prefix, err.path or "(root)")
    table.insert(lines, msg)
    for _, field_err in pairs(err.details.errors or {}) do
      format_error_impl(field_err, indent + 1, lines)
    end

  elseif err.kind == "one_of_mismatch" then
    local msg = string.format("%svalue does not match any alternative at %s:",
        prefix, err.path or "(root)")
    table.insert(lines, msg)

    -- Add intersection summary
    if err.details.intersection then
      local inter = err.details.intersection

      -- Show common required fields
      local req_fields = {}
      for field_name, field_type in pairs(inter.required_fields or {}) do
        table.insert(req_fields, string.format("%s: %s", field_name, field_type))
      end
      if #req_fields > 0 then
        table.insert(lines, prefix .. "  all alternatives require:")
        for _, field_desc in ipairs(req_fields) do
          table.insert(lines, prefix .. "    - " .. field_desc)
        end
      end

      -- Show optional common fields
      local opt_fields = {}
      for field_name, field_type in pairs(inter.optional_fields or {}) do
        table.insert(opt_fields, string.format("%s: %s", field_name, field_type))
      end
      if #opt_fields > 0 then
        table.insert(lines, prefix .. "  some alternatives also expect:")
        for _, field_desc in ipairs(opt_fields) do
          table.insert(lines, prefix .. "    - " .. field_desc)
        end
      end

      -- Show conflicting fields
      local conflicts = {}
      for field_name, field_types in pairs(inter.conflicting_fields or {}) do
        table.insert(conflicts, string.format("%s (conflicting types: %s)",
            field_name, table.concat(field_types, ", ")))
      end
      if #conflicts > 0 then
        table.insert(lines, prefix .. "  conflicting field requirements:")
        for _, conflict_desc in ipairs(conflicts) do
          table.insert(lines, prefix .. "    - " .. conflict_desc)
        end
      end
    end

    table.insert(lines, prefix .. "  tried alternatives:")
    for idx, variant_err in ipairs(err.details.variants or {}) do
      local variant_name = variant_err.name or ("variant " .. idx)
      table.insert(lines, string.format("%s    - %s:", prefix, variant_name))
      format_error_impl(variant_err.error, indent + 3, lines)
    end

  else
    -- Unknown error kind
    local msg = string.format("%sunknown error at %s: %s",
        prefix, err.path or "(root)", err.kind or "?")
    table.insert(lines, msg)
  end

  return lines
end

function T.format_error(err)
  if not err then
    return "no error"
  end

  local lines = format_error_impl(err, 0, {})
  return table.concat(lines, "\n")
end

-- Deep clone a value (for immutable transformations)
function T.deep_clone(value)
  if type(value) ~= "table" then
    return value
  end

  local result = {}
  for k, v in pairs(value) do
    result[k] = T.deep_clone(v)
  end
  return result
end

return T
