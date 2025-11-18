# lua_shape

A comprehensive schema validation and transformation library for Rspamd, designed to replace tableshape with improved error reporting, documentation generation, and export capabilities.

## Features

1. **Better Error Reporting**: Structured error trees with intersection analysis for `one_of` types
2. **Documentation Generation**: Extract structured documentation from schemas
3. **Type Constraints**: Numeric ranges, string lengths, patterns, and more
4. **First-class Mixins**: Field composition with origin tracking
5. **JSON Schema Export**: Export schemas for UCL validation
6. **Transform Support**: Immutable transformations with validation
7. **Pure Lua**: No dependencies on external modules (except optional lpeg for patterns)

## Quick Start

```lua
local T = require "lua_shape.core"

-- Define a schema
local config_schema = T.table({
  host = T.string({ min_len = 1 }),
  port = T.integer({ min = 1, max = 65535 }):with_default(8080),
  timeout = T.number({ min = 0 }):optional(),
  ssl = T.boolean():with_default(false)
})

-- Validate configuration
local ok, result = config_schema:check({
  host = "localhost",
  port = 3000
})

if not ok then
  print("Validation error:")
  print(T.format_error(result))
end

-- Transform with defaults applied
local ok, config = config_schema:transform({
  host = "example.com"
})
-- config.port == 8080 (default applied)
-- config.ssl == false (default applied)
```

## Core Types

### Scalars

- `T.string(opts)` - String with optional constraints
  - `min_len`, `max_len` - Length constraints
  - `pattern` - Lua pattern for validation (e.g., `"^%d+$"` for digits only)
  - `lpeg` - Optional lpeg pattern for complex parsing
- `T.number(opts)` - Number with optional range constraints (min, max)
  - Accepts both numbers and values convertible via `tonumber`
- `T.integer(opts)` - Integer (number with integer constraint)
- `T.boolean()` - Boolean value
- `T.callable()` - Function/callable value
- `T.enum(values)` - One of a fixed set of values
- `T.literal(value)` - Exact value match

### Structured Types

- `T.array(item_schema, opts)` - Array with item validation
  - Underlying table must be a dense, 1-indexed array (no sparse or string keys)
  - `min_items`, `max_items` - Size constraints
- `T.table(fields, opts)` - Table/object with field schemas
  - `open = true` - Allow additional fields not defined in schema
  - `open = false` (default) - Reject unknown fields
  - `extra = schema` - Schema for validating extra fields
  - `mixins` - Array of mixin schemas for composition (applied when the schema is resolved via the registry)
- `T.one_of(variants)` - Sum type (match exactly one alternative)

### Composition

- `schema:optional()` - Make schema optional
- `schema:with_default(value)` - Add default value (can be a function for dynamic defaults)
- `schema:doc(doc_table)` - Add documentation
- `schema:transform_with(fn)` - Apply transformation
- `T.transform(schema, fn)` - Transform wrapper
- `T.ref(id)` - Reference to registered schema
- `T.mixin(schema, opts)` - Mixin for table composition

## Examples

### Basic Types with Constraints

```lua
-- String with length constraint
local name_schema = T.string({ min_len = 3, max_len = 50 })

-- String with Lua pattern (validates format)
local email_schema = T.string({ pattern = "^[%w%.]+@[%w%.]+$" })
local ipv4_schema = T.string({ pattern = "^%d+%.%d+%.%d+%.%d+$" })

-- Integer with range
local age_schema = T.integer({ min = 0, max = 150 })

-- Enum
local level_schema = T.enum({"debug", "info", "warning", "error"})
```

### Arrays and Tables

```lua
-- Array of strings
local tags_schema = T.array(T.string())

-- Table with required and optional fields
local user_schema = T.table({
  name = T.string(),
  email = T.string(),
  age = T.integer():optional(),
  role = T.enum({"admin", "user"}):with_default("user")
})

-- Closed table (default): rejects unknown fields
local strict_config = T.table({
  host = T.string(),
  port = T.integer()
}, { open = false })

-- Open table: allows additional fields not in schema
local flexible_config = T.table({
  host = T.string(),
  port = T.integer()
}, { open = true })
-- Accepts: { host = "localhost", port = 8080, custom_field = "value" }
```

### one_of with Intersection

```lua
-- Multiple config variants
local config_schema = T.one_of({
  {
    name = "file_config",
    schema = T.table({
      type = T.literal("file"),
      path = T.string()
    })
  },
  {
    name = "redis_config",
    schema = T.table({
      type = T.literal("redis"),
      host = T.string(),
      port = T.integer():with_default(6379)
    })
  }
})

-- Error messages show intersection:
-- "all alternatives require: type (string)"
```

### Transforms

```lua
-- Parse time interval string to number
local timeout_schema = T.transform(T.number({ min = 0 }), function(val)
  if type(val) == "number" then
    return val
  elseif type(val) == "string" then
    return parse_time_interval(val)  -- "5s" -> 5.0
  else
    error("Expected number or time interval string")
  end
end)
```

> **Note:** transform functions are evaluated only when you call `schema:transform(...)`. A plain `schema:check(...)` validates the original input without invoking the transform, matching tableshape semantics.

### Callable Defaults

Defaults can be functions that are called each time a default is needed:

```lua
local function get_current_timestamp()
  return os.time()
end

local event_schema = T.table({
  name = T.string(),
  timestamp = T.number():with_default(get_current_timestamp),  -- Function called each time
  priority = T.integer():with_default(0)  -- Static default
})

-- Each transform gets a fresh timestamp
local ok, event1 = event_schema:transform({ name = "login" })
-- event1.timestamp will be the current time when transform was called
```

### Schema Registry

```lua
local Registry = require "lua_shape.registry"
local reg = Registry.global()

-- Define reusable schemas
local redis_schema = reg:define("redis.options", T.table({
  servers = T.array(T.string()),
  db = T.integer({ min = 0, max = 15 }):with_default(0)
}))

-- Reference in other schemas
local app_schema = T.table({
  cache = T.ref("redis.options")
})

-- Resolve references
local resolved = reg:resolve_schema(app_schema)
-- Validate/transforms should use the resolved schema so mixins/references are applied
local ok, cfg_or_err = resolved:transform({
  cache = {
    servers = {"redis:6379"}
  }
})
```

### Mixins with Origin Tracking

```lua
-- Base mixin
local redis_mixin = T.table({
  redis_host = T.string(),
  redis_port = T.integer():with_default(6379)
})

-- Use mixin in another schema
local plugin_schema = T.table({
  enabled = T.boolean(),
  plugin_option = T.string()
}, {
  mixins = {
    T.mixin(redis_mixin, { as = "redis" })
  }
})

-- Documentation will show:
-- Direct fields: enabled, plugin_option
-- Mixin "redis": redis_host, redis_port
```

Mixins are merged into the resulting table schema by `Registry:resolve_schema` (or `Registry:define`). Always validate against the resolved schema so that mixin fields participate in `:check` / `:transform` and emit proper documentation/JSON Schema output.

### JSON Schema Export

```lua
local jsonschema = require "lua_shape.jsonschema"

-- Export single schema
local json = jsonschema.from_schema(config_schema, {
  id = "https://rspamd.com/schema/config",
  title = "Application Config"
})

-- Export all schemas from registry
local all_schemas = jsonschema.export_registry(Registry.global())
```

### Documentation Generation

```lua
local docs = require "lua_shape.docs"

-- Generate documentation IR
local doc_tree = docs.for_schema(config_schema)

-- Render as markdown
local markdown_lines = docs.render_markdown(doc_tree.schema_doc)
for _, line in ipairs(markdown_lines) do
  print(line)
end
```

## Error Reporting

### Structured Errors

Errors are represented as trees:

```lua
{
  kind = "table_invalid",
  path = "config",
  details = {
    errors = {
      port = {
        kind = "constraint_violation",
        path = "config.port",
        details = { constraint = "max", expected = 65535, got = 99999 }
      }
    }
  }
}
```

### Human-Readable Formatting

```lua
local T = require "lua_shape.core"
print(T.format_error(error_tree))
```

Output:
```
table validation failed at config:
  constraint violation at config.port: max (expected: 65535, got: 99999)
```

### one_of Intersection Errors

When all variants of a one_of fail, the error shows common requirements:

```
value does not match any alternative at :
  all alternatives require:
    - name: string
    - type: string
  some alternatives also expect:
    - path: string (in file_config variant)
    - host: string (in redis_config variant)
  tried alternatives:
    - file_config: ...
    - redis_config: ...
```

## API Reference

### Core Module (`lua_shape.core`)

#### Type Constructors

- `T.string(opts?)` - String type
  - opts: `min_len`, `max_len`, `pattern`, `lpeg`, `doc`
- `T.number(opts?)` - Number type
  - opts: `min`, `max`, `doc`
- `T.integer(opts?)` - Integer type (number with integer=true)
  - opts: `min`, `max`, `doc`
- `T.boolean(opts?)` - Boolean type
- `T.enum(values, opts?)` - Enum type
- `T.literal(value, opts?)` - Literal value type
- `T.array(item_schema, opts?)` - Array type
  - opts: `min_items`, `max_items`, `doc`
- `T.table(fields, opts?)` - Table type
  - opts: `open`, `extra`, `mixins`, `doc`
- `T.one_of(variants, opts?)` - Sum type
- `T.optional(schema, opts?)` - Optional wrapper
- `T.default(schema, value)` - Default value wrapper
- `T.transform(schema, fn, opts?)` - Transform wrapper
- `T.ref(id, opts?)` - Schema reference placeholder (must be resolved via the registry before validation)
- `T.mixin(schema, opts?)` - Mixin definition

#### Schema Methods

- `schema:check(value, ctx?)` - Validate value
- `schema:transform(value, ctx?)` - Transform and validate (tableshape-compatible `(result)` / `(nil, err)` contract)
- `schema:optional(opts?)` - Make optional
- `schema:with_default(value)` - Add default
- `schema:doc(doc_table)` - Add documentation
- `schema:transform_with(fn, opts?)` - Add transformation

### Registry Module (`lua_shape.registry`)

- `Registry.global()` - Get/create global registry
- `registry:define(id, schema)` - Register schema with ID (returns the resolved version with mixins/reference chains applied)
- `registry:get(id)` - Get schema by ID
- `registry:resolve_schema(schema)` - Resolve references and mixins (recurses into nested arrays/one_of/options and caches the result)
- `registry:list()` - List all schema IDs
- `registry:export_all()` - Export all schemas

### Core Utilities

The core module also includes utility functions:

- `T.format_error(err)` - Format error tree as human-readable string
- `T.deep_clone(value)` - Deep clone value for immutable transformations

### JSON Schema Module (`lua_shape.jsonschema`)

- `jsonschema.from_schema(schema, opts?)` - Convert to JSON Schema
- `jsonschema.export_registry(registry, opts?)` - Export all schemas

### Docs Module (`lua_shape.docs`)

- `docs.for_schema(schema, opts?)` - Generate documentation IR
- `docs.for_registry(registry, opts?)` - Generate docs for all schemas
- `docs.render_markdown(doc_tree, indent?)` - Render as markdown

## Migration from tableshape

See [MIGRATION.md](MIGRATION.md) for detailed migration guide.

Quick reference:

| tableshape | lua_shape |
|------------|---------------|
| `ts.string` | `T.string()` |
| `ts.number` | `T.number()` |
| `ts.array_of(ts.string)` | `T.array(T.string())` |
| `ts.shape({...})` | `T.table({...})` |
| `field:is_optional()` | `field:optional()` or `{ schema = ..., optional = true }` |
| `ts.string + ts.number` | `T.one_of({ T.string(), T.number() })` |
| `ts.string / fn` | `T.string():transform_with(fn)` or `T.transform(T.number(), fn)` |
| `field:describe("...")` | `field:doc({ summary = "..." })` |

## Files

- `core.lua` - Core type system, validation, and utilities
- `registry.lua` - Schema registration and reference resolution
- `jsonschema.lua` - JSON Schema export
- `docs.lua` - Documentation generation
- `MIGRATION.md` - Migration guide from tableshape
- `README.md` - This file

## License

Apache License 2.0 - Same as Rspamd
