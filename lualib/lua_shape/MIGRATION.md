# Migration Guide: tableshape to lua_shape

This guide helps migrate from tableshape to the new lua_shape library.

## Basic Concepts

### Module Import

**tableshape:**
```lua
local ts = require("tableshape").types
```

**lua_shape:**
```lua
local T = require "lua_shape.core"

-- Only need Registry if using schema registration/refs:
local Registry = require "lua_shape.registry"  -- optional
```

Note: All utility functions (like `format_error`) are included in the core module, so you only need one require statement for most use cases.

## Type Constructors

### Scalar Types

| tableshape | rspamd_schema | Notes |
|------------|---------------|-------|
| `ts.string` | `T.string()` | |
| `ts.number` | `T.number()` | |
| `ts.integer` | `T.integer()` | |
| `ts.boolean` | `T.boolean()` | |
| `ts.literal("foo")` | `T.literal("foo")` | |
| `ts.one_of{"a","b"}` | `T.enum({"a","b"})` | For simple value enums |

### Constraints

**tableshape:**
```lua
ts.string:length(3, 10)  -- min 3, max 10
ts.number:range(0, 100)
```

**rspamd_schema:**
```lua
T.string({ min_len = 3, max_len = 10 })
T.number({ min = 0, max = 100 })
T.integer({ min = 0, max = 100 })
```

### Arrays

**tableshape:**
```lua
ts.array_of(ts.string)
```

**rspamd_schema:**
```lua
T.array(T.string())
```

### Tables (Shapes)

**tableshape:**
```lua
ts.shape({
  name = ts.string,
  age = ts.number,
  email = ts.string:is_optional()
})
```

**rspamd_schema:**
```lua
T.table({
  name = T.string(),
  age = T.number(),
  email = { schema = T.string(), optional = true }
})

-- Or using :optional() method:
T.table({
  name = T.string(),
  age = T.number(),
  email = T.string():optional()
})
```

### Optional Fields

**tableshape:**
```lua
field = ts.string:is_optional()
```

**rspamd_schema:**
```lua
-- Method 1: inline
field = { schema = T.string(), optional = true }

-- Method 2: using :optional()
field = T.string():optional()
```

### Default Values

**tableshape:**
```lua
field = ts.string:is_optional()  -- then handle defaults manually
```

**rspamd_schema:**
```lua
field = { schema = T.string(), optional = true, default = "default_value" }

-- Or using :with_default()
field = T.string():with_default("default_value")
```

## Operators

### Union (one_of)

**tableshape:**
```lua
ts.string + ts.number
```

**rspamd_schema:**
```lua
T.one_of({ T.string(), T.number() })
```

### Transform

**tableshape:**
```lua
ts.string / tonumber
ts.string / function(v) return v:upper() end
```

**rspamd_schema:**
```lua
T.string():transform_with(tonumber)
T.string():transform_with(function(v) return v:upper() end)

-- Or using T.transform:
T.transform(T.string(), tonumber)
```

### Chained Transforms

**tableshape:**
```lua
(ts.string / tonumber) * ts.number
```

**rspamd_schema:**
```lua
T.string():transform_with(tonumber):transform_with(function(v)
  return T.number():check(v) and v or error("not a number")
end)

-- Better: validate after transform
T.transform(T.number(), function(v)
  return tonumber(v) or 0
end)
```

## one_of with Multiple Shapes

**tableshape:**
```lua
ts.one_of {
  ts.shape({ type = ts.literal("file"), path = ts.string }),
  ts.shape({ type = ts.literal("redis"), host = ts.string }),
}
```

**rspamd_schema:**
```lua
T.one_of({
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
      host = T.string()
    })
  }
})
```

## Documentation

**tableshape:**
```lua
ts.string:describe("User name")
```

**rspamd_schema:**
```lua
T.string():doc({
  summary = "User name",
  description = "Full description here",
  examples = {"alice", "bob"}
})
```

## Complex Example: Redis Options

**tableshape:**
```lua
local ts = require("tableshape").types

local db_schema = (ts.number / tostring + ts.string):is_optional()

local common_schema = {
  timeout = (ts.number + ts.string / parse_time):is_optional(),
  db = db_schema,
  password = ts.string:is_optional(),
}

local servers_schema = table_merge({
  servers = ts.string + ts.array_of(ts.string),
}, common_schema)

local redis_schema = ts.one_of {
  ts.shape(common_schema),
  ts.shape(servers_schema),
}
```

**lua_shape:**
```lua
local T = require "lua_shape.core"

-- Accept string or number for db
local db_schema = T.one_of({
  T.number(),
  T.string()
}):optional():doc({ summary = "Database number" })

-- Accept number or time string for timeout
local timeout_schema = T.transform(T.number({ min = 0 }), function(val)
  if type(val) == "number" then return val end
  if type(val) == "string" then return parse_time(val) end
  error("Expected number or time string")
end):optional():doc({ summary = "Connection timeout" })

-- Common fields
local common_fields = {
  timeout = timeout_schema,
  db = db_schema,
  password = T.string():optional()
}

-- Servers field accepts string or array
local servers_field = T.one_of({
  T.string(),
  T.array(T.string())
})

-- Define variants
local redis_schema = T.one_of({
  {
    name = "no_servers",
    schema = T.table(common_fields)
  },
  {
    name = "with_servers",
    schema = T.table(table_merge({
      servers = servers_field
    }, common_fields))
  }
})
```

Key improvements:
- Better error messages with intersection ("all alternatives require: db, timeout")
- Named variants for clarity
- Transform semantics explicit
- Documentation embedded in schema

## Validation

### Check Mode

**tableshape:**
```lua
local ok, err = schema:transform(config)
if not ok then
  logger.errx("Invalid config: %s", err)
end
```

**lua_shape:**
```lua
local T = require "lua_shape.core"

local ok, val_or_err = schema:check(config)
if not ok then
  logger.errx("Invalid config:\n%s", T.format_error(val_or_err))
end
```

### Transform Mode

**tableshape:**
```lua
local ok, result = schema:transform(config)
```

**rspamd_schema:**
```lua
local ok, result = schema:transform(config)
-- result will have defaults applied and transforms executed
```

## Key Differences

1. **Explicit vs Operator-based:**
   - tableshape uses operators (`+`, `/`, `*`) for composition
   - rspamd_schema uses explicit methods and constructors

2. **Error Reporting:**
   - tableshape returns string errors
   - rspamd_schema returns structured error trees with better messages

3. **one_of Intersection:**
   - rspamd_schema computes intersection of table variants for better error messages
   - Shows "all alternatives require field X" instead of listing every variant error

4. **Mixins:**
   - rspamd_schema has first-class mixin support with origin tracking
   - Can show "field from mixin redis" in docs and errors

5. **Export:**
   - rspamd_schema can export to JSON Schema
   - Can generate documentation IR from schemas

## Migration Strategy

1. Start with standalone schemas (not referenced by other code yet)
2. Test validation and error messages
3. Gradually replace tableshape imports
4. Update schema definitions
5. Update validation call sites
6. Remove tableshape dependency when complete

## Helper Patterns

### Common Transform Pattern

For fields that accept multiple types with normalization:

**tableshape:**
```lua
(ts.string + ts.number) / normalize_fn
```

**rspamd_schema:**
```lua
T.one_of({
  T.string():transform_with(normalize_fn),
  T.number():transform_with(normalize_fn)
})

-- Or apply transform after one_of:
T.one_of({ T.string(), T.number() }):transform_with(normalize_fn)
```

### Optional with Transform

**tableshape:**
```lua
(ts.string / tonumber):is_optional()
```

**rspamd_schema:**
```lua
T.string():transform_with(tonumber):optional()

-- Or with default:
T.string():transform_with(tonumber):with_default(0)
```
