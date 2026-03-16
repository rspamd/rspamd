--[[
Copyright (c) 2026, Namecheap Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
]]--

context("Lupa Jinja template engine unit tests", function()
  local lupa = require("lupa")

  -- Helper: expand template with optional env table (simulates env vars as strings)
  local function expand(template, env)
    return lupa.expand(template, env or {})
  end

  -- Helper: expand with env vars (all values are strings, like real RSPAMD_ env vars)
  local function expand_env(template, vars)
    return lupa.expand(template, { env = vars })
  end

  -- =========================================================================
  -- VALIDATION FILTERS (with env var string inputs)
  -- =========================================================================

  -- mandatory
  test("mandatory: passes non-empty string", function()
    assert_equal(expand('{{ "test" | mandatory("fail") }}'), 'test')
  end)

  test("mandatory: works with env var", function()
    assert_equal(expand_env('{{ env.KEY | mandatory("KEY required") }}', { KEY = "my_key" }), 'my_key')
  end)

  test("mandatory: crashes on empty string", function()
    local ok, err = pcall(expand, '{{ "" | mandatory("VALUE_REQUIRED") }}')
    assert_false(ok)
    assert_match('VALUE_REQUIRED', err)
  end)

  test("mandatory: crashes on nil env var", function()
    local ok, err = pcall(expand_env, '{{ env.MISSING | mandatory("MISSING_VAR") }}', {})
    assert_false(ok)
    assert_match('MISSING_VAR', err)
  end)

  -- require_int
  test("require_int: valid integer string", function()
    assert_equal(expand('{{ "42" | require_int }}'), '42')
  end)

  test("require_int: works with env var", function()
    assert_equal(expand_env('{{ env.PORT | require_int }}', { PORT = "8080" }), '8080')
  end)

  test("require_int: zero is valid", function()
    assert_equal(expand('{{ "0" | require_int }}'), '0')
  end)

  test("require_int: negative is valid", function()
    assert_equal(expand('{{ "-1" | require_int }}'), '-1')
  end)

  test("require_int: crashes on float string", function()
    local ok, err = pcall(expand, '{{ "3.14" | require_int("NOT_INT") }}')
    assert_false(ok)
    assert_match('NOT_INT', err)
  end)

  test("require_int: crashes on non-numeric string", function()
    local ok, err = pcall(expand, '{{ "abc" | require_int("NOT_INT") }}')
    assert_false(ok)
    assert_match('NOT_INT', err)
  end)

  -- require_number
  test("require_number: valid float string", function()
    assert_equal(expand('{{ "3.14" | require_number }}'), '3.14')
  end)

  test("require_number: valid integer string", function()
    assert_equal(expand('{{ "42" | require_number }}'), '42')
  end)

  test("require_number: works with env var", function()
    assert_equal(expand_env('{{ env.THRESHOLD | require_number }}', { THRESHOLD = "8.0" }), '8.0')
  end)

  test("require_number: negative is valid", function()
    assert_equal(expand('{{ "-4.5" | require_number }}'), '-4.5')
  end)

  test("require_number: crashes on non-numeric", function()
    local ok, err = pcall(expand, '{{ "abc" | require_number("NOT_NUM") }}')
    assert_false(ok)
    assert_match('NOT_NUM', err)
  end)

  -- require_bool
  test("require_bool: accepts all UCL boolean strings", function()
    for _, v in ipairs({"true", "false", "yes", "no", "on", "off", "1", "0", "TRUE", "False", "YES", "NO", "On", "OFF"}) do
      local result = expand('{{ "' .. v .. '" | require_bool }}')
      assert_equal(result, v, 'require_bool should accept "' .. v .. '"')
    end
  end)

  test("require_bool: works with env var", function()
    assert_equal(expand_env('{{ env.ENABLED | require_bool }}', { ENABLED = "true" }), 'true')
    assert_equal(expand_env('{{ env.ENABLED | require_bool }}', { ENABLED = "YES" }), 'YES')
  end)

  test("require_bool: crashes on invalid", function()
    local ok, err = pcall(expand, '{{ "maybe" | require_bool("NOT_BOOL") }}')
    assert_false(ok)
    assert_match('NOT_BOOL', err)
  end)

  -- require_duration
  test("require_duration: parses all duration formats", function()
    assert_equal(expand('{{ "30s" | require_duration }}'), '30')
    assert_equal(expand('{{ "5min" | require_duration }}'), '300')
    assert_equal(expand('{{ "5m" | require_duration }}'), '300')
    assert_equal(expand('{{ "1h" | require_duration }}'), '3600')
    assert_equal(expand('{{ "10d" | require_duration }}'), '864000')
    assert_equal(expand('{{ "1w" | require_duration }}'), '604800')
    assert_equal(expand('{{ "1y" | require_duration }}'), '31536000')
    assert_equal(expand('{{ "500ms" | require_duration }}'), '0.5')
    assert_equal(expand('{{ "42" | require_duration }}'), '42')
  end)

  test("require_duration: works with env var", function()
    assert_equal(expand_env('{{ env.TIMEOUT | require_duration }}', { TIMEOUT = "30s" }), '30')
    assert_equal(expand_env('{{ env.INTERVAL | require_duration }}', { INTERVAL = "5min" }), '300')
  end)

  test("require_duration: crashes on invalid", function()
    local ok, err = pcall(expand, '{{ "abc" | require_duration("BAD_DUR") }}')
    assert_false(ok)
    assert_match('BAD_DUR', err)
  end)

  -- require_json
  test("require_json: valid JSON passes through", function()
    assert_equal(expand('{{ \'["a","b"]\' | require_json }}'), '["a","b"]')
  end)

  test("require_json: works with env var", function()
    assert_equal(expand_env('{{ env.MODULES | require_json }}', { MODULES = '["mod1","mod2"]' }), '["mod1","mod2"]')
  end)

  test("require_json: crashes on invalid", function()
    local ok, err = pcall(expand, '{% set x = "[unclosed" | require_json("BAD_JSON") %}')
    assert_false(ok)
    assert_match('BAD_JSON', err)
  end)

  -- require_size / tobytes
  test("require_size: accepts valid sizes", function()
    for _, v in ipairs({"150Mb", "1Gb", "512Kb", "1024", "0", "100b", "0Kb"}) do
      assert_equal(expand('{{ "' .. v .. '" | require_size }}'), v)
    end
  end)

  test("require_size: works with env var", function()
    assert_equal(expand_env('{{ env.MAX_SIZE | require_size }}', { MAX_SIZE = "150Mb" }), '150Mb')
  end)

  test("require_size: crashes on invalid", function()
    local ok, err = pcall(expand, '{{ "abc" | require_size("BAD_SIZE") }}')
    assert_false(ok)
    assert_match('BAD_SIZE', err)
  end)

  test("require_size: crashes on negative", function()
    local ok, err = pcall(expand, '{{ "-5Mb" | require_size("NEG_SIZE") }}')
    assert_false(ok)
    assert_match('NEG_SIZE', err)
  end)

  test("tobytes: converts correctly", function()
    assert_equal(expand('{{ "150Mb" | tobytes }}'), '157286400')
    assert_equal(expand('{{ "1Gb" | tobytes }}'), '1073741824')
    assert_equal(expand('{{ "512Kb" | tobytes }}'), '524288')
    assert_equal(expand('{{ "1024" | tobytes }}'), '1024')
    assert_equal(expand('{{ "100b" | tobytes }}'), '100')
    assert_equal(expand('{{ "0" | tobytes }}'), '0')
  end)

  -- =========================================================================
  -- PARSING FILTERS
  -- =========================================================================

  -- fromjson
  test("fromjson: parse JSON object", function()
    assert_equal(expand('{% set obj = \'{"a":1,"b":"hello"}\' | fromjson %}{{ obj.a }},{{ obj.b }}'), '1,hello')
  end)

  test("fromjson: parse JSON array", function()
    assert_equal(expand('{% set arr = \'["x","y","z"]\' | fromjson %}{{ arr[1] }},{{ arr[2] }},{{ arr[3] }}'), 'x,y,z')
  end)

  test("fromjson: works with env var", function()
    assert_equal(expand_env('{% set arr = env.LIST | fromjson %}{{ arr[1] }},{{ arr[2] }}', { LIST = '["a","b"]' }), 'a,b')
  end)

  test("fromjson: nested object access", function()
    assert_equal(expand('{% set obj = \'{"a":{"b":{"c":"deep"}}}\' | fromjson %}{{ obj.a.b.c }}'), 'deep')
  end)

  test("fromjson: iterate array with for loop", function()
    assert_equal(expand('{% set arr = \'["x","y","z"]\' | fromjson %}{% for item in arr %}{{ item }}{% endfor %}'), 'xyz')
  end)

  -- split
  test("split: basic CSV", function()
    assert_equal(expand('{% set arr = "a,b,c" | split(",") %}{{ arr[1] }},{{ arr[2] }},{{ arr[3] }}'), 'a,b,c')
  end)

  test("split: with max_splits", function()
    assert_equal(expand('{% set arr = "a,b,c,d" | split(",", 2) %}{{ arr | length }}'), '3')
  end)

  -- trim
  test("trim: strips whitespace", function()
    assert_equal(expand('{{ "  hello  " | trim }}'), 'hello')
  end)

  test("trim: tabs and newlines", function()
    assert_equal(expand('{{ "\t hello \n" | trim }}'), 'hello')
  end)

  -- =========================================================================
  -- TYPE TESTS (all must work with string inputs like env vars)
  -- =========================================================================

  -- is_defined / is_undefined / is_nil / is_none
  test("is_defined: true for set env var", function()
    assert_equal(expand_env('{% if is_defined(env.X) %}yes{% else %}no{% endif %}', { X = "val" }), 'yes')
  end)

  test("is_defined: false for missing env var", function()
    assert_equal(expand_env('{% if is_defined(env.MISSING) %}yes{% else %}no{% endif %}', {}), 'no')
  end)

  test("is_nil: true for missing env var", function()
    assert_equal(expand_env('{% if is_nil(env.MISSING) %}yes{% else %}no{% endif %}', {}), 'yes')
  end)

  test("is_none: alias for is_nil", function()
    assert_equal(expand_env('{% if is_none(env.MISSING) %}yes{% else %}no{% endif %}', {}), 'yes')
  end)

  test("is_undefined: alias for is_nil", function()
    assert_equal(expand_env('{% if is_undefined(env.MISSING) %}yes{% else %}no{% endif %}', {}), 'yes')
  end)

  -- is_string
  test("is_string: true for env var (always string)", function()
    assert_equal(expand_env('{% if is_string(env.X) %}yes{% else %}no{% endif %}', { X = "hello" }), 'yes')
  end)

  test("is_string: true for numeric env var (still string)", function()
    assert_equal(expand_env('{% if is_string(env.X) %}yes{% else %}no{% endif %}', { X = "42" }), 'yes')
  end)

  -- is_number (string-aware)
  test("is_number: true for integer string", function()
    assert_equal(expand('{% if is_number("42") %}yes{% else %}no{% endif %}'), 'yes')
  end)

  test("is_number: true for float string", function()
    assert_equal(expand('{% if is_number("3.14") %}yes{% else %}no{% endif %}'), 'yes')
  end)

  test("is_number: true for negative string", function()
    assert_equal(expand('{% if is_number("-1") %}yes{% else %}no{% endif %}'), 'yes')
  end)

  test("is_number: true for zero string", function()
    assert_equal(expand('{% if is_number("0") %}yes{% else %}no{% endif %}'), 'yes')
  end)

  test("is_number: false for non-numeric string", function()
    assert_equal(expand('{% if is_number("abc") %}yes{% else %}no{% endif %}'), 'no')
  end)

  test("is_number: works with env var", function()
    assert_equal(expand_env('{% if is_number(env.PORT) %}yes{% else %}no{% endif %}', { PORT = "8080" }), 'yes')
    assert_equal(expand_env('{% if is_number(env.NAME) %}yes{% else %}no{% endif %}', { NAME = "test" }), 'no')
  end)

  test("is_number: true for actual Lua number", function()
    assert_equal(expand('{% set x = 42 %}{% if is_number(x) %}yes{% else %}no{% endif %}'), 'yes')
  end)

  -- is_integer (string-aware)
  test("is_integer: true for integer string", function()
    assert_equal(expand('{% if is_integer("42") %}yes{% else %}no{% endif %}'), 'yes')
  end)

  test("is_integer: false for float string", function()
    assert_equal(expand('{% if is_integer("3.14") %}yes{% else %}no{% endif %}'), 'no')
  end)

  test("is_integer: true for zero string", function()
    assert_equal(expand('{% if is_integer("0") %}yes{% else %}no{% endif %}'), 'yes')
  end)

  test("is_integer: works with env var", function()
    assert_equal(expand_env('{% if is_integer(env.DB) %}yes{% else %}no{% endif %}', { DB = "15" }), 'yes')
    assert_equal(expand_env('{% if is_integer(env.PROB) %}yes{% else %}no{% endif %}', { PROB = "0.5" }), 'no')
  end)

  -- is_float
  test("is_float: true for float string", function()
    assert_equal(expand('{% if is_float("3.14") %}yes{% else %}no{% endif %}'), 'yes')
  end)

  test("is_float: false for integer string", function()
    assert_equal(expand('{% if is_float("42") %}yes{% else %}no{% endif %}'), 'no')
  end)

  -- is_boolean
  test("is_boolean: false for string 'true'", function()
    assert_equal(expand('{% if is_boolean("true") %}yes{% else %}no{% endif %}'), 'no')
  end)

  test("is_boolean: true for actual boolean", function()
    assert_equal(expand('{% set x = true %}{% if is_boolean(x) %}yes{% else %}no{% endif %}'), 'yes')
  end)

  -- is_mapping / is_table
  test("is_table: true for parsed JSON object", function()
    assert_equal(expand('{% set obj = \'{"a":1}\' | fromjson %}{% if is_table(obj) %}yes{% else %}no{% endif %}'), 'yes')
  end)

  test("is_table: false for string", function()
    assert_equal(expand('{% if is_table("hello") %}yes{% else %}no{% endif %}'), 'no')
  end)

  -- is_true / is_false (UCL-aware, string inputs)
  test("is_true: accepts all UCL truthy strings", function()
    for _, v in ipairs({"true", "TRUE", "True", "yes", "YES", "Yes", "on", "ON", "On", "1"}) do
      assert_equal(expand('{% if is_true("' .. v .. '") %}yes{% else %}no{% endif %}'), 'yes', 'is_true("' .. v .. '")')
    end
  end)

  test("is_true: rejects non-truthy", function()
    for _, v in ipairs({"false", "no", "off", "0", "maybe", "", "2"}) do
      assert_equal(expand('{% if is_true("' .. v .. '") %}yes{% else %}no{% endif %}'), 'no', 'is_true("' .. v .. '")')
    end
  end)

  test("is_true: works with env var", function()
    assert_equal(expand_env('{% if is_true(env.ENABLED) %}yes{% else %}no{% endif %}', { ENABLED = "true" }), 'yes')
    assert_equal(expand_env('{% if is_true(env.ENABLED) %}yes{% else %}no{% endif %}', { ENABLED = "YES" }), 'yes')
    assert_equal(expand_env('{% if is_true(env.ENABLED) %}yes{% else %}no{% endif %}', { ENABLED = "false" }), 'no')
  end)

  test("is_false: accepts all UCL falsy strings", function()
    for _, v in ipairs({"false", "FALSE", "False", "no", "NO", "No", "off", "OFF", "Off", "0"}) do
      assert_equal(expand('{% if is_false("' .. v .. '") %}yes{% else %}no{% endif %}'), 'yes', 'is_false("' .. v .. '")')
    end
  end)

  test("is_false: rejects non-falsy", function()
    for _, v in ipairs({"true", "yes", "on", "1", "maybe", "", "2"}) do
      assert_equal(expand('{% if is_false("' .. v .. '") %}yes{% else %}no{% endif %}'), 'no', 'is_false("' .. v .. '")')
    end
  end)

  test("is_false: works with env var", function()
    assert_equal(expand_env('{% if is_false(env.ENABLED) %}yes{% else %}no{% endif %}', { ENABLED = "false" }), 'yes')
    assert_equal(expand_env('{% if is_false(env.ENABLED) %}yes{% else %}no{% endif %}', { ENABLED = "true" }), 'no')
  end)

  -- is_json
  test("is_json: valid JSON", function()
    assert_equal(expand('{% if is_json(\'["a"]\') %}yes{% else %}no{% endif %}'), 'yes')
  end)

  test("is_json: valid JSON object", function()
    assert_equal(expand('{% if is_json(\'{"k":"v"}\') %}yes{% else %}no{% endif %}'), 'yes')
  end)

  test("is_json: invalid JSON", function()
    assert_equal(expand('{% if is_json("{broken") %}yes{% else %}no{% endif %}'), 'no')
  end)

  test("is_json: empty string", function()
    assert_equal(expand('{% if is_json("") %}yes{% else %}no{% endif %}'), 'no')
  end)

  test("is_json: works with env var", function()
    assert_equal(expand_env('{% if is_json(env.DATA) %}yes{% else %}no{% endif %}', { DATA = '["a"]' }), 'yes')
    assert_equal(expand_env('{% if is_json(env.DATA) %}yes{% else %}no{% endif %}', { DATA = 'broken' }), 'no')
  end)

  -- is_size
  test("is_size: valid sizes", function()
    for _, v in ipairs({"150Mb", "1Gb", "512Kb", "1024", "0", "100b", "0Kb"}) do
      assert_equal(expand('{% if is_size("' .. v .. '") %}yes{% else %}no{% endif %}'), 'yes', 'is_size("' .. v .. '")')
    end
  end)

  test("is_size: rejects invalid", function()
    for _, v in ipairs({"abc", "", "-5Mb"}) do
      assert_equal(expand('{% if is_size("' .. v .. '") %}yes{% else %}no{% endif %}'), 'no', 'is_size("' .. v .. '")')
    end
  end)

  test("is_size: works with env var", function()
    assert_equal(expand_env('{% if is_size(env.MAX) %}yes{% else %}no{% endif %}', { MAX = "150Mb" }), 'yes')
    assert_equal(expand_env('{% if is_size(env.MAX) %}yes{% else %}no{% endif %}', { MAX = "garbage" }), 'no')
  end)

  -- =========================================================================
  -- NUMBER TESTS
  -- =========================================================================

  test("is_odd: works", function()
    assert_equal(expand('{% if is_odd(3) %}yes{% else %}no{% endif %}'), 'yes')
    assert_equal(expand('{% if is_odd(4) %}yes{% else %}no{% endif %}'), 'no')
  end)

  test("is_even: works", function()
    assert_equal(expand('{% if is_even(4) %}yes{% else %}no{% endif %}'), 'yes')
    assert_equal(expand('{% if is_even(3) %}yes{% else %}no{% endif %}'), 'no')
  end)

  test("is_divisibleby: works", function()
    assert_equal(expand('{% if is_divisibleby(10, 5) %}yes{% else %}no{% endif %}'), 'yes')
    assert_equal(expand('{% if is_divisibleby(10, 3) %}yes{% else %}no{% endif %}'), 'no')
  end)

  -- =========================================================================
  -- COMPARISON TESTS
  -- =========================================================================

  test("is_eq: string comparison", function()
    assert_equal(expand('{% if is_eq("hello", "hello") %}yes{% else %}no{% endif %}'), 'yes')
    assert_equal(expand('{% if is_eq("hello", "world") %}yes{% else %}no{% endif %}'), 'no')
  end)

  test("is_ne: not equal", function()
    assert_equal(expand('{% if is_ne("a", "b") %}yes{% else %}no{% endif %}'), 'yes')
  end)

  test("is_lt / is_gt: comparison", function()
    assert_equal(expand('{% if is_lt(1, 2) %}yes{% else %}no{% endif %}'), 'yes')
    assert_equal(expand('{% if is_gt(2, 1) %}yes{% else %}no{% endif %}'), 'yes')
  end)

  test("is_le / is_ge: comparison", function()
    assert_equal(expand('{% if is_le(1, 1) %}yes{% else %}no{% endif %}'), 'yes')
    assert_equal(expand('{% if is_ge(1, 1) %}yes{% else %}no{% endif %}'), 'yes')
  end)

  test("is_eq: works with env var", function()
    assert_equal(expand_env('{% if is_eq(env.MODE, "strict") %}yes{% else %}no{% endif %}', { MODE = "strict" }), 'yes')
    assert_equal(expand_env('{% if is_eq(env.MODE, "strict") %}yes{% else %}no{% endif %}', { MODE = "lax" }), 'no')
  end)

  -- =========================================================================
  -- STRING TESTS
  -- =========================================================================

  test("is_in: substring check", function()
    assert_equal(expand('{% if is_in("@", "user@domain.com") %}yes{% else %}no{% endif %}'), 'yes')
    assert_equal(expand('{% if is_in("@", "nodomain") %}yes{% else %}no{% endif %}'), 'no')
  end)

  test("is_in: table membership", function()
    assert_equal(expand('{% set t = ["a","b","c"] %}{% if is_in("b", t) %}yes{% else %}no{% endif %}'), 'yes')
    assert_equal(expand('{% set t = ["a","b","c"] %}{% if is_in("d", t) %}yes{% else %}no{% endif %}'), 'no')
  end)

  test("is_startswith: works", function()
    assert_equal(expand('{% if is_startswith("hello world", "hello") %}yes{% else %}no{% endif %}'), 'yes')
    assert_equal(expand('{% if is_startswith("hello world", "world") %}yes{% else %}no{% endif %}'), 'no')
  end)

  test("is_endswith: works", function()
    assert_equal(expand('{% if is_endswith("hello.min", "min") %}yes{% else %}no{% endif %}'), 'yes')
    assert_equal(expand('{% if is_endswith("hello.min", "max") %}yes{% else %}no{% endif %}'), 'no')
  end)

  test("is_match: Lua pattern", function()
    assert_equal(expand('{% if is_match("hello123", "^%a+%d+$") %}yes{% else %}no{% endif %}'), 'yes')
    assert_equal(expand('{% if is_match("hello", "^%d+$") %}yes{% else %}no{% endif %}'), 'no')
  end)

  test("is_lower: works", function()
    assert_equal(expand('{% if is_lower("hello") %}yes{% else %}no{% endif %}'), 'yes')
    assert_equal(expand('{% if is_lower("Hello") %}yes{% else %}no{% endif %}'), 'no')
  end)

  test("is_upper: works", function()
    assert_equal(expand('{% if is_upper("HELLO") %}yes{% else %}no{% endif %}'), 'yes')
    assert_equal(expand('{% if is_upper("Hello") %}yes{% else %}no{% endif %}'), 'no')
  end)

  test("is_sameas: alias for is_eq", function()
    assert_equal(expand('{% if is_sameas("a", "a") %}yes{% else %}no{% endif %}'), 'yes')
  end)

  -- =========================================================================
  -- CONTROL FLOW AND SCOPING
  -- =========================================================================

  test("variables set in if blocks persist after endif", function()
    assert_equal(expand('{% set x = "original" %}{% if 1 == 1 %}{% set x = "redefined" %}{% endif %}{{ x }}'), 'redefined')
  end)

  test("elseif works", function()
    assert_equal(expand('{% set x = "b" %}{% if x == "a" %}A{% elseif x == "b" %}B{% else %}C{% endif %}'), 'B')
  end)

  test("range is 1-based", function()
    assert_equal(expand('{% for i in range(3) %}{{ i }},{% endfor %}'), '1,2,3,')
  end)

  test("range with start and stop", function()
    assert_equal(expand('{% for i in range(2, 5) %}{{ i }},{% endfor %}'), '2,3,4,5,')
  end)

  test("loop.last works in for", function()
    assert_equal(expand('{% set arr = ["a","b","c"] %}{% for item in arr %}{{ item }}{% if not loop.last %},{% endif %}{% endfor %}'), 'a,b,c')
  end)

  test("loop.index works in for", function()
    assert_equal(expand('{% for i in range(3) %}{{ loop.index }},{% endfor %}'), '1,2,3,')
  end)

  -- =========================================================================
  -- REAL-WORLD ENV VAR PATTERNS
  -- =========================================================================

  test("pattern: boolean env var with is_true", function()
    assert_equal(
      expand_env('{% if is_true(env.FEATURE_ENABLED) %}enabled = true;{% else %}enabled = false;{% endif %}', { FEATURE_ENABLED = "yes" }),
      'enabled = true;'
    )
  end)

  test("pattern: default with require_bool", function()
    assert_equal(
      expand_env('{% set enabled = env.FEATURE | default "true" | require_bool %}enabled = {{ enabled }};', {}),
      'enabled = true;'
    )
  end)

  test("pattern: duration with capping", function()
    assert_equal(
      expand_env('{% set timeout = env.TIMEOUT | default "30s" | require_duration %}{% if timeout > 300 %}{% set timeout = "5min" %}{% endif %}timeout = {{ timeout }};', { TIMEOUT = "600s" }),
      'timeout = 5min;'
    )
  end)

  test("pattern: JSON array iteration", function()
    assert_equal(
      expand_env('{% set modules = env.DISABLED | default \'["a"]\' | fromjson %}{% for m in modules %}{{ m }},{% endfor %}', { DISABLED = '["x","y","z"]' }),
      'x,y,z,'
    )
  end)

  test("pattern: size validation with tobytes", function()
    assert_equal(
      expand_env('{% set bytes = env.MAX_SIZE | default "150Mb" | require_size | tobytes %}{{ bytes }}', { MAX_SIZE = "1Gb" }),
      '1073741824'
    )
  end)

  test("pattern: conditional validation with mandatory", function()
    local ok, err = pcall(expand_env,
      '{% set pct = env.PERCENT | default "0.5" | require_number %}{% if (pct | float) >= 1 %}{% set _err = "" | mandatory("PERCENT must be < 1") %}{% endif %}',
      { PERCENT = "1.5" }
    )
    assert_false(ok)
    assert_match('PERCENT must be < 1', err)
  end)
end)
