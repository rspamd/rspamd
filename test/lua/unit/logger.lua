context("Logger unit tests", function()
  test("Logger functions", function()
    local log = require "rspamd_logger"

    local cases = {
      { 'string', 'string' },
      { '%1', 'string', 'string' },
      { '%1', '1.1', 1.1 },
      { '%1', '1', 1 },
      { '%1', 'true', true },
      { '%1', '{[1] = 1, [2] = test}', { 1, 'test' } },
      { '%1', '{[1] = 1, [2] = 2.1, [k2] = test}', { 1, 2.1, k2 = 'test' } },
      { '%s', 'true', true },
    }

    for _, c in ipairs(cases) do
      local s
      if c[3] then
        s = log.slog(c[1], c[3])
      else
        s = log.slog(c[1])
      end
      assert_equal(s, c[2], string.format("'%s' doesn't match with '%s'",
          c[2], s))
    end
  end)

  test("Logger graceful error handling", function()
    local log = require "rspamd_logger"

    -- Test missing arguments
    local missing_arg_cases = {
      { '%1', '<MISSING ARGUMENT>' },
      { '%0', '<MISSING ARGUMENT>' }, -- %0 is invalid since Lua args are 1-indexed
      { '%2', '<MISSING ARGUMENT>', 'arg1' },
      { '%1 %2', 'arg1 <MISSING ARGUMENT>', 'arg1' },
      { 'prefix %1 %3 suffix', 'prefix arg1 <MISSING ARGUMENT> suffix', 'arg1' },
    }

    for _, c in ipairs(missing_arg_cases) do
      local s
      if c[3] then
        s = log.slog(c[1], c[3])
      else
        s = log.slog(c[1])
      end
      assert_equal(s, c[2], string.format("Missing arg test: '%s' doesn't match with '%s'",
          c[2], s))
    end

    -- Test extra arguments
    local extra_arg_cases = {
      { '%1', 'arg1 <EXTRA 1 ARGUMENTS>', 'arg1', 'extra1' },
      { '%1', 'arg1 <EXTRA 2 ARGUMENTS>', 'arg1', 'extra1', 'extra2' },
      { '%s', 'arg1 <EXTRA 1 ARGUMENTS>', 'arg1', 'extra1' },
      { 'prefix %1 suffix', 'prefix arg1 suffix <EXTRA 1 ARGUMENTS>', 'arg1', 'extra1' },
    }

    for _, c in ipairs(extra_arg_cases) do
      local s
      if c[4] and c[5] then
        s = log.slog(c[1], c[3], c[4], c[5])
      elseif c[4] then
        s = log.slog(c[1], c[3], c[4])
      else
        s = log.slog(c[1], c[3])
      end
      assert_equal(s, c[2], string.format("Extra arg test: '%s' doesn't match with '%s'",
          c[2], s))
    end

    -- Test literal percent sequences (should pass through as-is)
    local literal_cases = {
      { '%-1', '%-1' },
      { '%abc', '%abc' }, -- Should pass through as literal since it's not a valid number
      { '%', '%' }, -- Single percent should pass through
    }

    for _, c in ipairs(literal_cases) do
      local s = log.slog(c[1])
      assert_equal(s, c[2], string.format("Literal test: '%s' doesn't match with '%s'",
          c[2], s))
    end

    -- Test mixed scenarios
    local mixed_cases = {
      { '%1 %3', 'arg1 <MISSING ARGUMENT> <EXTRA 1 ARGUMENTS>', 'arg1', 'extra1' },
      { '%2 %4', 'extra1 <MISSING ARGUMENT> <EXTRA 1 ARGUMENTS>', 'arg1', 'extra1' },
    }

    for _, c in ipairs(mixed_cases) do
      local s
      if c[4] then
        s = log.slog(c[1], c[3], c[4])
      else
        s = log.slog(c[1], c[3])
      end
      assert_equal(s, c[2], string.format("Mixed test: '%s' doesn't match with '%s'",
          c[2], s))
    end
  end)

  test("Logger type specifiers", function()
    local log = require "rspamd_logger"

    -- Test %d (signed integer)
    local int_cases = {
      { '%d', '100', 100 },
      { '%d', '100', 100.5 },  -- Should truncate to integer
      { '%d', '-42', -42 },
      { '%d', '0', 0 },
      { '%1d', '100', 100 },
      { 'count=%d', 'count=100', 100 },
      { 'count=%1d', 'count=100', 100 },
      { '%d items', '100 items', 100 },
    }

    for _, c in ipairs(int_cases) do
      local s = log.slog(c[1], c[3])
      assert_equal(s, c[2], string.format("Int format test: '%s' doesn't match with '%s'",
          c[2], s))
    end

    -- Test %ud (unsigned integer)
    local uint_cases = {
      { '%ud', '100', 100 },
      { '%1ud', '100', 100 },
      { 'size=%ud bytes', 'size=1024 bytes', 1024 },
    }

    for _, c in ipairs(uint_cases) do
      local s = log.slog(c[1], c[3])
      assert_equal(s, c[2], string.format("Unsigned int format test: '%s' doesn't match with '%s'",
          c[2], s))
    end

    -- Test %f (float) - smart formatting without trailing zeros
    local float_cases = {
      { '%f', '1.5', 1.5 },
      { '%f', '100.0', 100 },
      { '%f', '-42.75', -42.75 },
      { '%1f', '1.5', 1.5 },
      { 'pi=%f', 'pi=3.14', 3.14 },
    }

    for _, c in ipairs(float_cases) do
      local s = log.slog(c[1], c[3])
      assert_equal(s, c[2], string.format("Float format test: '%s' doesn't match with '%s'",
          c[2], s))
    end

    -- Test %.Nf (float with precision)
    local precision_cases = {
      { '%.2f', '1.50', 1.5 },
      { '%.3f', '3.145', 3.145 },
      { '%.1f', '100.0', 100 },
      { '%.0f', '42', 42.0 },
      { 'price=%.2f', 'price=19.99', 19.99 },
    }

    for _, c in ipairs(precision_cases) do
      local s = log.slog(c[1], c[3])
      assert_equal(s, c[2], string.format("Precision format test: '%s' doesn't match with '%s'",
          c[2], s))
    end

    -- Test mixed type specifiers
    local mixed_type_cases = {
      { 'count=%1d, price=%.2f, name=%3', 'count=100, price=1.50, name=string', 100, 1.5, 'string' },
      { '%d %f %s', '42 3.14 test', 42, 3.14, 'test' },
      { 'int=%d, float=%.3f, str=%s', 'int=100, float=1.500, str=hello', 100, 1.5, 'hello' },
    }

    for _, c in ipairs(mixed_type_cases) do
      local s = log.slog(c[1], c[3], c[4], c[5])
      assert_equal(s, c[2], string.format("Mixed type format test: '%s' doesn't match with '%s'",
          c[2], s))
    end

    -- Test type conversion from strings
    local string_conversion_cases = {
      { '%d', '42', '42' },  -- String to int
      { '%f', '3.14', '3.14' },  -- String to float
      { '%.2f', '3.14', '3.14' },  -- String to float with precision
    }

    for _, c in ipairs(string_conversion_cases) do
      local s = log.slog(c[1], c[3])
      assert_equal(s, c[2], string.format("String conversion test: '%s' doesn't match with '%s'",
          c[2], s))
    end

    -- Test fallback for non-numeric types
    local fallback_cases = {
      { '%d', '0', nil },  -- nil should become 0
      { '%f', '0.0', nil },  -- nil should become 0.0
      { '%.2f', '0.00', nil },  -- nil with precision should become 0.00
    }

    for _, c in ipairs(fallback_cases) do
      local s = log.slog(c[1], c[3])
      assert_equal(s, c[2], string.format("Fallback test: '%s' doesn't match with '%s'",
          c[2], s))
    end

    -- Test %% escaping
    local escape_cases = {
      { '%%', '%' },
      { '100%%', '100%' },
      { 'price=%.2f%%', 'price=19.99%', 19.99 },
      { '%1 is %%d not %d', '100 is %d not 42', 100, 42 },
    }

    for _, c in ipairs(escape_cases) do
      local s
      if c[4] then
        s = log.slog(c[1], c[3], c[4])
      elseif c[3] then
        s = log.slog(c[1], c[3])
      else
        s = log.slog(c[1])
      end
      assert_equal(s, c[2], string.format("Escape test: '%s' doesn't match with '%s'",
          c[2], s))
    end
  end)
end)