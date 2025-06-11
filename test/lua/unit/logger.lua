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
end)