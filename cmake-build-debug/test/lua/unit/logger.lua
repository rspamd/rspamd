context("Logger unit tests", function()
  test("Logger functions", function()
    local log = require "rspamd_logger"

    local cases = {
      {'string', 'string'},
      {'%1', 'string', 'string'},
      {'%1', '1.1', 1.1},
      {'%1', '1', 1},
      {'%1', 'true', true},
      {'%1', '{[1] = 1, [2] = test}', {1, 'test'}},
       {'%1', '{[1] = 1, [2] = 2.1, [k2] = test}', {1, 2.1, k2='test'}},
      {'%s', 'true', true},
    }

    for _,c in ipairs(cases) do
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
end)