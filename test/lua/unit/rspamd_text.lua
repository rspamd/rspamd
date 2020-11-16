context("Rspamd_text:byte() test", function()
  local lua_util = require "lua_util"
  local rspamd_text = require "rspamd_text"

  local str = 'OMG'
  local txt = rspamd_text.fromstring(str)
  local fmt = 'case rspamd_text:byte(%s,%s)'
  local cases = {
    {'1', 'nil'},
    {'nil', '1'},
  }

  for start = -4, 4 do
    for stop = -4, 4 do
      table.insert(cases, {tostring(start), tostring(stop)})
    end
  end

  for _, case in ipairs(cases) do
    local name = string.format(fmt, case[1], case[2])
    test(name, function()
      local txt_bytes = {txt:byte(tonumber(case[1]), tonumber(case[2]))}
      local str_bytes = {str:byte(tonumber(case[1]), tonumber(case[2]))}
      assert_rspamd_table_eq({
        expect = str_bytes,
        actual = txt_bytes
      })
    end)
  end
end)
