-- Telescope regression tests for DATE_FAR_FUTURE_NO_TZ.
-- Exercise the helper in the actual rules/misc.lua; do not modify production.
context("DATE_FAR_FUTURE_NO_TZ", function()
  local parser = require "rspamd_parsers"
  local source_path = os.getenv("RSPAMD_MISC_TEST_SOURCE") or "rules/misc.lua"
  local file, err = io.open(source_path, "rb")
  assert(file, "Cannot open " .. source_path .. ": " .. tostring(err))
  local source = file:read("*a")
  file:close()

  local begin_marker = "local function far_future_date_without_tz("
  local end_marker = "\nend\n\n-- Date issues"
  local first = assert(source:find(begin_marker, 1, true), "Helper not found in misc.lua")
  local last = assert(source:find(end_marker, first, true), "Helper ending not found in misc.lua")
  local snippet = source:sub(first, last + #("\nend") - 1)

  -- LuaJIT 2.1 uses loadstring + setfenv, unlike Lua 5.2+ load(..., env).
  local chunk, loaderr = loadstring(snippet .. "\nreturn far_future_date_without_tz",
                                    "patched-misc-date-function")
  assert(chunk, "Cannot compile helper: " .. tostring(loaderr))
  setfenv(chunk, {
    rspamd_parsers = parser, os = os, type = type,
    tonumber = tonumber, tostring = tostring, math = math,
    pairs = pairs,
  })
  local check = assert(chunk(), "Cannot load extracted helper")

  local function ts(s)
    local stamp, parse_err = parser.parse_smtp_date(s)
    assert(type(stamp) == "number",
           "Invalid reference timestamp: " .. s .. " / " .. tostring(parse_err))
    return stamp
  end

  local received = ts("Mon, 02 Nov 2026 19:47:52 -0300")
  local cases = {
    {"original future 10d", "Thu, 12 Nov 2026 19:47:48", received, true},
    {"valid future with timezone", "Thu, 12 Nov 2026 19:47:48 -0300", received, false},
    {"date close to receipt", "Mon, 02 Nov 2026 19:47:48", received, false},
    {"future by one day", "Tue, 03 Nov 2026 19:47:48", received, false},
    {"future without weekday", "12 Nov 2026 19:47:48", received, true},
    {"incorrect weekday", "Fri, 12 Nov 2026 19:47:48", received, false},
    {"invalid February 31", "Tue, 31 Feb 2027 19:47:48", received, false},
    {"invalid April 31", "Sat, 31 Apr 2027 19:47:48", received, false},
    {"invalid hour", "Thu, 12 Nov 2026 25:47:48", received, false},
    {"missing time", "Thu, 12 Nov 2026", received, false},
    {"not a Date header", "qualquer coisa", received, false},
    {"missing Date", nil, received, false},
    {"missing connection timestamp", "Thu, 12 Nov 2026 19:47:48", nil, false},
    {"valid leap day", "Sat, 29 Feb 2020 12:00:00",
      ts("Thu, 20 Feb 2020 12:00:00 +0000"), true},
    {"invalid leap day", "Mon, 29 Feb 2027 12:00:00",
      ts("Sat, 20 Feb 2027 12:00:00 +0000"), false},
    {"non-leap century", "Mon, 29 Feb 2100 12:00:00",
      ts("Sat, 20 Feb 2100 12:00:00 +0000"), false},
    {"exact guaranteed 48h threshold", "Thu, 12 Nov 2026 19:47:48",
      ts("Tue, 10 Nov 2026 05:47:48 +0000"), false},
    {"above guaranteed 48h threshold", "Thu, 12 Nov 2026 19:47:48",
      ts("Tue, 10 Nov 2026 05:47:47 +0000"), true},
  }

  for _, case in ipairs(cases) do
    test(case[1], function()
      local result = check(case[2], case[3])
      assert_rspamd_eq({expect = case[4], actual = result ~= nil})
    end)
  end
end)
