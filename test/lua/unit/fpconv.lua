-- fpconv tests

context("Fpconv printf functions", function()
  local ffi = require("ffi")
  local u = require "rspamd_util"
  local niter_fuzz = 100000
  local function small_double()
    return math.random()
  end
  local function large_double()
    return math.random() * math.random(2^52)
  end
  local function huge_double()
    return math.random(2^52) * math.random(2^52)
  end
  local function tiny_double()
    return math.random() / math.random(2^52)
  end
  ffi.cdef[[
int snprintf(char *str, size_t size, const char *format, ...);
long rspamd_snprintf(char *str, size_t size, const char *format, ...);
long rspamd_printf(const char *format, ...);
]]
  local benchmarks = {
    {'tiny fixed', small_double, '%f'},
    {'small fixed', tiny_double, '%f'},
    {'large fixed', large_double, '%.3f'},
    {'huge fixed', huge_double, '%.3f'},
    {'tiny scientific', small_double, '%g'},
    {'small scientific', tiny_double, '%g'},
    {'large scientific', large_double, '%g'},
    {'huge scientific', huge_double, '%g'},
  }

  local generic = {
    {0, '%f', '0'},
    {0, '%.1f', '0.0'},
    {0, '%.2f', '0.00'},
    {0, '%.32f', '0.000000000000000000000000000'}, -- max
    {0, '%.150f', '0.000000000000000000000000000'}, -- too large
    {1/3, '%f', '0.3333333333333333'},
    {1/3, '%.1f', '0.3'},
    {1/3, '%.2f', '0.33'},
    {-1/3, '%.32f', '-0.333333333333333300000000000'},
    {-1/3, '%.150f', '-0.333333333333333300000000000'},
    {-3.6817595395344857e-68, '%f', '-3.6817595395344857e-68'},
    {3.5844466002796428e+298, '%f', '3.5844466002796428e+298'},
    {9223372036854775808, '%f', '9223372036854776000'}, -- 2^63 with precision lost
    {2^50 + 0.2, '%f', '1125899906842624.3'}, -- 2^50 with precision lost
    {2^50 + 0.2, '%.2f', '1125899906842624.30'}, -- 2^50 with precision lost
    {-3.6817595395344857e-68, '%.3f', '-0.000'}, -- not enough precision
    {3.5844466002796428e+298, '%.3f', '3.5844466002796428e+298'},
    {9223372036854775808, '%.3f', '9223372036854776000.000'}, -- 2^63 with precision lost
    {math.huge, '%f', 'inf'},
    {-math.huge, '%f', '-inf'},
    {0.0/0.0, '%f', 'nan'},
    {math.huge, '%.1f', 'inf'},
    {-math.huge, '%.2f', '-inf'},
    {0.0/0.0, '%.3f', 'nan'},
    {math.huge, '%g', 'inf'},
    {-math.huge, '%g', '-inf'},
    {0.0/0.0, '%g', 'nan'},
  }

  local buf = ffi.new("char[64]")
  local buf2 = ffi.new("char[64]")

  for i,c in ipairs(generic) do
    test("Generic fp test fmt: " .. c[2] .. '; ' .. tostring(c[1]), function()
      ffi.C.rspamd_snprintf(buf, 64, c[2], c[1])
      local sbuf = ffi.string(buf)
      assert_equal(sbuf, c[3], c[3] .. " but test returned " .. sbuf)
    end)
  end
  for i,c in ipairs(benchmarks) do
    test("Fuzz fp test " .. c[1], function()
      for _=1,niter_fuzz do
        local sign = 1
        if math.random() > 0.5 then
          sign = -1
        end
        local d = c[2]() * sign
        ffi.C.snprintf(buf, 64, c[3], d)
        ffi.C.rspamd_snprintf(buf2, 64, c[3], d)

        local sbuf = ffi.string(buf)
        local sbuf2 = ffi.string(buf2)

        assert_less_than(math.abs(d -  tonumber(sbuf2))/math.abs(d),
            0.00001,
            string.format('rspamd emitted: %s, libc emitted: %s, original number: %g',
              sbuf2, sbuf, d))
      end
    end)
  end
end)