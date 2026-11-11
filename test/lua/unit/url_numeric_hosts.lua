-- Hosts that are addresses: the value reported is the one a browser goes to

context("URL numeric hosts", function()
  local rspamd_url = require "rspamd_url"
  local mpool = require "rspamd_mempool"
  local pool = mpool.create()

  -- { input, url, host, obscured }
  local cases = {
    { "http://127.0.0.1/x", "http://127.0.0.1/x", "127.0.0.1", false },
    { "http://0.0.0.0/x", "http://0.0.0.0/x", "0.0.0.0", false },
    { "http://192.168.0.1./x", "http://192.168.0.1/x", "192.168.0.1", false },
    -- A leading zero is octal
    { "http://0177.0.0.1/x", "http://127.0.0.1/x", "127.0.0.1", true },
    { "http://010.010.010.010/", "http://8.8.8.8/", "8.8.8.8", true },
    { "http://017700000001/x", "http://127.0.0.1/x", "127.0.0.1", true },
    -- Not octal digits: decimal
    { "http://08.0.0.1/x", "http://8.0.0.1/x", "8.0.0.1", true },
    { "http://0x7f.1/x", "http://127.0.0.1/x", "127.0.0.1", true },
    { "http://0x7f.0x0.0x0.0x1/", "http://127.0.0.1/", "127.0.0.1", true },
    { "http://0X7F000001/x", "http://127.0.0.1/x", "127.0.0.1", true },
    { "http://2130706433/x", "http://127.0.0.1/x", "127.0.0.1", true },
    { "http://2130706433./x", "http://127.0.0.1/x", "127.0.0.1", true },
    -- The last number fills the remaining bytes
    { "http://127.1/x", "http://127.0.0.1/x", "127.0.0.1", true },
    { "http://1.2.3/x", "http://1.2.0.3/x", "1.2.0.3", true },
    { "http://1.2.65535/", "http://1.2.255.255/", "1.2.255.255", true },
    { "http://0/x", "http://0.0.0.0/x", "0.0.0.0", true },
    -- Leading zeroes of any length change nothing but the base
    { "http://" .. string.rep("0", 48) .. "127.0.0.1/x", "http://87.0.0.1/x", "87.0.0.1", true },
    { "http://0x" .. string.rep("0", 60) .. "7f000001/x", "http://127.0.0.1/x", "127.0.0.1", true },
    { "http://1.2.3.4:8080/p?q#f", "http://1.2.3.4:8080/p?q#f", "1.2.3.4", false },
    { "http://0x1.2.3.4:8080/p?q#f", "http://1.2.3.4:8080/p?q#f", "1.2.3.4", true },
    -- An IPv6 address keeps its brackets in the url
    { "http://[::1]/x", "http://[::1]/x", "::1", false },
    { "http://[2001:db8::1]:8080/p?q#f", "http://[2001:db8::1]:8080/p?q#f", "2001:db8::1", false },
    { "http://[::ffff:1.2.3.4]/", "http://[::ffff:1.2.3.4]/", "::ffff:1.2.3.4", false },
  }

  for _, c in ipairs(cases) do
    test("Numeric host: " .. c[1]:sub(1, 48), function()
      local u = rspamd_url.create(pool, c[1])
      assert_not_nil(u, "no url for " .. c[1])
      local t = u:to_table()
      assert_equal(c[2], tostring(u))
      assert_equal(c[3], t.host)
      assert_equal(c[3], t.tld)
      local flags = u:get_flags()
      assert_true(flags.numeric == true, "not numeric: " .. c[1])
      assert_equal(c[4], flags.obscured == true, "obscured flag of " .. c[1])
    end)
  end

  -- No address a browser accepts: the host stays as written
  for _, s in ipairs({ "http://256.1.1.1/x", "http://1.2.3.4.5/x", "http://1..2/x",
                       "http://4294967296/x", "http://1.2.3.256/x", "http://0x1g/x",
                       "http://1.256.3/x" }) do
    test("Not an address: " .. s, function()
      local u = rspamd_url.create(pool, s)
      if u then
        assert_nil(u:get_flags().numeric, tostring(u))
        assert_equal(s, tostring(u))
      end
    end)
  end
end)
