-- inet addr tests

context("Inet addr check functions", function()
  local ffi = require("ffi")

  ffi.cdef[[
  typedef struct rspamd_inet_addr_s rspamd_inet_addr_t;
  bool rspamd_parse_inet_address (rspamd_inet_addr_t **target,
    const char *src, size_t len);
  void rspamd_inet_address_free (rspamd_inet_addr_t *addr);
  ]]

  local cases = {
    {'192.168.1.1', true},
    {'2a01:4f8:190:43b5::99', true},
    {'256.1.1.1', false},
    {'/tmp/socket', true},
    {'./socket', true},
    {'[fe80::f919:8b26:ff93:3092%5]', true},
    {'[fe80::f919:8b26:ff93:3092]', true},
    {'IPv6:::1', true},
    {'IPv6:[::1]', true},
    {'IPv6[:::1]', false},
    {'[::]', true},
    {'[1::]', true},
    {'[000:01:02:003:004:5:6:007]', true}, -- leading zeros
    {'[A:b:c:DE:fF:0:1:aC]', true}, -- mixed case
    {'[::192.168.0.1]', true}, -- embedded ipv4
    {'[1:2:192.168.0.1:5:6]', false}, -- poor octets
    {'[::ffff:192.1.2]', false}, -- ipv4 without last octet (maybe should be true?)
    {'[0:0::0:0:8]', true}, -- bogus zeros
    {'[::192.168.0.0.1]', false}, -- invalid mapping
  }

  for i,c in ipairs(cases) do
    test("Create inet addr from string " .. c[1] .. '; expect ' .. tostring(c[2]), function()
      local ip = ffi.new("rspamd_inet_addr_t* [1]");
      local res = ffi.C.rspamd_parse_inet_address(ip, c[1], #c[1])
      assert_equal(res, c[2], "Expect " .. tostring(c[2]) .. " while parsing " .. c[1])
      if res then
        ffi.C.rspamd_inet_address_free(ip[0])
      end
    end)

  end
end)