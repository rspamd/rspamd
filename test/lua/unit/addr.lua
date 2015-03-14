-- inet addr tests

context("Inet addr check functions", function()
  local ffi = require("ffi")
  
  ffi.cdef[[
  typedef struct rspamd_inet_addr_s rspamd_inet_addr_t;
  bool rspamd_parse_inet_address (rspamd_inet_addr_t **target,
    const char *src);
  void rspamd_inet_address_destroy (rspamd_inet_addr_t *addr);
  ]]
  
  test("Create inet addr from string", function()
    local cases = {
      {'192.168.1.1', true},
      {'2a01:4f8:190:43b5::99', true},
      {'256.1.1.1', false},
      {'/tmp/socket', true},
      {'./socket', true},
    }
    
    for _,c in ipairs(cases) do
      local ip = ffi.new("rspamd_inet_addr_t* [1]");
      local res = ffi.C.rspamd_parse_inet_address(ip, c[1])
      assert_equal(res, c[2], "Expect " .. tostring(c[2]) .. " while parsing " .. c[1])
      if res then
        ffi.C.rspamd_inet_address_destroy(ip[0])
      end
    end
  end)
end)