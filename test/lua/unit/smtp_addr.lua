-- SMTP address parser tests

context("SMTP address check functions", function()
  local logger = require("rspamd_logger")
  local ffi = require("ffi")
  require "fun" ()
  ffi.cdef[[
  struct rspamd_email_address {
    const char *raw;
    const char *addr;
    const char *user;
    const char *domain;
    const char *name;

    unsigned raw_len;
    unsigned addr_len;
    unsigned user_len;
    unsigned domain_len;
    unsigned name_len;
    int flags;
  };
  struct rspamd_email_address * rspamd_email_address_from_smtp (const char *str, unsigned len);
  void rspamd_email_address_unref (struct rspamd_email_address *addr);
  ]]

  test("Parse addrs", function()
    local cases_valid = {
      {'<>', {addr = ''}},
      {'<a@example.com>', {user = 'a', domain = 'example.com', addr = 'a@example.com'}},
      {'a@example.com', {user = 'a', domain = 'example.com', addr = 'a@example.com'}},
      {'a+b@example.com', {user = 'a+b', domain = 'example.com', addr = 'a+b@example.com'}},
      {'"a"@example.com', {user = 'a', domain = 'example.com', addr = 'a@example.com'}},
      {'"a+b"@example.com', {user = 'a+b', domain = 'example.com', addr = 'a+b@example.com'}},
    }

    each(function(case)
      local st = ffi.C.rspamd_email_address_from_smtp(case[1], #case[1])

      assert_not_nil(st, "cannot parse " .. case[1])

      each(function(k, ex)
        if k == 'user' then
          local str = ffi.string(st.user, st.user_len)
          assert_equal(str, ex)
        elseif k == 'domain' then
          local str = ffi.string(st.domain, st.domain_len)
          assert_equal(str, ex)
        elseif k == 'addr' then
          local str = ffi.string(st.addr, st.addr_len)
          assert_equal(str, ex)
        end
      end, case[2])
      ffi.C.rspamd_email_address_unref(st)
    end, cases_valid)
  end)
end)
