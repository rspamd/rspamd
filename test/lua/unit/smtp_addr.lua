-- SMTP address parser tests

context("SMTP address check functions", function()
  local logger = require("rspamd_logger")
  local ffi = require("ffi")
  local util = require("rspamd_util")
  local fun = require "fun"
  ffi.cdef[[
  struct rspamd_email_address {
    const char *raw;
    const char *addr;
    const char *user;
    const char *domain;
    const char *name;

    unsigned raw_len;
    unsigned addr_len;
    unsigned domain_len;
    uint16_t user_len;
    unsigned char flags;
  };
  struct rspamd_email_address * rspamd_email_address_from_smtp (const char *str, unsigned len);
  void rspamd_email_address_free (struct rspamd_email_address *addr);
  ]]

  local cases_valid = {
    {'<>', {addr = ''}},
    {'<a@example.com>', {user = 'a', domain = 'example.com', addr = 'a@example.com'}},
    {'<a-b@example.com>', {user = 'a-b', domain = 'example.com', addr = 'a-b@example.com'}},
    {'<a-b@ex-ample.com>', {user = 'a-b', domain = 'ex-ample.com', addr = 'a-b@ex-ample.com'}},
    {'1367=dec2a6ce-81bd-4fa9-ad02-ec5956466c04=9=1655370@example.220-volt.ru',
     {user = '1367=dec2a6ce-81bd-4fa9-ad02-ec5956466c04=9=1655370',
      domain = 'example.220-volt.ru',
      addr = '1367=dec2a6ce-81bd-4fa9-ad02-ec5956466c04=9=1655370@example.220-volt.ru'}},
    {'notification+kjdm---m7wwd@facebookmail.com', {user = 'notification+kjdm---m7wwd'}},
    {'a@example.com', {user = 'a', domain = 'example.com', addr = 'a@example.com'}},
    {'a+b@example.com', {user = 'a+b', domain = 'example.com', addr = 'a+b@example.com'}},
    {'"a"@example.com', {user = 'a', domain = 'example.com', addr = 'a@example.com'}},
    {'"a+b"@example.com', {user = 'a+b', domain = 'example.com', addr = 'a+b@example.com'}},
    {'"<>"@example.com', {user = '<>', domain = 'example.com', addr = '<>@example.com'}},
    {'<"<>"@example.com>', {user = '<>', domain = 'example.com', addr = '<>@example.com'}},
    {'"\\""@example.com', {user = '"', domain = 'example.com', addr = '"@example.com'}},
    {'"\\"abc"@example.com', {user = '"abc', domain = 'example.com', addr = '"abc@example.com'}},
    {'<@domain1,@domain2,@domain3:abc@example.com>',
     {user = 'abc', domain = 'example.com', addr = 'abc@example.com'}},

  }


  fun.each(function(case)
    test("Parse valid smtp addr: " .. case[1], function()
      local st = ffi.C.rspamd_email_address_from_smtp(case[1], #case[1])

      assert_not_nil(st, "should be able to parse " .. case[1])

      fun.each(function(k, ex)
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
      ffi.C.rspamd_email_address_free(st)
    end)
  end, cases_valid)

    local cases_invalid = {
      'a',
      'a"b"@example.com',
      'a"@example.com',
      '"a@example.com',
      '<a@example.com',
      'a@example.com>',
      '<a@.example.com>',
      '<a@example.com>>',
      '<a@example.com><>',
    }

  fun.each(function(case)
    test("Parse invalid smtp addr: " .. case, function()
      local st = ffi.C.rspamd_email_address_from_smtp(case, #case)

      assert_nil(st, "should not be able to parse " .. case)
    end)
  end, cases_invalid)

  test("Speed test", function()
    local case = '<@domain1,@domain2,@domain3:abc%d@example.com>'
    local niter = 100000
    local total = 0

    for i = 1,niter do
      local ncase = string.format(case, i)
      local t1 = util.get_ticks()
      local st = ffi.C.rspamd_email_address_from_smtp(ncase, #ncase)
      local t2 = util.get_ticks()
      ffi.C.rspamd_email_address_free(st)
      total = total + t2 - t1
    end

    print(string.format('Spend %f seconds in processing addrs', total))
  end)
end)
