local msg
context("Selectors test", function()
  local rspamd_task = require "rspamd_task"
  local logger = require "rspamd_logger"
  local lua_selectors = require "lua_selectors"
  local ffi = require "ffi"
  local cfg = rspamd_config
  
  local task
  
  ffi.cdef[[
  void rspamd_url_init (const char *tld_file);
  unsigned ottery_rand_range(unsigned top);
  void rspamd_http_normalize_path_inplace(char *path, size_t len, size_t *nlen);
  ]]

  local test_dir = string.gsub(debug.getinfo(1).source, "^@(.+/)[^/]+$", "%1")

  ffi.C.rspamd_url_init(string.format('%s/%s', test_dir, "test_tld.dat"))

  before(function()
    local res
    res,task = rspamd_task.load_from_string(msg, cfg)
    task:set_from_ip("198.172.22.91")
    task:set_user("cool user name")
    task:set_helo("hello mail")
    task:process_message()
    task:get_mempool():set_variable("int_var", 1)
    task:get_mempool():set_variable("str_var", "str 1")
    if not res then
      assert_true(false, "failed to load message")
    end
  end)

  local function check_selector(selector_string)
    local sels = lua_selectors.parse_selector(cfg, selector_string)
    local elts = lua_selectors.process_selectors(task, sels)
    return elts
  end

  local cases = {
    ["ip"] = {
                selector = "ip", 
                expect = {"198.172.22.91"}},

    ["header Subject"] = {
                selector = "header(Subject)", 
                expect = {"Second, lower-cased header subject"}},

    ["header Subject lower"] = {
                selector = "header(Subject).lower", 
                expect = {"second, lower-cased header subject"}},

    ["header full Subject lower"] = {
                selector = "header(Subject, 'full').lower", 
                expect = {{"second, lower-cased header subject", "test subject"}}},

    ["header full strong Subject"] = {
                selector = "header(Subject, 'full,strong')", 
                expect = {{"Test subject"}}},

    ["header full strong lower-cased Subject"] = {
                selector = "header(subject, 'full,strong')", 
                expect = {{"Second, lower-cased header subject"}}},

    ["digest"] = {
                selector = "digest", 
                expect = {"4676b65106f41941d65ee21b5f3f37ec"}},

    ["user"] = {
                selector = "user", 
                expect = {"cool user name"}},

    ["from"] = {
                selector = "from", 
                expect = {"whoknows@nowhere.com"}},

    ["rcpts"] = {
                selector = "rcpts", 
                expect = {{"nobody@example.com", "no-one@example.com"}}},
--[[ not working so far
    ["1st rcpts"] = {
                selector = "rcpts.nth(1)", 
                expect = {"nobody@example.com"}},
]]
    ["to"] = {
                selector = "to", 
                expect = {"nobody@example.com"}},

    ["attachments"] = {
                selector = "attachments", 
                expect = {{"ce112d07c52ae649f9646f3d0b5aaab5d4834836d771c032d1a75059d31fed84f38e00c0b205918f6d354934c2055d33d19d045f783a62561f467728ebcf0160",
                          "ce112d07c52ae649f9646f3d0b5aaab5d4834836d771c032d1a75059d31fed84f38e00c0b205918f6d354934c2055d33d19d045f783a62561f467728ebcf0160"
                          }}},

--[[ not working
    ["attachments id"] = {
                selector = "attachments.id", 
                expect = {""}},
]]
    ["files"] = {
                selector = "files", 
                expect = {{"f.zip", "f2.zip"}}},

    ["helo"] = {
                selector = "helo", 
                expect = {"hello mail"}},

--[[ not working:
Failed asserting that 
  (actual)   {[1] = {[1] = , [2] = , [3] = }} 
 equals to
  (expected) {[1] = hello mail}

    ["received"] = {
                selector = "received", 
                expect = {"hello mail"}},
]]

--[[ not working:
/Users/mgalanin/install/share/rspamd/lib/lua_selectors.lua:633: bad argument #1 to 'implicit_tostring' (table expected, got userdata)
stack traceback:
  [C]: in function 'implicit_tostring'
  install/share/rspamd/lib/lua_selectors.lua:633: in function 'fun'
  install/share/rspamd/lib/fun.lua:30: in function 'gen_x'
  install/share/rspamd/lib/fun.lua:778: in function 'totable'
  install/share/rspamd/lib/lua_selectors.lua:700: in function 'process_selector'
  install/share/rspamd/lib/lua_selectors.lua:860: in function 'process_selectors'
  build/test/lua/unit/selectors.lua:35: in function 'check_selector'
  build/test/lua/unit/selectors.lua:131: in function <build/test/lua/unit/selectors.lua:129>
    ["urls"] = {
                selector = "urls", 
                expect = {"hello mail"}},
]]

--[===[ not working
lua_selectors.lua:771: processed selector pool_var, args: nil

    ["pool_var"] = {
                selector = [[pool_var("str_var")]], 
                expect = {"hello mail"}},
]===]
    ["time"] = {
                selector = "time", 
                expect = {"1537364211"}},

  }
  
  local check_this_case = nil -- replace this with case name
  if check_this_case then
    cases = {[check_this_case] = cases[check_this_case]}
  end

  for case_name, case in pairs(cases) do
    test("case " .. case_name, function()
      -- local selector_string = [[ip;header(Subject, "full").lower;rcpts:addr.lower]]
      local elts = check_selector(case.selector)
      assert_not_nil(elts)
      assert_rspamd_table_eq({actual = elts, expect = case.expect})
    end)
  end
end)


--[=========[ *******************  message  ******************* ]=========]
msg = [[
Received: from server.chat-met-vreemden.nl (unknown [IPv6:2a01:7c8:aab6:26d:5054:ff:fed1:1da2])
    (using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
    (Client did not present a certificate)
    by mx1.freebsd.org (Postfix) with ESMTPS id CF0171862
    for <test@example.com>; Mon,  6 Jul 2015 09:01:20 +0000 (UTC)
    (envelope-from upwest201diana@outlook.com)
Received: from ca-18-193-131.service.infuturo.it ([151.18.193.131] helo=User)
    by server.chat-met-vreemden.nl with esmtpa (Exim 4.76)
    (envelope-from <upwest201diana@outlook.com>)
    id 1ZC1sl-0006b4-TU; Mon, 06 Jul 2015 10:36:08 +0200
From: <whoknows@nowhere.com>
To: <nobody@example.com>, <no-one@example.com>
Date: Wed, 19 Sep 2018 14:36:51 +0100 (BST)
subject: Second, lower-cased header subject
Subject: Test subject
Content-Type: multipart/alternative;
    boundary="_000_6be055295eab48a5af7ad4022f33e2d0_"

--_000_6be055295eab48a5af7ad4022f33e2d0_
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: base64

Hello world


--_000_6be055295eab48a5af7ad4022f33e2d0_
Content-Type: text/html; charset="utf-8"

<html><body>
<a href="http://example.net">http://example.net</a>
<a href="http://example1.net">http://example1.net</a>
<a href="http://example2.net">http://example2.net</a>
<a href="http://example3.net">http://example3.net</a>
<a href="http://example4.net">http://example4.net</a>
<a href="http://domain1.com">http://domain1.com</a>
<a href="http://domain2.com">http://domain2.com</a>
<a href="http://domain3.com">http://domain3.com</a>
<a href="http://domain4.com">http://domain4.com</a>
<a href="http://domain5.com">http://domain5.com</a>
<a href="http://domain.com">http://example.net/</a>
</html>


--_000_6be055295eab48a5af7ad4022f33e2d0_
Content-Type: application/zip; name=f.zip
Content-Disposition: attachment; size=166; filename=f.zip
Content-Transfer-Encoding: base64

UEsDBAoAAAAAAINe6kgAAAAAAAAAAAAAAAAIABwAZmFrZS5leGVVVAkAA8YaglfGGoJXdXgLAAEE
6AMAAAToAwAAUEsBAh4DCgAAAAAAg17qSAAAAAAAAAAAAAAAAAgAGAAAAAAAAAAAALSBAAAAAGZh
a2UuZXhlVVQFAAPGGoJXdXgLAAEE6AMAAAToAwAAUEsFBgAAAAABAAEATgAAAEIAAAAAAA==


--_000_6be055295eab48a5af7ad4022f33e2d0_
Content-Type: application/zip; name=f.zip
Content-Disposition: attachment; size=166; filename=f2.zip
Content-Transfer-Encoding: base64

UEsDBAoAAAAAAINe6kgAAAAAAAAAAAAAAAAIABwAZmFrZS5leGVVVAkAA8YaglfGGoJXdXgLAAEE
6AMAAAToAwAAUEsBAh4DCgAAAAAAg17qSAAAAAAAAAAAAAAAAAgAGAAAAAAAAAAAALSBAAAAAGZh
a2UuZXhlVVQFAAPGGoJXdXgLAAEE6AMAAAToAwAAUEsFBgAAAAABAAEATgAAAEIAAAAAAA==
]]