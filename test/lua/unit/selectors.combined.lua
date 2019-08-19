local msg
context("Selectors test", function()
  local rspamd_task = require "rspamd_task"
  local logger = require "rspamd_logger"
  local lua_selectors = require "lua_selectors"
  local test_helper = require "rspamd_test_helper"
  local cfg = rspamd_config
  local task

  test_helper.init_url_parser()

  before(function()
    local res
    res,task = rspamd_task.load_from_string(msg, cfg)
    task:set_from_ip("198.172.22.91")
    task:set_user("cool user name")
    task:set_helo("hello mail")
    task:set_request_header("hdr1", "value1")
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
    local res = lua_selectors.combine_selectors(task, elts, ':')
    return res
  end

  local cases = {
    ["rcpts + weekend"] = {
                selector = "rcpts:addr.take_n(5).lower;time('message', '!%w').in(6, 7).id('weekends')",
                expect = {
                  "nobody@example.com:weekends",
                  "no-one@example.com:weekends"}},

    ["weekend + rcpts"] = {
                selector = "time('message', '!%w').in(6, 7).id('weekends');rcpts:addr.take_n(5).lower",
                expect = {
                  "weekends:nobody@example.com",
                  "weekends:no-one@example.com"}},

    ["id(rcpt) + rcpts + weekend"] = {
                selector = "id('rcpt');rcpts:addr.take_n(5).lower;time('message', '!%w').in(6, 7).id('weekends')",
                expect = {
                  "rcpt:nobody@example.com:weekends",
                  "rcpt:no-one@example.com:weekends"}},

    ["id(rcpt) + id(2) rcpts + weekend"] = {
                selector = "id('rcpt'); id(2); rcpts:addr.take_n(5).lower; time('message', '!%w').in(6, 7).id('weekends')",
                expect = {
                  "rcpt:2:nobody@example.com:weekends",
                  "rcpt:2:no-one@example.com:weekends"}},

    -- There are two rcpts but only one url in the message
    -- resulting table size is the size of the smallest table
    ["id(rcpt) + id(2) + rcpts and urls + weekend"] = {
                selector = "id('rcpt'); id(2); rcpts:addr.take_n(5).lower; id('urls'); urls:get_host; time('message', '!%w').in(6, 7).id('weekends')",
                expect = {
                  "rcpt:2:nobody@example.com:urls:example.net:weekends"}},
  }

  for case_name, case in pairs(cases) do
    test("case " .. case_name, function()
      local elts = check_selector(case.selector)
      assert_not_nil(elts)
      assert_rspamd_table_eq({actual = elts, expect = case.expect})
    end)
  end
end)


--[=========[ *******************  message  ******************* ]=========]
msg = [[
Received: from ca-18-193-131.service.infuturo.it ([151.18.193.131] helo=User)
    by server.chat-met-vreemden.nl with esmtpa (Exim 4.76)
    (envelope-from <upwest201diana@outlook.com>)
    id 1ZC1sl-0006b4-TU; Mon, 06 Jul 2015 10:36:08 +0200
From: <whoknows@nowhere.com>
To: <nobody@example.com>, <no-one@example.com>
Date: Sat, 22 Sep 2018 14:36:51 +0100 (BST)
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
<a href="mailto:test@example.net">mail me</a>
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
