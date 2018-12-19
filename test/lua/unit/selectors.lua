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
                expect = {"c459a21bd1f33fb4ba035481f46ef0c7"}},

    ["user"] = {
                selector = "user",
                expect = {"cool user name"}},

    ["from"] = {
                selector = "from",
                expect = {"whoknows@nowhere.com"}},

    ["rcpts"] = {
                selector = "rcpts",
                expect = {{"nobody@example.com", "no-one@example.com"}}},

    ["1st rcpts"] = {
                selector = "rcpts.nth(1)",
                expect = {"nobody@example.com"}},

    ["lower rcpts"] = {
                selector = "rcpts.lower.first",
                expect = {"nobody@example.com"}},

    ["first rcpts"] = {
                selector = "rcpts.first",
                expect = {"nobody@example.com"}},

    ["first addr rcpts"] = {
                selector = "rcpts:addr.first",
                expect = {"nobody@example.com"}},

    ["to"] = {
                selector = "to",
                expect = {"nobody@example.com"}},

    ["attachments"] = {
                selector = "attachments",
                expect = {{"ce112d07c52ae649f9646f3d0b5aaab5d4834836d771c032d1a75059d31fed84f38e00c0b205918f6d354934c2055d33d19d045f783a62561f467728ebcf0160",
                          "ce112d07c52ae649f9646f3d0b5aaab5d4834836d771c032d1a75059d31fed84f38e00c0b205918f6d354934c2055d33d19d045f783a62561f467728ebcf0160"
                          }}},

    ["attachments id"] = {
                selector = "attachments.id",
                expect = {""}},

    ["files"] = {
                selector = "files",
                expect = {{"f.zip", "f2.zip"}}},

    ["helo"] = {
                selector = "helo",
                expect = {"hello mail"}},

    ["received by hostname"] = {
                selector = "received:by_hostname",
                expect = {{"server.chat-met-vreemden.nl"}}},

    ["urls"] = {
                selector = "urls",
                expect = {{"http://example.net"}}},

    ["emails"] = {
                selector = "emails",
                expect = {{"mailto://test@example.net"}}},

    ["pool_var str, default type"] = {
                selector = [[pool_var("str_var")]],
                expect = {"str 1"}},

    ["pool_var str"] = {
                selector = [[pool_var("str_var", 'string')]],
                expect = {"str 1"}},

    ["pool_var double"] = {
                selector = [[pool_var("int_var", 'double')]],
                expect = {"1"}},

    ["time"] = {
                selector = "time",
                expect = {"1537364211"}},

    ["request_header"] = {
                selector = "request_header(hdr1)",
                expect = {"value1"}},

    ["get_host"] = {
                selector = "urls:get_host",
                expect = {{"example.net"}}},

    ["get_tld"] = {
                selector = "urls:get_tld",
                expect = {{"example.net"}}},

    ["transformation regexp"] = {
                selector = "urls:get_tld.regexp('\\.([\\w]+)$')",
                expect = {{{".net", "net"}}}},

    ["transformation id"] = {
                selector = "urls:get_tld.id",
                expect = {''}},

    ["transformation id arg"] = {
                selector = "urls:get_tld.id('1')",
                expect = {'1'}},

    ["transformation id args"] = {
                selector = "urls:get_tld.id('1', '2', '3')",
                expect = {{'1', '2', '3'}}},

    ["transformation in"] = {
                selector = "time(message, '!%w').in(2,3,4)",
                expect = {'3'}},

    ["transformation in id"] = {
                selector = "time(message, '!%w').in(2,3,4).id",
                expect = {''}},

    ["transformation not in"] = {
                selector = "time(message, '!%w').not_in(1,6,7)",
                expect = {'3'}},

    ["transformation in not id"] = {
                selector = "time(message, '!%w').not_in(1,6,7).id",
                expect = {''}},

    ["transformation in not id 1"] = {
                selector = "time(message, '!%w').not_in(1,6,7).id(1)",
                expect = {'1'}},

    ["transformation take"] = {
                selector = "rcpts.take_n(1).lower",
                expect = {{'nobody@example.com'}}},

    ["transformation take 2"] = {
                selector = "rcpts.take_n(2).lower",
                expect = {{'nobody@example.com', 'no-one@example.com'}}},

    ["transformation take 3"] = {
                selector = "rcpts.take_n(3).lower",
                expect = {{'nobody@example.com', 'no-one@example.com'}}},

    ["transformation nth"] = {
                selector = "rcpts.nth(1).lower",
                expect = {'nobody@example.com'}},

    ["transformation nth 2"] = {
                selector = "rcpts.nth(2).lower",
                expect = {'no-one@example.com'}},

    ["transformation substring"] = {
                selector = "header(Subject, strong).substring(6)",
                expect = {'subject'}},

    ["transformation substring 2"] = {
                selector = "header(Subject, strong).substring(6, 7)",
                expect = {'su'}},

    ["transformation substring -4"] = {
                selector = "header(Subject, strong).substring(-4)",
                expect = {'ject'}},
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
