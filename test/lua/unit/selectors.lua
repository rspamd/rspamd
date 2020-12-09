local msg
context("Selectors test", function()
  local rspamd_task = require "rspamd_task"
  local logger = require "rspamd_logger"
  local lua_selectors = require "lua_selectors"
  local lua_maps = require "lua_maps"
  local test_helper = require "rspamd_test_helper"
  local lua_util = require "lua_util"
  local cfg = rspamd_config
  local task

  test_helper.init_url_parser()

  lua_selectors.maps.test_map = lua_maps.map_add_from_ucl({
    'key value',
    'key1 value1',
    'key3 value1',
  }, 'hash', 'test selectors maps')

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
    task:cache_set('cachevar1', 'hello\x00world')
    task:cache_set('cachevar2', {'hello', 'world'})
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
                expect = {"198.172.22.91"}
    },

    ["header Subject"] = {
                selector = "header(Subject)",
                expect = {"Second, lower-cased header subject"}
    },

    ["header Subject lower"] = {
                selector = "header(Subject).lower",
                expect = {"second, lower-cased header subject"}},

    ["header full Subject lower"] = {
                selector = "header(Subject, 'full').lower",
                expect = {{"second, lower-cased header subject", "test subject"}}
    },

    ["header full strong Subject"] = {
                selector = "header(Subject, 'full,strong')",
                expect = {{"Test subject"}}
    },

    ["header full strong lower-cased Subject"] = {
                selector = "header(subject, 'full,strong')",
                expect = {{"Second, lower-cased header subject"}}
    },

    ["digest"] = {
                selector = "digest",
                expect = {"1ac109c58a7d0f5f532100ac14e9f4d9"}
    },

    ["user"] = {
                selector = "user",
                expect = {"cool user name"}
    },

    ["from"] = {
                selector = "from",
                expect = {"whoknows@nowhere.com"}
    },

    ["rcpts"] = {
                selector = "rcpts",
                expect = {{"nobody@example.com", "no-one@example.com"}}
    },

    ["1st rcpts"] = {
                selector = "rcpts.nth(1)",
                expect = {"nobody@example.com"}
    },

    ["lower rcpts"] = {
                selector = "rcpts.lower.first",
                expect = {"nobody@example.com"}
    },

    ["first rcpts"] = {
                selector = "rcpts.first",
                expect = {"nobody@example.com"}
    },

    ["first addr rcpts"] = {
                selector = "rcpts:addr.first",
                expect = {"nobody@example.com"}
    },

    ["rcpts_uniq_domains"] = {
      selector = "rcpts:domain.uniq",
      expect = {{"example.com"}}
    },

    ["rcpts_sorted"] = {
      selector = "rcpts:addr.sort",
      expect = {{"nobody@example.com", "no-one@example.com"}}
    },

    ["to"] = {
      selector = "to",
      expect = {"nobody@example.com"}},

    ["attachments"] = {
      selector = "attachments",
      expect = {{"ce112d07c52ae649f9646f3d0b5aaab5d4834836d771c032d1a75059d31fed84f38e00c0b205918f6d354934c2055d33d19d045f783a62561f467728ebcf0160",
                 "ce112d07c52ae649f9646f3d0b5aaab5d4834836d771c032d1a75059d31fed84f38e00c0b205918f6d354934c2055d33d19d045f783a62561f467728ebcf0160"
                }}
    },

    ["attachments blake2 base32"] = {
      selector = "attachments('base32', 'blake2')",
      expect = {{"qqr41dwakt3uwhucxmxsypjiifi8er3gzqhyc3r48fw1ij9dp8b8x8nyyscmoe6tpmp1r4eafezguezurazo87ecs48cw5bfm9udyob",
                 "qqr41dwakt3uwhucxmxsypjiifi8er3gzqhyc3r48fw1ij9dp8b8x8nyyscmoe6tpmp1r4eafezguezurazo87ecs48cw5bfm9udyob"
                }}
    },

    ["attachments blake2 base64"] = {
      selector = "attachments('base64', 'blake2')",
      expect = {{"zhEtB8Uq5kn5ZG89C1qqtdSDSDbXccAy0adQWdMf7YTzjgDAsgWRj201STTCBV0z0Z0EX3g6YlYfRnco688BYA==",
                 "zhEtB8Uq5kn5ZG89C1qqtdSDSDbXccAy0adQWdMf7YTzjgDAsgWRj201STTCBV0z0Z0EX3g6YlYfRnco688BYA=="
                }}
    },

    ["attachments blake2 rfc base32"] = {
      selector = "attachments('rbase32', 'blake2')",
      expect = {{"ZYIS2B6FFLTET6LEN46QWWVKWXKIGSBW25Y4AMWRU5IFTUY75WCPHDQAYCZALEMPNU2USNGCAVOTHUM5ARPXQOTCKYPUM5ZI5PHQCYA",
                 "ZYIS2B6FFLTET6LEN46QWWVKWXKIGSBW25Y4AMWRU5IFTUY75WCPHDQAYCZALEMPNU2USNGCAVOTHUM5ARPXQOTCKYPUM5ZI5PHQCYA"
                }}
    },

    ["attachments md5 rfc base32"] = {
      selector = "attachments('rbase32', 'md5')",
      expect = {{"LYXF2IMILRFFO4LLTDTM66MKEA",
                 "LYXF2IMILRFFO4LLTDTM66MKEA"
                }}
    },

    ["attachments id"] = {
                selector = "attachments.id",
                expect = {""}},

    ["files"] = {
                selector = "files",
                expect = {{"f.zip", "f2.zip"}}},

    ["helo"] = {
                selector = "helo",
                expect = {"hello mail"}},

    ["received ip"] = {
                selector = "received:by_hostname.filter_string_nils",
                expect = {{"server1.chat-met-vreemden.nl", "server2.chat-met-vreemden.nl"}}},

    ["received by hostname last"] = {
      selector = "received:by_hostname.filter_string_nils.last",
      expect = {"server2.chat-met-vreemden.nl"}
    },

    ["received by hostname first"] = {
      selector = "received:by_hostname.filter_string_nils.first",
      expect = {"server1.chat-met-vreemden.nl"}
    },

    ["urls"] = {
                selector = "urls",
                expect = {{"http://subdomain.example.net"}}},

    ["emails"] = {
                selector = "emails",
                expect = {{"test@example.net"}}},

    ["specific_urls"] = {
      selector = "specific_urls({limit = 1})",
      expect = {{"http://subdomain.example.net"}}},

    ["specific_urls + emails"] = {
      selector = "specific_urls({need_emails = true, limit = 2})",
      expect = {{"test@example.net", "http://subdomain.example.net"}}},

    ["specific_urls + emails limit"] = {
      selector = "specific_urls({need_emails = true, limit = 1})",
      expect = {{"test@example.net"}}},

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

--    ["request_header"] = {
--                selector = "request_header(hdr1)",
--                expect = {"value1"}},

    ["get_host"] = {
                selector = "urls:get_host",
                expect = {{"subdomain.example.net"}}},

    ["get_tld_method"] = {
                selector = "urls:get_tld",
                expect = {{"example.net"}}},
    ["get_tld_transform"] = {
      selector = "urls:get_host.get_tld",
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

    ["transformation last"] = {
      selector = "rcpts.last.lower",
      expect = {'no-one@example.com'}},

    ["transformation substring"] = {
                selector = "header(Subject, strong).substring(6)",
                expect = {'subject'}},

    ["transformation substring 2"] = {
                selector = "header(Subject, strong).substring(6, 7)",
                expect = {'su'}},

    ["transformation substring -4"] = {
                selector = "header(Subject, strong).substring(-4)",
                expect = {'ject'}
    },
    ["map filter"] = {
      selector = "id('key').filter_map(test_map)",
      expect = {'key'}
    },
    ["map except"] = {
      selector = "list('key', 'key1', 'key2', 'key3', 'key4').except_map(test_map)",
      expect = {{'key2', 'key4'}}
    },
    ["map apply"] = {
      selector = "id('key').apply_map(test_map)",
      expect = {'value'}
    },
    ["map filter list"] = {
      selector = "list('key', 'key1', 'key2').filter_map(test_map)",
      expect = {{'key', 'key1'}}
    },
    ["map apply list"] = {
      selector = "list('key', 'key1', 'key2', 'key3').apply_map(test_map)",
      expect = {{'value', 'value1', 'value1'}}
    },
    ["map apply list uniq"] = {
      selector = "list('key', 'key1', 'key2', 'key3').apply_map(test_map).uniq",
      expect = {{'value1', 'value'}}
    },
    ["words"] = {
      selector = "words('norm')",
      expect = {{'hello', 'world', 'mail', 'me'}}
    },
    ["words_full"] = {
      selector = "words('full'):2",
      expect = {{'hello', 'world', '', 'mail', 'me'}}
    },
    ["header X-Test first"] = {
      selector = "header(X-Test, full).first",
      expect = {"1"}
    },
    ["header X-Test last"] = {
      selector = "header(X-Test, full).last",
      expect = {"3"}
    },
    ["header lower digest substring"] = {
      selector = "header('Subject').lower.digest('hex').substring(1, 16)",
      expect = {"736ad5f50fc95d73"}
    },
    ["header gsub"] = {
      selector = "header('Subject'):gsub('a', 'b')",
      expect = {"Second, lower-cbsed hebder subject"}
    },
    ["header regexp first"] = {
      selector = "header('Subject').regexp('.*').first",
      expect = {"Second, lower-cased header subject"}
    },

    ["task cache string"] = {
      selector = "task_cache('cachevar1')",
      expect = {"hello\x00world"}
    },
    ["task cache table"] = {
      selector = "task_cache('cachevar2')",
      expect = {{"hello", "world"}}
    },
  }

  for case_name, case in lua_util.spairs(cases) do
    test("case " .. case_name, function()
      local elts = check_selector(case.selector)
      assert_not_nil(elts)
      assert_rspamd_table_eq_sorted({actual = elts, expect = case.expect})
    end)
  end
end)


--[=========[ *******************  message  ******************* ]=========]
msg = [[
Received: from ca-18-193-131.service1.infuturo.it ([151.18.193.131] helo=User)
    by server1.chat-met-vreemden.nl with esmtpa (Exim 4.76)
    (envelope-from <upwest201diana@outlook.com>)
    id 1ZC1sl-0006b4-TU; Mon, 06 Jul 2015 10:36:08 +0200
Received: from ca-18-193-131.service2.infuturo.it ([151.18.193.132] helo=User)
    by server2.chat-met-vreemden.nl with esmtpa (Exim 4.76)
    (envelope-from <upwest201diana@outlook.com>)
    id 1ZC1sl-0006b4-TU; Mon, 06 Jul 2015 10:36:08 +0200
From: <whoknows@nowhere.com>
To: <nobody@example.com>, <no-one@example.com>
Date: Wed, 19 Sep 2018 14:36:51 +0100 (BST)
subject: Second, lower-cased header subject
Subject: Test subject
X-Test: 1
X-Test: 2
X-Test: 3
Content-Type: multipart/alternative;
    boundary="_000_6be055295eab48a5af7ad4022f33e2d0_"

--_000_6be055295eab48a5af7ad4022f33e2d0_
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 7bit

Hello world


--_000_6be055295eab48a5af7ad4022f33e2d0_
Content-Type: text/html; charset="utf-8"

<html><body>
<a href="http://subdomain.example.net">http://subdomain.example.net</a>
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
