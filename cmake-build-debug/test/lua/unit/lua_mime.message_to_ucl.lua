
--[=========[ *******************  message  ******************* ]=========]
local cases = {
  { message = [[
Received: from mail0.mindspring.com (unknown [1.1.1.1])
	(using TLSv1.2 with cipher ECDHE-ECDSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.example.com (Postfix) with ESMTPS id 88A0C6B332
	for <example@example.com>; Wed, 24 Nov 2021 19:05:43 +0000 (GMT)
From: <>
To: <nobody@example.com>
Subject: test
Content-Type: multipart/alternative;
    boundary="_000_6be055295eab48a5af7ad4022f33e2d0_"

--_000_6be055295eab48a5af7ad4022f33e2d0_
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 7bit

Hello world


--_000_6be055295eab48a5af7ad4022f33e2d0_
Content-Type: text/html; charset="utf-8"

<html><body>
lol
</html>
]],
                  expected = [[{
    "parts": [
        {
            "type": "multipart/alternative",
            "multipart_boundary": "_000_6be055295eab48a5af7ad4022f33e2d0_",
            "size": 0,
            "headers": []
        },
        {
            "content": "Hello world\n\n\n",
            "size": 14,
            "type": "text/plain",
            "boundary": "_000_6be055295eab48a5af7ad4022f33e2d0_",
            "detected_type": "text/plain",
            "headers": [
                {
                    "order": 0,
                    "raw": "Content-Type: text/plain; charset=\"utf-8\"\n",
                    "empty_separator": false,
                    "value": "text/plain; charset=\"utf-8\"",
                    "separator": " ",
                    "decoded": "text/plain; charset=\"utf-8\"",
                    "name": "Content-Type",
                    "tab_separated": false
                },
                {
                    "order": 1,
                    "raw": "Content-Transfer-Encoding: 7bit\n",
                    "empty_separator": false,
                    "value": "7bit",
                    "separator": " ",
                    "decoded": "7bit",
                    "name": "Content-Transfer-Encoding",
                    "tab_separated": false
                }
            ]
        },
        {
            "content": "<html><body>\nlol\n</html>\n",
            "size": 25,
            "type": "text/html",
            "boundary": "_000_6be055295eab48a5af7ad4022f33e2d0_",
            "detected_type": "text/html",
            "headers": [
                {
                    "order": 0,
                    "raw": "Content-Type: text/html; charset=\"utf-8\"\n",
                    "empty_separator": false,
                    "value": "text/html; charset=\"utf-8\"",
                    "separator": " ",
                    "decoded": "text/html; charset=\"utf-8\"",
                    "name": "Content-Type",
                    "tab_separated": false
                }
            ]
        }
    ],
    "newlines": "lf",
    "digest": "043cf1a314d0a1af95951d6aec932faf",
    "envelope": {
        "recipients_smtp": [
            {
                "addr": "test1@example.com",
                "raw": "<test1@example.com>",
                "flags": {
                    "valid": true
                },
                "user": "test1",
                "name": "Test1",
                "domain": "example.com"
            },
            {
                "addr": "test2@example.com",
                "raw": "<test2@example.com>",
                "flags": {
                    "valid": true
                },
                "user": "test2",
                "name": "Test2",
                "domain": "example.com"
            }
        ],
        "from_smtp": {
            "addr": "test@example.com",
            "raw": "<test@example.com>",
            "flags": {
                "valid": true
            },
            "user": "test",
            "name": "Test",
            "domain": "example.com"
        },
        "helo": "hello mail",
        "from_ip": "198.172.22.91"
    },
    "size": 666,
    "headers": [
        {
            "order": 0,
            "raw": "Received: from mail0.mindspring.com (unknown [1.1.1.1])\n\t(using TLSv1.2 with cipher ECDHE-ECDSA-AES256-GCM-SHA384 (256/256 bits))\n\t(No client certificate requested)\n\tby mail.example.com (Postfix) with ESMTPS id 88A0C6B332\n\tfor <example@example.com>; Wed, 24 Nov 2021 19:05:43 +0000 (GMT)\n",
            "empty_separator": false,
            "value": "from mail0.mindspring.com (unknown [1.1.1.1]) (using TLSv1.2 with cipher ECDHE-ECDSA-AES256-GCM-SHA384 (256/256 bits)) (No client certificate requested) by mail.example.com (Postfix) with ESMTPS id 88A0C6B332 for <example@example.com>; Wed, 24 Nov 2021 19:05:43 +0000 (GMT)",
            "separator": " ",
            "decoded": "from mail0.mindspring.com (unknown [1.1.1.1]) (using TLSv1.2 with cipher ECDHE-ECDSA-AES256-GCM-SHA384 (256/256 bits)) (No client certificate requested) by mail.example.com (Postfix) with ESMTPS id 88A0C6B332 for <example@example.com>; Wed, 24 Nov 2021 19:05:43 +0000 (GMT)",
            "name": "Received",
            "tab_separated": false
        },
        {
            "order": 1,
            "raw": "From: <>\n",
            "empty_separator": false,
            "value": "<>",
            "separator": " ",
            "decoded": "<>",
            "name": "From",
            "tab_separated": false
        },
        {
            "order": 2,
            "raw": "To: <nobody@example.com>\n",
            "empty_separator": false,
            "value": "<nobody@example.com>",
            "separator": " ",
            "decoded": "<nobody@example.com>",
            "name": "To",
            "tab_separated": false
        },
        {
            "order": 3,
            "raw": "Subject: test\n",
            "empty_separator": false,
            "value": "test",
            "separator": " ",
            "decoded": "test",
            "name": "Subject",
            "tab_separated": false
        },
        {
            "order": 4,
            "raw": "Content-Type: multipart/alternative;\n    boundary=\"_000_6be055295eab48a5af7ad4022f33e2d0_\"\n",
            "empty_separator": false,
            "value": "multipart/alternative; boundary=\"_000_6be055295eab48a5af7ad4022f33e2d0_\"",
            "separator": " ",
            "decoded": "multipart/alternative; boundary=\"_000_6be055295eab48a5af7ad4022f33e2d0_\"",
            "name": "Content-Type",
            "tab_separated": false
        }
    ]
}]]
                },
  {
    message = [[
From: <>
Content-Type: multipart/mixed; boundary="-"

123
---
321

--
WBR yours
--
a
-----------------
b
------
c
-
d
--------
f
-----
]],
  expected = [[
{
    "parts": [
        {
            "type": "multipart/mixed",
            "multipart_boundary": "-",
            "size": 0,
            "headers": []
        },
        {
            "content": "--\nWBR yours\n--\na\n-----------------\nb\n------\nc\n-\nd\n--------\nf\n",
            "size": 62,
            "type": "text/plain",
            "boundary": "-",
            "detected_type": "text/plain",
            "headers": []
        }
    ],
    "newlines": "lf",
    "digest": "1a680eb7563f32a2fbf67cf45e90f045",
    "envelope": {
        "recipients_smtp": [
            {
                "addr": "test1@example.com",
                "raw": "<test1@example.com>",
                "flags": {
                    "valid": true
                },
                "user": "test1",
                "name": "Test1",
                "domain": "example.com"
            },
            {
                "addr": "test2@example.com",
                "raw": "<test2@example.com>",
                "flags": {
                    "valid": true
                },
                "user": "test2",
                "name": "Test2",
                "domain": "example.com"
            }
        ],
        "from_smtp": {
            "addr": "test@example.com",
            "raw": "<test@example.com>",
            "flags": {
                "valid": true
            },
            "user": "test",
            "name": "Test",
            "domain": "example.com"
        },
        "helo": "hello mail",
        "from_ip": "198.172.22.91"
    },
    "size": 135,
    "headers": [
        {
            "order": 0,
            "raw": "From: <>\n",
            "empty_separator": false,
            "value": "<>",
            "separator": " ",
            "decoded": "<>",
            "name": "From",
            "tab_separated": false
        },
        {
            "order": 1,
            "raw": "Content-Type: multipart/mixed; boundary=\"-\"\n",
            "empty_separator": false,
            "value": "multipart/mixed; boundary=\"-\"",
            "separator": " ",
            "decoded": "multipart/mixed; boundary=\"-\"",
            "name": "Content-Type",
            "tab_separated": false
        }
    ]
}]]
  }
}

context("Task piecewise split", function()
  local rspamd_task = require "rspamd_task"
  local rspamd_util = require "rspamd_util"
  local rspamd_test_helper = require "rspamd_test_helper"
  local lua_mime = require "lua_mime"
  local ucl = require "ucl"
  local rspamd_parsers = require "rspamd_parsers"

  rspamd_test_helper.init_url_parser()
  local cfg = rspamd_util.config_from_ucl(rspamd_test_helper.default_config(),
      "INIT_URL,INIT_LIBS,INIT_SYMCACHE,INIT_VALIDATE,INIT_PRELOAD_MAPS")

  for i,case in ipairs(cases) do
    test("Simple message split case " .. tostring(i), function()
      local res,task = rspamd_task.load_from_string(case.message, cfg)

      if not res or not task then
        assert_true(false, "failed to load message")
      end

      task:set_from('smtp', rspamd_parsers.parse_mail_address("Test <test@example.com>")[1])
      task:set_recipients('smtp', {
        rspamd_parsers.parse_mail_address("Test1 <test1@example.com>")[1],
        rspamd_parsers.parse_mail_address("Test2 <test2@example.com>")[1]
      }, 'rewrite')
      task:set_from_ip("198.172.22.91")
      task:set_user("cool user name")
      task:set_helo("hello mail")
      task:process_message()
      local parser = ucl.parser()
      local res = parser:parse_string(case.expected)
      assert_true(res)
      local expected = parser:get_object()
      local ucl_object = lua_mime.message_to_ucl(task, true)
      local schema = lua_mime.message_to_ucl_schema()
      assert_true(schema(ucl_object))
      assert_rspamd_table_eq({
        actual = ucl_object,
        expect = expected
      })
      task:destroy()
    end)
  end

end)