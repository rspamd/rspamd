-- Tests for lua_feedback_parsers module (DSN and ARF parsing)

context("Lua feedback parsers - pure helpers", function()
  local lua_feedback_parsers = require "lua_feedback_parsers"

  context("strip_angles", function()
    test("simple angle-bracketed id", function()
      assert_equal("abc@example.com",
        lua_feedback_parsers._strip_angles("<abc@example.com>"))
    end)

    test("with surrounding whitespace", function()
      assert_equal("abc@example.com",
        lua_feedback_parsers._strip_angles("  <abc@example.com>  "))
    end)

    test("no angles - returns trimmed input", function()
      assert_equal("abc@example.com",
        lua_feedback_parsers._strip_angles("  abc@example.com  "))
    end)

    test("nil input", function()
      assert_nil(lua_feedback_parsers._strip_angles(nil))
    end)
  end)

  context("parse_field_blocks", function()
    test("single block, simple fields", function()
      local body = "Reporting-MTA: dns; mta.example.com\r\n" ..
          "Arrival-Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
      local blocks = lua_feedback_parsers._parse_field_blocks(body)
      assert_equal(1, #blocks)
      assert_equal("dns; mta.example.com", blocks[1].fields["reporting-mta"])
      assert_equal("Mon, 01 Jan 2024 12:00:00 +0000",
        blocks[1].fields["arrival-date"])
    end)

    test("multiple blocks separated by blank lines", function()
      local body = "Reporting-MTA: dns; mta.example.com\n\n" ..
          "Final-Recipient: rfc822; user@example.com\n" ..
          "Action: failed\n" ..
          "Status: 5.1.1\n"
      local blocks = lua_feedback_parsers._parse_field_blocks(body)
      assert_equal(2, #blocks)
      assert_equal("dns; mta.example.com", blocks[1].fields["reporting-mta"])
      assert_equal("rfc822; user@example.com",
        blocks[2].fields["final-recipient"])
      assert_equal("failed", blocks[2].fields["action"])
      assert_equal("5.1.1", blocks[2].fields["status"])
    end)

    test("header folding (continuation lines)", function()
      local body = "Diagnostic-Code: smtp;\n" ..
          " 550 5.1.1 user unknown\n" ..
          "\tplease verify the address\n"
      local blocks = lua_feedback_parsers._parse_field_blocks(body)
      assert_equal(1, #blocks)
      assert_equal("smtp; 550 5.1.1 user unknown please verify the address",
        blocks[1].fields["diagnostic-code"])
    end)

    test("repeated fields collected in fields_multi", function()
      local body = "Reported-Uri: http://a.example/\n" ..
          "Reported-Uri: http://b.example/\n" ..
          "Reported-Uri: http://c.example/\n"
      local blocks = lua_feedback_parsers._parse_field_blocks(body)
      assert_equal(1, #blocks)
      local uris = blocks[1].fields_multi["reported-uri"]
      assert_not_nil(uris)
      assert_equal(3, #uris)
      assert_equal("http://a.example/", uris[1])
      assert_equal("http://b.example/", uris[2])
      assert_equal("http://c.example/", uris[3])
    end)

    test("empty body returns empty list", function()
      assert_equal(0, #lua_feedback_parsers._parse_field_blocks(""))
    end)

    test("CRLF normalisation", function()
      local body = "Feedback-Type: abuse\r\nVersion: 1\r\n"
      local blocks = lua_feedback_parsers._parse_field_blocks(body)
      assert_equal(1, #blocks)
      assert_equal("abuse", blocks[1].fields["feedback-type"])
      assert_equal("1", blocks[1].fields["version"])
    end)
  end)
end)

context("Lua feedback parsers - DSN/ARF on synthetic tasks", function()
  local rspamd_task = require "rspamd_task"
  local rspamd_util = require "rspamd_util"
  local rspamd_test_helper = require "rspamd_test_helper"
  local lua_feedback_parsers = require "lua_feedback_parsers"

  rspamd_test_helper.init_url_parser()
  local cfg = rspamd_util.config_from_ucl(rspamd_test_helper.default_config(),
    "INIT_URL,INIT_LIBS,INIT_SYMCACHE,INIT_VALIDATE,INIT_PRELOAD_MAPS")

  local function load_task(message)
    local res, task = rspamd_task.load_from_string(message, cfg)
    if not res or not task then
      return nil
    end
    task:process_message()
    return task
  end

  test("parse_dsn on RFC 3464 multipart/report", function()
    local message = "Return-Path: <>\r\n" ..
        "From: MAILER-DAEMON@mta.example.com\r\n" ..
        "To: sender@example.org\r\n" ..
        "Subject: Undelivered Mail Returned to Sender\r\n" ..
        "Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n" ..
        "Message-ID: <bounce-001@mta.example.com>\r\n" ..
        "MIME-Version: 1.0\r\n" ..
        "Content-Type: multipart/report; report-type=delivery-status; boundary=\"bnd0\"\r\n" ..
        "\r\n" ..
        "--bnd0\r\n" ..
        "Content-Type: text/plain; charset=us-ascii\r\n" ..
        "\r\n" ..
        "This is the mail system at mta.example.com.\r\n" ..
        "\r\n" ..
        "I'm sorry to have to inform you that your message could not be delivered.\r\n" ..
        "\r\n" ..
        "--bnd0\r\n" ..
        "Content-Type: message/delivery-status\r\n" ..
        "\r\n" ..
        "Reporting-MTA: dns; mta.example.com\r\n" ..
        "Arrival-Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n" ..
        "\r\n" ..
        "Final-Recipient: rfc822; user@bad.example.com\r\n" ..
        "Action: failed\r\n" ..
        "Status: 5.1.1\r\n" ..
        "Diagnostic-Code: smtp; 550 5.1.1 user unknown\r\n" ..
        "Remote-MTA: dns; mx.bad.example.com\r\n" ..
        "\r\n" ..
        "--bnd0\r\n" ..
        "Content-Type: message/rfc822\r\n" ..
        "\r\n" ..
        "From: sender@example.org\r\n" ..
        "To: user@bad.example.com\r\n" ..
        "Subject: Hi\r\n" ..
        "Date: Mon, 01 Jan 2024 11:59:00 +0000\r\n" ..
        "Message-ID: <orig-msg-001@example.org>\r\n" ..
        "\r\n" ..
        "Original message body.\r\n" ..
        "--bnd0--\r\n"

    local task = load_task(message)
    assert_not_nil(task, "failed to load DSN message")
    local dsn = lua_feedback_parsers.parse_dsn(task)
    assert_not_nil(dsn)
    assert_equal("dns; mta.example.com", dsn.reporting_mta)
    assert_equal("Mon, 01 Jan 2024 12:00:00 +0000", dsn.arrival_date)
    assert_equal(1, #dsn.recipients)
    assert_equal("rfc822; user@bad.example.com",
      dsn.recipients[1].final_recipient)
    assert_equal("failed", dsn.recipients[1].action)
    assert_equal("5.1.1", dsn.recipients[1].status)
    assert_equal("smtp; 550 5.1.1 user unknown",
      dsn.recipients[1].diagnostic_code)
    assert_equal("dns; mx.bad.example.com", dsn.recipients[1].remote_mta)
    assert_not_nil(dsn.original_message)
    assert_equal("orig-msg-001@example.org", dsn.original_message.message_id)
    assert_equal("sender@example.org", dsn.original_message.from)
    assert_equal("user@bad.example.com", dsn.original_message.to)
    assert_equal("Hi", dsn.original_message.subject)
    task:destroy()
  end)

  test("parse_dsn returns nil on non-DSN message", function()
    local message = "From: a@example.com\r\n" ..
        "To: b@example.com\r\n" ..
        "Subject: hello\r\n" ..
        "\r\n" ..
        "just a regular message\r\n"
    local task = load_task(message)
    assert_not_nil(task, "failed to load message")
    assert_nil(lua_feedback_parsers.parse_dsn(task))
    task:destroy()
  end)

  test("parse_arf on RFC 5965 feedback report", function()
    local message = "Return-Path: <abuse@isp.example>\r\n" ..
        "From: complaints@isp.example\r\n" ..
        "To: fbl@example.org\r\n" ..
        "Subject: FW: spam complaint\r\n" ..
        "Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n" ..
        "Message-ID: <fbl-001@isp.example>\r\n" ..
        "MIME-Version: 1.0\r\n" ..
        "Content-Type: multipart/report; report-type=feedback-report; boundary=\"bnd1\"\r\n" ..
        "\r\n" ..
        "--bnd1\r\n" ..
        "Content-Type: text/plain; charset=us-ascii\r\n" ..
        "\r\n" ..
        "This is an email abuse report for an email message received from\r\n" ..
        "IP 1.2.3.4 on Mon, 01 Jan 2024 11:55:00 +0000.\r\n" ..
        "\r\n" ..
        "--bnd1\r\n" ..
        "Content-Type: message/feedback-report\r\n" ..
        "\r\n" ..
        "Feedback-Type: abuse\r\n" ..
        "User-Agent: ISP-FBL/1.0\r\n" ..
        "Version: 1\r\n" ..
        "Original-Mail-From: <sender@example.org>\r\n" ..
        "Original-Rcpt-To: <user@isp.example>\r\n" ..
        "Arrival-Date: Mon, 01 Jan 2024 11:55:00 +0000\r\n" ..
        "Source-IP: 1.2.3.4\r\n" ..
        "Reported-Domain: example.org\r\n" ..
        "Reported-Uri: http://example.org/landing\r\n" ..
        "Reported-Uri: http://example.org/other\r\n" ..
        "\r\n" ..
        "--bnd1\r\n" ..
        "Content-Type: message/rfc822\r\n" ..
        "\r\n" ..
        "From: sender@example.org\r\n" ..
        "To: user@isp.example\r\n" ..
        "Subject: Newsletter\r\n" ..
        "Date: Mon, 01 Jan 2024 11:54:00 +0000\r\n" ..
        "Message-ID: <orig-fbl-001@example.org>\r\n" ..
        "\r\n" ..
        "body\r\n" ..
        "--bnd1--\r\n"

    local task = load_task(message)
    assert_not_nil(task, "failed to load ARF message")
    local arf = lua_feedback_parsers.parse_arf(task)
    assert_not_nil(arf)
    assert_equal("abuse", arf.feedback_type)
    assert_equal("1", arf.version)
    assert_equal("ISP-FBL/1.0", arf.user_agent)
    assert_equal("sender@example.org", arf.original_mail_from)
    assert_equal("user@isp.example", arf.original_rcpt_to)
    assert_equal("1.2.3.4", arf.source_ip)
    assert_equal("example.org", arf.reported_domain)
    assert_equal(2, #arf.reported_uri)
    assert_equal("http://example.org/landing", arf.reported_uri[1])
    assert_equal("http://example.org/other", arf.reported_uri[2])
    assert_not_nil(arf.original_message)
    assert_equal("orig-fbl-001@example.org", arf.original_message.message_id)
    assert_equal("sender@example.org", arf.original_message.from)
    task:destroy()
  end)

  test("parse_arf returns nil when report-type is not feedback-report", function()
    local message = "From: a@example.com\r\n" ..
        "To: b@example.com\r\n" ..
        "Subject: not a fbl\r\n" ..
        "MIME-Version: 1.0\r\n" ..
        "Content-Type: multipart/report; report-type=delivery-status; boundary=\"x\"\r\n" ..
        "\r\n" ..
        "--x\r\n" ..
        "Content-Type: text/plain\r\n" ..
        "\r\n" ..
        "stub\r\n" ..
        "--x--\r\n"
    local task = load_task(message)
    assert_not_nil(task, "failed to load message")
    assert_nil(lua_feedback_parsers.parse_arf(task))
    task:destroy()
  end)
end)
