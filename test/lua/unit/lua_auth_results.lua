-- Tests for lua_auth_results module (AAR parsing)
context("Lua auth results - AAR parsing", function()
  local lua_auth_results = require "lua_auth_results"

  -- parse_ar_element tests
  context("parse_ar_element", function()
    test("simple dkim=pass", function()
      local r = lua_auth_results.parse_ar_element("dkim=pass header.d=example.com header.s=sel")
      assert_not_nil(r)
      assert_equal("pass", r.dkim)
      assert_equal("example.com", r["header.d"])
      assert_equal("sel", r["header.s"])
    end)

    test("spf with comment", function()
      local r = lua_auth_results.parse_ar_element(
        'spf=pass (mx.example.com: domain of user@example.com designates 1.2.3.4) smtp.mailfrom=user@example.com')
      assert_not_nil(r)
      assert_equal("pass", r.spf)
      assert_equal("user@example.com", r["smtp.mailfrom"])
    end)

    test("dmarc with comment and quoted", function()
      local r = lua_auth_results.parse_ar_element('dmarc=pass (policy=none) header.from=example.com')
      assert_not_nil(r)
      assert_equal("pass", r.dmarc)
      assert_equal("example.com", r["header.from"])
    end)

    test("arc with nested parens containing i=N", function()
      local r = lua_auth_results.parse_ar_element(
        'arc=pass ("mail.example.com:s=selector1:i=2")')
      assert_not_nil(r)
      assert_equal("pass", r.arc)
    end)

    test("authserv-id without equals returns nil", function()
      local r = lua_auth_results.parse_ar_element("mail.example.com")
      assert_nil(r)
    end)
  end)

  -- parse_aar_header tests
  context("parse_aar_header", function()
    test("basic AAR with dkim and spf", function()
      local r = lua_auth_results.parse_aar_header(
        "i=1; mx.example.com; dkim=pass header.d=example.com; spf=pass smtp.mailfrom=user@example.com")
      assert_not_nil(r)
      assert_equal("1", r.i)
      assert_not_nil(r.ar)
      assert_equal(2, #r.ar)
      assert_equal("pass", r.ar[1].dkim)
      assert_equal("example.com", r.ar[1]["header.d"])
      assert_equal("pass", r.ar[2].spf)
    end)

    test("AAR with comment containing i=N (#5963)", function()
      local r = lua_auth_results.parse_aar_header(
        'i=3; mx.example.com; arc=pass ("mail.example.com:s=selector1:i=2"); dkim=pass header.d=example.com')
      assert_not_nil(r)
      assert_equal("3", r.i)
      assert_not_nil(r.ar)
      assert_equal(2, #r.ar)
      assert_equal("pass", r.ar[1].arc)
      assert_equal("pass", r.ar[2].dkim)
    end)

    test("AAR with semicolon inside comment does not split incorrectly", function()
      local r = lua_auth_results.parse_aar_header(
        'i=2; mx.example.com; spf=pass (something; tricky) smtp.mailfrom=user@example.com')
      assert_not_nil(r)
      assert_equal("2", r.i)
      assert_not_nil(r.ar)
      assert_equal(1, #r.ar)
      assert_equal("pass", r.ar[1].spf)
      assert_equal("user@example.com", r.ar[1]["smtp.mailfrom"])
    end)

    test("AAR with semicolon inside quoted string does not split", function()
      -- The split respects quotes so "foo;bar" stays in one element.
      -- Note: parse_ar_element cannot consume key="quoted" pairs, so
      -- properties after reason="..." are lost.  The important thing is
      -- the semicolon inside quotes does not create a spurious element.
      local r = lua_auth_results.parse_aar_header(
        'i=1; mx.example.com; dkim=pass reason="foo;bar" header.d=example.com')
      assert_not_nil(r)
      assert_equal("1", r.i)
      assert_not_nil(r.ar)
      assert_equal(1, #r.ar)
      assert_equal("pass", r.ar[1].dkim)
    end)

    test("AAR with nested parentheses", function()
      local r = lua_auth_results.parse_aar_header(
        'i=1; mx.example.com; dmarc=pass (policy=none (nested)) header.from=example.com')
      assert_not_nil(r)
      assert_equal("1", r.i)
      assert_not_nil(r.ar)
      assert_equal(1, #r.ar)
      assert_equal("pass", r.ar[1].dmarc)
      assert_equal("example.com", r.ar[1]["header.from"])
    end)

    test("AAR with only i= and authserv-id", function()
      local r = lua_auth_results.parse_aar_header("i=1; mx.example.com; none")
      assert_not_nil(r)
      assert_equal("1", r.i)
      -- ar may be nil or empty since "none" has no '='
    end)

    test("empty string returns nil", function()
      local r = lua_auth_results.parse_aar_header("")
      assert_nil(r)
    end)

    test("multiple dmarc and spf results", function()
      local r = lua_auth_results.parse_aar_header(
        "i=2; mx.example.com; dkim=pass header.d=a.com; spf=fail smtp.mailfrom=b.com; dmarc=pass header.from=a.com")
      assert_not_nil(r)
      assert_equal("2", r.i)
      assert_not_nil(r.ar)
      assert_equal(3, #r.ar)
      assert_equal("pass", r.ar[1].dkim)
      assert_equal("fail", r.ar[2].spf)
      assert_equal("pass", r.ar[3].dmarc)
    end)

    test("real-world multi-hop AAR from issue #5963", function()
      -- This is the exact scenario: rspamd generates arc=pass ("domain:s=sel:i=2")
      -- which previously broke the i=N extraction
      local r = lua_auth_results.parse_aar_header(
        'i=4; mx.example.com; arc=pass ("mx.example.com:s=arc-20220101:i=3"); '
        .. 'dkim=pass header.d=example.com header.s=mail header.b=abc123; '
        .. 'spf=pass (mx.example.com: domain of sender@example.com designates 1.2.3.4 as permitted sender) smtp.mailfrom=sender@example.com; '
        .. 'dmarc=pass (policy=reject) header.from=example.com')
      assert_not_nil(r)
      assert_equal("4", r.i)
      assert_not_nil(r.ar)
      assert_equal(4, #r.ar)
      assert_equal("pass", r.ar[1].arc)
      assert_equal("pass", r.ar[2].dkim)
      assert_equal("pass", r.ar[3].spf)
      assert_equal("pass", r.ar[4].dmarc)
      assert_equal("example.com", r.ar[4]["header.from"])
    end)
  end)
end)
