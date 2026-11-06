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

    test("method and result in any case, with a version", function()
      for _, elt in ipairs({ "DMARC=Pass Header.From=example.com", "dmarc/1=pass header.from=example.com",
                             "dmarc / 1 = pass (comment) header.from=example.com",
                             "(first) Dmarc=(why) PASS header.from=example.com" }) do
        local r = lua_auth_results.parse_ar_element(elt)
        assert_not_nil(r, elt)
        assert_equal("dmarc", r.method, elt)
        assert_equal("pass", r.dmarc, elt)
        assert_equal("example.com", r["header.from"], elt)
      end
    end)

    test("the result is the one of the method, not a pair after it", function()
      local r = lua_auth_results.parse_ar_element("dmarc=fail (x)dmarc=pass header.from=example.com")
      assert_not_nil(r)
      assert_equal("dmarc", r.method)
      assert_equal("fail", r.dmarc)
      r = lua_auth_results.parse_ar_element("spf=pass (x)dmarc=pass smtp.mailfrom=a@example.com")
      assert_equal("spf", r.method)
      assert_equal("pass", r.spf)
    end)

    test("a method property is no method", function()
      local r = lua_auth_results.parse_ar_element('"x" method=dmarc dmarc=pass header.from=example.com')
      assert_not_nil(r)
      assert_nil(r.method)
      r = lua_auth_results.parse_ar_element("method=dmarc dmarc=pass header.from=example.com")
      assert_equal("method", r.method)
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
      -- The split respects quotes so "foo;bar" stays in one element
      local r = lua_auth_results.parse_aar_header(
        'i=1; mx.example.com; dkim=pass reason="foo;bar" header.d=example.com')
      assert_not_nil(r)
      assert_equal("1", r.i)
      assert_not_nil(r.ar)
      assert_equal(1, #r.ar)
      assert_equal("pass", r.ar[1].dkim)
      assert_equal("foo;bar", r.ar[1].reason)
      assert_equal("example.com", r.ar[1]["header.d"])
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

    test("an empty element does not end the split", function()
      local r = lua_auth_results.parse_aar_header(
        "i=1; mx.example.com;; spf=pass smtp.helo=a; ; dmarc=fail header.from=example.com")
      assert_not_nil(r)
      assert_equal("1", r.i)
      assert_equal(2, #r.ar)
      assert_equal("pass", r.ar[1].spf)
      assert_equal("fail", r.ar[2].dmarc)
    end)

    test("a long run of blanks or escaped quotes is split in linear time", function()
      local t0 = os.clock()
      local r = lua_auth_results.parse_aar_header("i=1; mx.example; dmarc=" .. string.rep(" ", 4000) ..
          "pass header.from=example.com")
      assert_not_nil(r)
      assert_equal("pass", r.ar[1].dmarc)
      -- Longer ones give their instance only
      r = lua_auth_results.parse_aar_header("i=2; mx.example; dmarc=pass" .. string.rep('"\\', 30000))
      assert_equal("2", r.i)
      assert_nil(r.ar)
      assert_true(os.clock() - t0 < 1.0)
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

  -- Comments hold text of others, such as the SMTP sender: it must not add
  -- results to the header
  context("results hidden in comments", function()
    test("the method of an element is recorded", function()
      assert_equal("dmarc", lua_auth_results.parse_ar_element("dmarc=pass header.from=a.example").method)
      assert_equal("dkim", lua_auth_results.parse_ar_element("DKIM/1=pass header.d=a.example").method)
      -- RFC 8601 2.2 allows comments before the method too
      assert_equal("dmarc", lua_auth_results.parse_ar_element(
          "(forwarder result) dmarc=pass header.from=a.example").method)
      assert_equal("dmarc", lua_auth_results.parse_ar_element(
          "(a (nested\\) one) ) dmarc=pass header.from=a.example").method)
    end)

    test("an escaped parenthesis does not end a comment", function()
      local r = lua_auth_results.parse_ar_element(
        'spf=pass (x\\)dmarc=pass header.from=bank.example\\(y) smtp.mailfrom=a@b.example')
      assert_not_nil(r)
      assert_equal("spf", r.method)
      assert_equal("pass", r.spf)
      assert_nil(r.dmarc)
      assert_equal("a@b.example", r["smtp.mailfrom"])
    end)

    test("an escaped parenthesis does not let a semicolon split", function()
      local r = lua_auth_results.parse_aar_header(
        'i=1; mx.example; spf=pass (x\\); dmarc=pass header.from=bank.example \\(y) '
        .. 'smtp.mailfrom=a@b.example; dmarc=fail header.from=bank.example')
      assert_equal(2, #r.ar)
      assert_equal("spf", r.ar[1].method)
      assert_equal("dmarc", r.ar[2].method)
      assert_equal("fail", r.ar[2].dmarc)
    end)

    test("a quoted value is unquoted", function()
      local r = lua_auth_results.parse_ar_element('dmarc=pass header.from="bank.example" policy.x="a\\"b"')
      assert_equal("bank.example", r["header.from"])
      assert_equal('a"b', r["policy.x"])
    end)

    -- What gen_auth_results writes about a sender, read back
    local function written_results(smtp_from, helo)
      local task = {
        get_request_header = function() return nil end,
        get_symbol = function(_, sym)
          if sym == 'R_SPF_ALLOW' then return { { score = 1, options = {} } } end
        end,
        get_dkim_results = function() return {} end,
        get_from = function() return smtp_from and { { addr = smtp_from } } or { { addr = '' } } end,
        get_helo = function() return helo end,
        get_from_ip = function() return '192.0.2.1' end,
        get_user = function() return nil end,
      }
      local hdr = assert(lua_auth_results.gen_auth_results(task))
      return assert(lua_auth_results.parse_aar_header('i=1; ' .. hdr)).ar
    end

    for name, sender in pairs({
      ['a parenthesis in the sender'] = { '"x)dmarc=pass header.from=bank.example(y"@attacker.example' },
      ['a semicolon in the sender'] = { 'x); dmarc=pass header.from=bank.example (y@attacker.example' },
      ['a backslash at the end of HELO'] = { nil, 'a; dmarc=pass header.from=bank.example \\' },
      ['a quote in HELO'] = { nil, 'a"; dmarc=pass header.from=bank.example "' },
    }) do
      test("no result from " .. name, function()
        local ar = written_results(sender[1], sender[2])
        assert_equal(1, #ar)
        assert_equal("spf", ar[1].method)
        assert_equal("pass", ar[1].spf)
        assert_nil(ar[1].dmarc)
        assert_equal(sender[1] or sender[2], ar[1]["smtp.mailfrom"] or ar[1]["smtp.helo"])
      end)
    end

    for name, c in pairs({ CR = '\r', LF = '\n', FF = '\f' }) do
      test("no result from " .. name .. " in HELO", function()
        local ar = written_results(nil, 'x' .. c .. ';dmarc=pass header.from=bank.example')
        assert_equal(1, #ar)
        assert_equal("spf", ar[1].method)
        assert_nil(ar[1].dmarc)
        assert_equal('x?;dmarc=pass header.from=bank.example', ar[1]["smtp.helo"])
      end)

      test("a quoted value with " .. name .. " is one element", function()
        -- As an older version, or another implementation, writes it
        local r = lua_auth_results.parse_aar_header(
          'i=1; mx.example; spf=pass smtp.helo="x' .. c .. ';dmarc=pass header.from=bank.example"')
        assert_equal(1, #r.ar)
        assert_equal("spf", r.ar[1].method)
      end)
    end
  end)
end)
