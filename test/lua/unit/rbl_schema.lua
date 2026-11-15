-- Unit tests for lualib/plugins/rbl.lua (rule schema) and the RFC 4648 base32
-- encoding behind hash_format = "rbase32"

context("rbl rule schema", function()
  local rbl = require "plugins/rbl"

  local function rule(extra)
    local r = { rbl = "example.test" }
    for k, v in pairs(extra or {}) do
      r[k] = v
    end
    return r
  end

  test("hash_format rbase32 is retained", function()
    local res, err = rbl.rule_schema:transform(rule({ hash = "sha256", hash_format = "rbase32" }))
    assert_not_nil(res, err)
    assert_equal(res.hash_format, "rbase32")
    assert_equal(res.hash, "sha256")
  end)

  test("existing hash_format values are still valid", function()
    for _, f in ipairs({ "hex", "base32", "base64" }) do
      local res, err = rbl.rule_schema:transform(rule({ hash = "sha1", hash_format = f }))
      assert_not_nil(res, err)
      assert_equal(res.hash_format, f)
    end
  end)

  test("unknown hash_format is rejected", function()
    local res = rbl.rule_schema:transform(rule({ hash = "sha256", hash_format = "base58" }))
    assert_nil(res)
  end)

  test("max_dns_requests is retained", function()
    local res, err = rbl.rule_schema:transform(rule({ max_dns_requests = 1 }))
    assert_not_nil(res, err)
    assert_equal(res.max_dns_requests, 1)
  end)

  test("max_dns_requests is optional", function()
    local res, err = rbl.rule_schema:transform(rule())
    assert_not_nil(res, err)
    assert_nil(res.max_dns_requests)
  end)

  test("max_dns_requests accepts only positive integers", function()
    assert_nil(rbl.rule_schema:transform(rule({ max_dns_requests = 0 })))
    assert_nil(rbl.rule_schema:transform(rule({ max_dns_requests = -3 })))
    assert_nil(rbl.rule_schema:transform(rule({ max_dns_requests = 1.5 })))
    assert_nil(rbl.rule_schema:transform(rule({ max_dns_requests = "many" })))
  end)

  test("max_dns_requests given as a numeric string becomes a number", function()
    -- UCL may hand over a string; the plugin compares it with counters
    local res, err = rbl.rule_schema:transform(rule({ max_dns_requests = "2" }))
    assert_not_nil(res, err)
    assert_equal(res.max_dns_requests, 2)
  end)

  test("selector_hash is a boolean", function()
    local res, err = rbl.rule_schema:transform(rule({ selector_hash = false }))
    assert_not_nil(res, err)
    assert_equal(res.selector_hash, false)
    assert_nil(rbl.rule_schema:transform(rule({ selector_hash = "no" })))
  end)

  test("unknown key is rejected", function()
    local res, err = rbl.rule_schema:transform(rule({ max_dns_request = 1 }))
    assert_nil(res)
    assert_not_nil(err)
  end)
end)

context("rbl rbase32 encoding", function()
  local hash = require "rspamd_cryptobox_hash"

  -- Expected values computed independently with python3:
  --   base64.b32encode(hashlib.sha256(data).digest()).decode().rstrip('=')
  local vectors = {
    { "example.com", "UN42N5XOV642KXRXRQIYANHCOUPGQL5LT4WTBKYT2IJFLBWODFDQ" },
    { "", "4OYMIQUY7QOBJGX36TEJS35ZEQT24QPEMSNZGTFESWMRW6CSXBKQ" },
  }

  for _, v in ipairs(vectors) do
    test("sha256 of '" .. v[1] .. "' as RFC 4648 base32", function()
      local s = hash.create_specific("sha256", v[1]):base32("rfc")
      assert_equal(s, v[2])
      -- 32 bytes: 52 characters, no padding
      assert_equal(#s, 52)
      assert_nil(s:find("=", 1, true))
    end)
  end

  test("zbase32 default is a different alphabet", function()
    local z = hash.create_specific("sha256", "example.com"):base32()
    assert_not_equal(z, vectors[1][2])
    assert_equal(#z, 52)
  end)
end)
