-- What a published DMARC record means

context("DMARC record parsing", function()
  local dmarc = require "plugins/dmarc"

  local function parse(record, is_tld)
    return dmarc.dmarc_check_record(nil, record, is_tld)
  end

  local policies = {
    { 'v=DMARC1; p=reject', 'reject' },
    { 'v=DMARC1;p=quarantine', 'quarantine' },
    { 'v=DMARC1; p=none', 'none' },
    { 'V=DMARC1; P=Reject', 'reject' },
    -- White space around the parts of a tag
    { 'v=DMARC1; p = reject', 'reject' },
    { 'v = DMARC1 ; p= reject ;', 'reject' },
    -- A tag that is not known or cannot be read does not end the record
    { 'v=DMARC1; x1=a; p=reject', 'reject' },
    { 'v=DMARC1; x-y=a; p=reject', 'reject' },
    { 'v=DMARC1; garbage; p=reject', 'reject' },
    { 'v=DMARC1; =; p=reject', 'reject' },
    { 'v=DMARC1;; p=reject', 'reject' },
    -- The first of two tags of one name, whatever the case
    { 'v=DMARC1; p=reject; p=none', 'reject' },
    { 'v=DMARC1; p=reject; P=none', 'reject' },
    { 'v=DMARC1; P=reject; p=none', 'reject' },
    { 'v=DMARC1; p=none; p=reject', 'none' },
  }

  for _, c in ipairs(policies) do
    test("Policy of " .. c[1], function()
      local ok, res = parse(c[1])
      assert_true(ok, tostring(res))
      assert_equal(c[2], res.dmarc_policy)
    end)
  end

  test("Not a DMARC record", function()
    for _, rec in ipairs({ '', 'v=spf1 -all', 'v=DMARC2; p=reject', 'v=DMARC10; p=reject',
                           'v=DMARC1 p=reject', 'p=reject; v=DMARC1', 'DMARC1; p=reject' }) do
      local ok, err = parse(rec)
      assert_false(ok, rec)
      assert_false(err, rec)
    end
  end)

  test("An invalid value of a known tag is an error", function()
    for _, rec in ipairs({ 'v=DMARC1; p=bogus', 'v=DMARC1; p=reject; adkim=x', 'v=DMARC1; p=reject; aspf=x' }) do
      local ok, err = parse(rec)
      assert_false(ok, rec)
      assert_equal('string', type(err), rec)
    end
  end)

  test("Alignment modes and the subdomain policy", function()
    local ok, res = parse('v=DMARC1; p=none; sp=reject; adkim=s; aspf=S', true)
    assert_true(ok)
    assert_equal('reject', res.dmarc_policy)
    assert_true(res.strict_dkim)
    assert_true(res.strict_spf)

    ok, res = parse('v=DMARC1; p=none; sp=reject', false)
    assert_true(ok)
    assert_equal('none', res.dmarc_policy)
  end)

  test("A percentage is a whole number from 0 to 100", function()
    local cases = {
      { 'pct=0', 0 }, { 'pct=50', 50 }, { 'pct=100', 100 }, { 'pct = 25', 25 },
      { 'pct=101', nil }, { 'pct=-1', nil }, { 'pct=nan', nil }, { 'pct=inf', nil },
      { 'pct=0x10', nil }, { 'pct=1e1', nil }, { 'pct=50%', nil }, { 'pct=5.5', nil },
      { 'pct=1000', nil },
    }
    for _, c in ipairs(cases) do
      local ok, res = parse('v=DMARC1; p=reject; ' .. c[1])
      assert_true(ok, c[1])
      assert_equal(c[2], res.pct, c[1])
    end

    -- A tag after an empty one is read
    local ok, res = parse('v=DMARC1; p=reject;; pct=0')
    assert_true(ok)
    assert_equal(0, res.pct)
  end)

  test("The address for reports is bounded and has no control characters", function()
    local ok, res = parse('v=DMARC1; p=none; rua=mailto:dmarc@example.com')
    assert_true(ok)
    assert_equal('mailto:dmarc@example.com', res.rua)

    ok, res = parse('v=DMARC1; p=reject; rua=mailto:' .. string.rep('a', 60000) .. '@example.com')
    assert_true(ok)
    assert_nil(res.rua)
    assert_equal('reject', res.dmarc_policy)

    ok, res = parse('v=DMARC1; p=reject; rua=mailto:a@example.com\r\nX: y')
    assert_true(ok)
    assert_nil(res.rua)
  end)
end)
