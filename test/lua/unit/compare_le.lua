-- `<=` and `>=` on userdata: Lua 5.5 does not derive them from `__lt`

context("Less or equal for userdata", function()
  local rspamd_text = require "rspamd_text"
  local rspamd_ip = require "rspamd_ip"
  local rspamd_url = require "rspamd_url"
  local rspamd_mempool = require "rspamd_mempool"

  test("rspamd_text", function()
    local a, b = rspamd_text.fromstring('abc'), rspamd_text.fromstring('abd')
    local a2 = rspamd_text.fromstring('abc')
    assert_true(a <= b)
    assert_true(a <= a2)
    assert_true(a2 >= a)
    assert_false(b <= a)
    assert_true(b >= a)
  end)

  test("rspamd_ip", function()
    local a, b = rspamd_ip.from_string('10.0.0.1'), rspamd_ip.from_string('10.0.0.2')
    local a2 = rspamd_ip.from_string('10.0.0.1')
    -- Only the consistency with `<` and `==` is checked, not the order itself
    assert_true(a <= a2)
    assert_true(a >= a2)
    assert_equal(a <= b, a < b)
    assert_equal(b <= a, b < a)
    assert_true((a <= b) ~= (b <= a))
  end)

  test("rspamd_url", function()
    local pool = rspamd_mempool.create()
    local a = rspamd_url.create(pool, 'http://a.example.com/')
    local a2 = rspamd_url.create(pool, 'http://a.example.com/')
    local b = rspamd_url.create(pool, 'http://b.example.com/')
    assert_not_nil(a)
    assert_not_nil(b)
    assert_true(a <= a2)
    assert_true(a >= a2)
    assert_equal(a <= b, a < b)
    assert_equal(b <= a, b < a)
    assert_true((a <= b) ~= (b <= a))
    pool:destroy()
  end)
end)
