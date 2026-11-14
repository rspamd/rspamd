-- rspamd_version() build identity selectors

context("Build identity", function()
  local function is_int(v)
    return type(v) == 'number' and v >= 0 and math.floor(v) == v
  end

  test("release_base is a version string", function()
    local base = rspamd_version('release_base')
    assert_equal(type(base), 'string')
    assert_not_nil(base:match('^%d+%.%d+'), 'unexpected release_base: ' .. base)
  end)

  test("dev is boolean", function()
    assert_equal(type(rspamd_version('dev')), 'boolean')
  end)

  test("distance is nil or a non-negative integer", function()
    local d = rspamd_version('distance')
    assert_true(d == nil or is_int(d), 'unexpected distance')
  end)

  test("describe is nil or tag-n-ghash starting with release_base", function()
    local desc = rspamd_version('describe')
    if desc ~= nil then
      assert_equal(type(desc), 'string')
      assert_not_nil(desc:match('^%d+%.%d+[%d%.]*%-%d+%-g%x+$'),
          'unexpected describe: ' .. desc)
      local base = rspamd_version('release_base')
      assert_equal(desc:sub(1, #base + 1), base .. '-')
      -- distance must agree with describe
      assert_equal(tostring(rspamd_version('distance')), desc:match('%-(%d+)%-g'))
    end
  end)

  test("non-dev build is at distance 0 or unknown", function()
    local dev, d = rspamd_version('dev'), rspamd_version('distance')
    assert_true(dev or d == nil or d == 0, 'non-dev build must be at distance 0 or unknown')
    if not dev and d == nil then
      assert_equal(rspamd_version('describe'), nil)
    end
  end)

  test("dev follows from version and distance", function()
    local main, base = rspamd_version('main'), rspamd_version('release_base')
    local d = rspamd_version('distance')
    assert_equal(rspamd_version('dev'), main ~= base or (d ~= nil and d > 0))
  end)

  test("existing selectors are unchanged", function()
    assert_equal(rspamd_version('main'),
        rspamd_version('major') .. '.' .. rspamd_version('minor') .. '.' .. rspamd_version('patch'))
  end)
end)
