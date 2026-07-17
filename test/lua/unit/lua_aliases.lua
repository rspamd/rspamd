context("Lua aliases - apply_service_rules", function()
  local lua_aliases = require 'lua_aliases'

  local function mk_addr(user, domain)
    return {
      user = user,
      domain = domain,
      addr = string.format('%s@%s', user, domain),
    }
  end

  test('gmail: dots are removed from user part', function()
    local nu, tags, nd = lua_aliases.apply_service_rules(mk_addr('first.last', 'gmail.com'))
    assert_equal(nu, 'firstlast')
    assert_nil(nd)
    assert_rspamd_table_eq({ actual = tags, expect = {} })
  end)

  -- str_split of '+tag1+tag2' on '+' yields a leading empty element;
  -- consumers filter empty tags out
  test('gmail: plus tags are stripped', function()
    local nu, tags, nd = lua_aliases.apply_service_rules(mk_addr('user+tag1+tag2', 'gmail.com'))
    assert_equal(nu, 'user')
    assert_nil(nd)
    assert_rspamd_table_eq({ actual = tags, expect = { '', 'tag1', 'tag2' } })
  end)

  test('gmail: plain address is not modified', function()
    local nu, tags, nd = lua_aliases.apply_service_rules(mk_addr('user', 'gmail.com'))
    assert_nil(nu)
    assert_nil(tags)
    assert_nil(nd)
  end)

  test('googlemail: user part canonicalized, domain preserved', function()
    local nu, tags, nd = lua_aliases.apply_service_rules(mk_addr('first.last+tag', 'googlemail.com'))
    assert_equal(nu, 'firstlast')
    assert_nil(nd)
    assert_rspamd_table_eq({ actual = tags, expect = { '', 'tag' } })
  end)

  test('googlemail: plain address is not modified', function()
    local nu, tags, nd = lua_aliases.apply_service_rules(mk_addr('mailer-daemon', 'googlemail.com'))
    assert_nil(nu)
    assert_nil(tags)
    assert_nil(nd)
  end)

  test('generic domain: plus tags are stripped', function()
    local nu, tags, nd = lua_aliases.apply_service_rules(mk_addr('user+tag', 'example.com'))
    assert_equal(nu, 'user')
    assert_nil(nd)
    assert_rspamd_table_eq({ actual = tags, expect = { '', 'tag' } })
  end)

  test('generic domain: dots are kept', function()
    local nu = lua_aliases.apply_service_rules(mk_addr('first.last', 'example.com'))
    assert_nil(nu)
  end)
end)
