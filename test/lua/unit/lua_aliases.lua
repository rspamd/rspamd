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

context("Lua aliases - mailbox_identity", function()
  local lua_aliases = require 'lua_aliases'

  local function mk_addr(user, domain)
    return {
      user = user,
      domain = domain,
      addr = string.format('%s@%s', user, domain),
    }
  end

  test('canonical_domain folds the builtin google class', function()
    assert_equal(lua_aliases.canonical_domain('googlemail.com'), 'gmail.com')
    assert_equal(lua_aliases.canonical_domain('GoogleMail.COM'), 'gmail.com')
    assert_equal(lua_aliases.canonical_domain('gmail.com'), 'gmail.com')
    assert_equal(lua_aliases.canonical_domain('example.com'), 'example.com')
    assert_equal(lua_aliases.canonical_domain(''), '')
    assert_nil(lua_aliases.canonical_domain(nil))
  end)

  test('google: one identity for both domains and dotted/tagged forms', function()
    local ref = lua_aliases.mailbox_identity(mk_addr('johndoe', 'gmail.com'))
    assert_equal(ref, 'johndoe@gmail.com')
    assert_equal(lua_aliases.mailbox_identity(mk_addr('johndoe', 'googlemail.com')), ref)
    assert_equal(lua_aliases.mailbox_identity(mk_addr('j.o.h.n.doe', 'googlemail.com')), ref)
    assert_equal(lua_aliases.mailbox_identity(mk_addr('John.Doe+news', 'GMAIL.com')), ref)
    assert_not_equal(lua_aliases.mailbox_identity(mk_addr('janedoe', 'googlemail.com')), ref)
  end)

  test('returns the canonical domain as the second value', function()
    local id, dom = lua_aliases.mailbox_identity(mk_addr('user', 'googlemail.com'))
    assert_equal(id, 'user@gmail.com')
    assert_equal(dom, 'gmail.com')
  end)

  test('generic domain: plus tag and case folded, dots kept', function()
    local ref = lua_aliases.mailbox_identity(mk_addr('first.last', 'example.com'))
    assert_equal(ref, 'first.last@example.com')
    assert_equal(lua_aliases.mailbox_identity(mk_addr('First.Last+tag', 'Example.COM')), ref)
    assert_not_equal(lua_aliases.mailbox_identity(mk_addr('firstlast', 'example.com')), ref)
  end)

  test('accepts a bare address string', function()
    assert_equal(lua_aliases.mailbox_identity('J.Doe+x@googlemail.com'), 'jdoe@gmail.com')
    assert_equal(lua_aliases.mailbox_identity('nodomain'), 'nodomain@')
  end)

  test('no user part yields nil', function()
    assert_nil(lua_aliases.mailbox_identity(mk_addr('', 'example.com')))
    assert_nil(lua_aliases.mailbox_identity(nil))
    assert_nil(lua_aliases.mailbox_identity(''))
  end)

  test('inline equivalent domains extend the builtin classes', function()
    assert_true(lua_aliases.init_equivalent_domains(nil, { ['Alias.Test'] = 'Primary.test' }))
    assert_equal(lua_aliases.canonical_domain('alias.test'), 'primary.test')
    assert_equal(lua_aliases.mailbox_identity(mk_addr('user+tag', 'alias.test')), 'user@primary.test')
    assert_equal(lua_aliases.canonical_domain('googlemail.com'), 'gmail.com')
    assert_false(lua_aliases.init_equivalent_domains(nil, nil))
  end)
end)
