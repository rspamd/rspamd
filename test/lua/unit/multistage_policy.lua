context('DATA policy selection', function()
  local compile = require('lua_multistage_policy').compile

  local function task(recipients, user)
    local addresses = {}

    for _, address in ipairs(recipients) do
      local parsed = require('rspamd_util').parse_mail_address(address)
      addresses[#addresses + 1] = parsed[1]
    end

    return {
      get_recipients = function() return addresses end,
      get_from = function() return { { addr = 'sender@example.net', user = 'sender', domain = 'example.net' } } end,
      get_from_ip = function() return require('rspamd_ip').from_string('192.0.2.1') end,
      get_user = function() return user end,
      get_helo = function() return 'mail.example.net' end,
      get_hostname = function() return 'mx.example.net' end,
      get_metadata_field = function(_, name) return name == 'settings_id' and 'customer' or nil end,
    }
  end

  test('a recipient exemption does not exempt another recipient', function()
    local select = assert(compile(rspamd_config, { policies = {
      { name = 'block', action = 'reject', match = { rcpt = '@example.org' },
        except = { rcpt = 'exempt@example.org' } },
    } }))

    for _, recipients in ipairs({
      { 'exempt@example.org', 'blocked@example.org' },
      { 'blocked@example.org', 'exempt@example.org' },
    }) do
      local index, recipient = select(task(recipients), { true })
      assert_equal(index, 1)
      assert_equal(recipient, 'blocked@example.org')
    end

    assert_nil(select(task({ 'exempt@example.org' }), { true }))
    assert_nil(select(task({ 'blocked@example.org' }), { false }))
  end)

  test('user and recipient settings select DATA policies with deterministic overrides', function()
    local select = assert(compile(rspamd_config, {
      policies = { { name = 'block', action = 'reject' } },
      settings = {
        defaults = { priority = -1, apply = { policies_enabled = {} } },
        customer = { match = { rcpt = '@example.org', settings_id = 'customer' },
          apply = { policies_enabled = { 'block' } } },
        exempt = { priority = 1, match = { rcpt = 'exempt@example.org' },
          apply = { policies_disabled = { 'block' } } },
        trusted = { priority = 2, match = { user = '/^trusted@/', authenticated = true },
          apply = { policies_disabled = { 'block' } } },
      },
    }))

    local mixed = task({ 'exempt@example.org', 'other@example.net', 'blocked@example.org' })
    local index, recipient = select(mixed, { true })
    assert_equal(index, 1)
    assert_equal(recipient, 'blocked@example.org')
    assert_nil(select(task({ 'other@example.net' }), { true }))
    assert_nil(select(task({ 'blocked@example.org' }, 'trusted@example.net'), { true }))
  end)

  test('permanent rejection wins over temporary rejection', function()
    local select = assert(compile(rspamd_config, { policies = {
      { name = 'defer', action = 'soft reject' },
      { name = 'block', action = 'reject', match = { rcpt = 'blocked@example.org' } },
    } }))
    local index, recipient = select(task({ 'first@example.org', 'blocked@example.org' }), { true, true })
    assert_equal(index, 2)
    assert_equal(recipient, 'blocked@example.org')
    assert_equal(select(task({ 'first@example.org' }), { true, true }), 1)
  end)

  test('scopes reuse address, CIDR and regexp matching', function()
    local select = assert(compile(rspamd_config, { policies = {
      { name = 'block', action = 'reject', match = {
        ip = { '2001:db8::/32', '192.0.2.0/24' }, from = '@example.net',
        helo = '/^mail\\./', hostname = 'mx.example.net', authenticated = false,
      } },
    } }))
    assert_equal(select(task({ 'recipient@example.org' }), { true }), 1)
    assert_nil(select(task({ 'recipient@example.org' }, 'user'), { true }))
  end)

  test('unavailable inputs and ambiguous configurations fail validation', function()
    for _, scope in ipairs({ { header = 'Subject' }, { selector = 'header(From)' },
      { rcpt = {} }, { rcpt = { typo = '@example.org' } }, { authenticated = 'yes' },
      { user = 'map:not-loaded' }, { ip = 'not-an-ip' }, { helo = '/[/' } }) do
      local select, err = compile(rspamd_config, { policies = {
        { name = 'block', action = 'reject', match = scope },
      } })
      assert_nil(select)
      assert_true(type(err) == 'string')
    end

    local select, err = compile(rspamd_config, {
      policies = { { name = 'block', action = 'reject' } },
      settings = { invalid = { apply = { policies_disabled = { 'typo' } } } },
    })
    assert_nil(select)
    assert_true(type(err) == 'string')
  end)
end)

context('Selector input requirements', function()
  local selectors = require 'lua_selectors'

  test('known envelope selectors and address modes declare their inputs', function()
    for expression, expected in pairs({
      ['asn'] = { 'connection' },
      ['helo.lower'] = { 'helo' },
      ["from('smtp'):domain.get_tld"] = { 'sender' },
      ["from('smtp', 'orig'):domain"] = { 'sender' },
      ["from('smtp', 'mime'):domain"] = { 'eom' },
      ["rcpts('smtp'):domain"] = { 'recipients' },
      ["rcpts('smtp', 'any'):domain"] = { 'eom' },
      ['from'] = { 'eom' },
      ["from('mime')"] = { 'eom' },
      ['helo;header(Subject)'] = { 'headers', 'helo' },
    }) do
      assert_rspamd_table_eq(expected, selectors.get_required_inputs(rspamd_config, expression))
    end
  end)

  test('unknown extension requirements are conservative', function()
    selectors.register_extractor(rspamd_config, 'policy_test_unknown', {
      get_value = function() return 'value', 'string' end,
    })
    assert_rspamd_table_eq({ 'eom' }, selectors.get_required_inputs(rspamd_config, 'policy_test_unknown'))
    selectors.register_transform(rspamd_config, 'policy_test_transform', {
      types = { string = true }, map_type = 'string', process = function(value) return value, 'string' end,
    })
    assert_rspamd_table_eq({ 'eom', 'helo' },
        selectors.get_required_inputs(rspamd_config, 'helo.policy_test_transform'))
  end)
end)

context('Multimap producer replay', function()
  local wrap = require('plugins/multimap').wrap_callback

  test('changed map contents or envelope values rerun the matcher', function()
    local digest, helo, fact = 'first', 'mail.example.org', nil
    local rule = { type = 'helo', map_obj = { get_data_digest = function() return digest end } }
    local task = {
      get_helo = function() return helo end,
      is_checkpoint = function() return true end,
      set_check_fact = function(_, _, value) fact = value end,
    }
    local run, _, _, replay = wrap(rspamd_config, rule, function() end)
    run(task)
    assert_true(replay(task, { map = fact }))
    digest = 'second'
    assert_false(replay(task, { map = fact }))
    digest, helo = 'first', 'other.example.org'
    assert_false(replay(task, { map = fact }))
  end)

  test('a map changed during the callback has no reusable fact', function()
    local digest, fact = 'first', nil
    local rule = { type = 'helo', map_obj = { get_data_digest = function() return digest end } }
    local task = {
      get_helo = function() return 'mail.example.org' end,
      is_checkpoint = function() return true end,
      set_check_fact = function(_, _, value) fact = value end,
    }
    local run = wrap(rspamd_config, rule, function() digest = 'second' end)
    run(task)
    assert_nil(fact)
  end)

  test('external maps and message inputs stay at EOM', function()
    local callback = function() end

    for _, rule in ipairs({
      { type = 'regexp_rules', map_obj = require('rspamd_ip').from_string('192.0.2.1') },
      { type = 'helo', map_obj = { __external = true, get_data_digest = function() end } },
      { type = 'from', extract_from = 'default', map_obj = { get_data_digest = function() end } },
      { type = 'selector', selector_str = 'header(Subject)', map_obj = { get_data_digest = function() end } },
    }) do
      local run, inputs = wrap(rspamd_config, rule, callback)
      assert_equal(callback, run)
      assert_nil(inputs)
    end
  end)
end)
