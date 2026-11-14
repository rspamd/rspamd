context("Dynamic configuration registry", function()
  local T = require "lua_shape.core"
  local real_config = rspamd_config
  local real_util = require "rspamd_util"
  local schema_counter = 0

  -- Each test gets a fresh registry: the module keeps its state in upvalues
  -- The framework is enabled by default (file backend), so the tests that need the passive store disable
  -- it explicitly; `keep_defaults` leaves it alone
  local function fresh(time_fn, keep_defaults)
    package.loaded['lua_dynconf'] = nil
    package.loaded['lua_dynconf.redis'] = nil
    package.loaded['lua_dynconf.file'] = nil
    package.loaded['lua_dynconf.legacy'] = nil
    if time_fn then
      package.loaded['rspamd_util'] = setmetatable({ get_time = time_fn }, { __index = real_util })
    end
    local ok, res = pcall(require, 'lua_dynconf')
    package.loaded['rspamd_util'] = real_util
    assert(ok, res)
    if not keep_defaults then
      assert(res.configure({ enabled = false }))
    end
    return res
  end

  local function unique_schema_id()
    schema_counter = schema_counter + 1
    return 'plugins.dynconf_test_' .. schema_counter
  end

  -- Registers a fake backend and enables the framework with the manual policy; returns a handle that
  -- lets the test complete the pending check by hand
  local function with_fake_backend(dynconf, name, extra)
    local handle = { checks = 0 }
    dynconf.register_backend(name, {
      configure = function() return true end,
      check = function(_, cb)
        handle.checks = handle.checks + 1
        handle.pending = cb
      end,
    })
    local section = { enabled = true, backend = name, policy = 'manual' }
    for k, v in pairs(extra or {}) do
      section[k] = v
    end
    local ok, err = dynconf.configure(section)
    assert(ok, err)
    handle.complete = function(err, updates)
      local cb = handle.pending
      handle.pending = nil
      cb(err, updates)
    end
    return handle
  end

  local function register_basic(dynconf, extra)
    local params = {
      defaults = { threshold = 5, name = 'x', rules = { r1 = { score = 1, label = 'a' }, r2 = { score = 2 } },
                   limits = { a = 1, b = 2 }, list = { 1, 2, 3 } },
      opts = { threshold = 7 },
      dynamic = { 'threshold', 'rules.*.score', 'limits', 'list' },
    }
    for k, v in pairs(extra or {}) do
      params[k] = v
    end
    return dynconf.register('basic', params)
  end

  context("Registration", function()
    test("merges defaults and static options", function()
      local dynconf = fresh()
      local settings, err = register_basic(dynconf)
      assert_nil(err)
      assert_equal(settings.threshold, 7)
      assert_equal(settings.name, 'x')
      assert_equal(settings.rules.r1.score, 1)
      assert_equal(dynconf.get('basic'), settings)
    end)

    test("does not alias defaults or opts", function()
      local dynconf = fresh()
      local defaults = { nested = { a = 1 } }
      local opts = { other = { b = 2 } }
      local settings = dynconf.register('alias', { defaults = defaults, opts = opts, dynamic = { 'nested' } })
      assert_not_equal(settings.nested, defaults.nested)
      assert_not_equal(settings.other, opts.other)
      settings.nested.a = 100
      settings.other.b = 100
      assert_equal(defaults.nested.a, 1)
      assert_equal(opts.other.b, 2)
      -- A later update must not leak into the defaults either
      assert_true(dynconf.apply('test', 'alias', { nested = { a = 5 } }))
      assert_equal(defaults.nested.a, 1)
    end)

    test("opts = false means no static configuration", function()
      local dynconf = fresh()
      local settings = dynconf.register('nostatic', { defaults = { a = 1 }, opts = false })
      assert_equal(settings.a, 1)
    end)

    test("is idempotent", function()
      local dynconf = fresh()
      local first = register_basic(dynconf)
      local second = dynconf.register('basic', { defaults = { threshold = 99 }, opts = false })
      assert_equal(first, second)
      assert_equal(second.threshold, 7)
    end)

    test("rejects bad parameters", function()
      local dynconf = fresh()
      local settings, err = dynconf.register('bad', { defaults = 'nope' })
      assert_nil(settings)
      assert_equal(type(err), 'string')
      settings, err = dynconf.register('bad', { defaults = {}, dynamic = { 1 } })
      assert_nil(settings)
      assert_equal(type(err), 'string')
    end)

    test("schema failure is reported as a string", function()
      local dynconf = fresh()
      local schema = T.table({ threshold = T.number({ min = 0 }) })
      local settings, err = dynconf.register('schema_bad', {
        defaults = {}, opts = { threshold = 'abc' }, schema = schema, schema_id = unique_schema_id(),
      })
      assert_nil(settings)
      assert_equal(type(err), 'string')
      assert_nil(dynconf.get('schema_bad'))
    end)

    test("applies schema defaults and transform at load", function()
      local dynconf = fresh()
      local schema = T.table({
        threshold = T.number({ min = 0 }):with_default(3),
        enabled = T.default(T.boolean(), false),
      })
      local settings, err = dynconf.register('schema_ok', {
        defaults = {}, opts = {}, schema = schema, schema_id = unique_schema_id(),
        transform = function(tbl)
          tbl.doubled = tbl.threshold * 2
          return tbl
        end,
      })
      assert_nil(err)
      assert_equal(settings.threshold, 3)
      assert_equal(settings.enabled, false)
      assert_equal(settings.doubled, 6)
    end)

    test("failing transform is reported", function()
      local dynconf = fresh()
      local settings, err = dynconf.register('tr_bad', {
        defaults = {}, opts = false, transform = function() return nil, 'nope' end,
      })
      assert_nil(settings)
      assert_equal(err, 'nope')
    end)

    test("is_dynamic and modules", function()
      local dynconf = fresh()
      register_basic(dynconf)
      assert_true(dynconf.is_dynamic('basic', 'threshold'))
      assert_true(dynconf.is_dynamic('basic', 'rules.r1.score'))
      assert_true(dynconf.is_dynamic('basic', { 'rules', 'zzz', 'score' }))
      assert_false(dynconf.is_dynamic('basic', 'rules.r1.label'))
      assert_false(dynconf.is_dynamic('basic', 'rules.r1'))
      assert_false(dynconf.is_dynamic('basic', 'name'))
      assert_false(dynconf.is_dynamic('missing', 'name'))
      dynconf.register('another', { defaults = {}, opts = false })
      assert_rspamd_table_eq({ expect = { 'another', 'basic' }, actual = dynconf.modules() })
    end)
  end)

  context("Applying overrides", function()
    test("dynamic leaf", function()
      local dynconf = fresh()
      local settings = register_basic(dynconf)
      local gen = dynconf.generation()
      local ok, err, changed = dynconf.apply('test', 'basic', { threshold = 10 }, 1)
      assert_true(ok)
      assert_nil(err)
      assert_equal(settings.threshold, 10)
      assert_rspamd_table_eq({ expect = { 'threshold' }, actual = changed })
      assert_equal(dynconf.generation(), gen + 1)
    end)

    test("wildcard path", function()
      local dynconf = fresh()
      local settings = register_basic(dynconf)
      assert_true(dynconf.apply('test', 'basic', { rules = { r1 = { score = 5 } } }))
      assert_equal(settings.rules.r1.score, 5)
      assert_equal(settings.rules.r1.label, 'a')
      assert_equal(settings.rules.r2.score, 2)
      -- A rule that does not exist in the static config is not created by an override
      local ok, err = dynconf.apply('test', 'basic', { rules = { r3 = { score = 9 } } })
      assert_false(ok)
      assert_not_nil(err:match('rules.r3'))
      assert_nil(settings.rules.r3)
      -- Neither are empty or literal-star keys
      ok = dynconf.apply('test', 'basic', { rules = { [''] = { score = 9 } } })
      assert_false(ok)
      ok = dynconf.apply('test', 'basic', { rules = { ['*'] = { score = 9 } } })
      assert_false(ok)
      assert_nil(settings.rules[''])
      assert_nil(settings.rules['*'])
    end)

    test("a table leaf replaces the whole value", function()
      local dynconf = fresh()
      local settings = register_basic(dynconf)
      local limits, list = settings.limits, settings.list
      -- A map loses keys, a list can be emptied; identities stay
      assert_true(dynconf.apply('test', 'basic', { limits = { a = 10 }, list = {} }))
      assert_equal(settings.limits, limits)
      assert_equal(settings.list, list)
      assert_equal(settings.limits.a, 10)
      assert_nil(settings.limits.b)
      assert_equal(#settings.list, 0)
      assert_true(dynconf.apply('test', 'basic', nil))
      assert_equal(settings.limits.b, 2)
      assert_equal(#settings.list, 3)
    end)

    test("a later source replaces a table leaf of an earlier one", function()
      local dynconf = fresh()
      local settings = register_basic(dynconf)
      dynconf.register_backend('s1', { check = function() end })
      dynconf.register_backend('s2', { check = function() end })
      assert_true(dynconf.apply('s1', 'basic', { limits = { a = 1, b = 5, c = 6 } }))
      assert_true(dynconf.apply('s2', 'basic', { limits = { a = 9 } }))
      assert_equal(settings.limits.a, 9)
      assert_nil(settings.limits.b)
      assert_nil(settings.limits.c)
    end)

    test("paths through arrays", function()
      local dynconf = fresh()
      local settings = dynconf.register('arr', {
        defaults = { rules = { { name = 'a', score = 1 }, { name = 'b', score = 2 } } },
        opts = false,
        dynamic = { 'rules.*.score' },
      })
      local first = settings.rules[1]
      -- A JSON object has string keys
      assert_true(dynconf.apply('test', 'arr', { rules = { ['2'] = { score = 7 } } }))
      assert_equal(settings.rules[2].score, 7)
      assert_nil(settings.rules['2'])
      -- A numeric key does not replace the array
      assert_true(dynconf.apply('test', 'arr', { rules = { [1] = { score = 9 } } }))
      assert_equal(settings.rules[1], first)
      assert_equal(settings.rules[1].score, 9)
      assert_equal(settings.rules[1].name, 'a')
      assert_equal(settings.rules[2].score, 2)
      -- An index that does not exist is not created
      local ok = dynconf.apply('test', 'arr', { rules = { ['3'] = { score = 1 } } })
      assert_false(ok)
      assert_nil(settings.rules[3])
      assert_nil(settings.rules['3'])
    end)

    test("nested table leaf and array leaf", function()
      local dynconf = fresh()
      local settings = register_basic(dynconf)
      assert_true(dynconf.apply('test', 'basic', { limits = { a = 10 }, list = { 9 } }))
      assert_equal(settings.limits.a, 10)
      -- The value of a leaf replaces the old one as a whole
      assert_nil(settings.limits.b)
      assert_rspamd_table_eq({ expect = { 9 }, actual = settings.list })
    end)

    test("rejects options that are not dynamic", function()
      local dynconf = fresh()
      local settings = register_basic(dynconf)
      local ok, err = dynconf.apply('test', 'basic', { name = 'y' })
      assert_false(ok)
      assert_not_nil(err:match('name'))
      assert_equal(settings.name, 'x')
      -- One bad leaf rejects the whole update
      ok, err = dynconf.apply('test', 'basic', { threshold = 1, rules = { r1 = { label = 'z' } } })
      assert_false(ok)
      assert_not_nil(err:match('rules.r1.label'))
      assert_equal(settings.threshold, 7)
      -- The table above a dynamic leaf is not dynamic itself
      ok = dynconf.apply('test', 'basic', { rules = { r1 = 5 } })
      assert_false(ok)
    end)

    test("rejects type mismatch without a schema", function()
      local dynconf = fresh()
      local settings = register_basic(dynconf)
      local ok, err = dynconf.apply('test', 'basic', { threshold = 'high' })
      assert_false(ok)
      assert_not_nil(err:match('type mismatch'))
      assert_equal(settings.threshold, 7)
      ok = dynconf.apply('test', 'basic', { limits = 5 })
      assert_false(ok)
    end)

    test("rejects functions and userdata", function()
      local dynconf = fresh()
      local settings = register_basic(dynconf)
      local ok = dynconf.apply('test', 'basic', { threshold = function() return 1 end })
      assert_false(ok)
      ok = dynconf.apply('test', 'basic', { limits = { a = function() return 1 end } })
      assert_false(ok)
      ok = dynconf.apply('test', 'basic', { name = function() return 1 end })
      assert_false(ok)
      ok = dynconf.apply('test', 'basic', { threshold = real_util })
      assert_false(ok)
      assert_equal(settings.threshold, 7)
    end)

    test("rejects unknown modules and static-only modules", function()
      local dynconf = fresh()
      assert_false(dynconf.apply('test', 'missing', { a = 1 }))
      dynconf.register_static('static_mod', { a = 1 })
      assert_false(dynconf.apply('test', 'static_mod', { a = 2 }))
    end)

    test("schema validation applies to updates", function()
      local dynconf = fresh()
      local schema = T.table({ threshold = T.number({ min = 0, max = 10 }):with_default(3) })
      local settings = dynconf.register('schema_dyn', {
        defaults = {}, opts = {}, schema = schema, schema_id = unique_schema_id(),
        dynamic = { 'threshold' },
      })
      assert_true(dynconf.apply('test', 'schema_dyn', { threshold = 8 }))
      assert_equal(settings.threshold, 8)
      local ok, err = dynconf.apply('test', 'schema_dyn', { threshold = 80 })
      assert_false(ok)
      assert_equal(type(err), 'string')
      assert_equal(settings.threshold, 8)
    end)

    test("false defaults survive the schema", function()
      local dynconf = fresh()
      local schema = T.table({ flag = T.default(T.boolean(), false) })
      local settings = dynconf.register('schema_false', {
        defaults = {}, opts = {}, schema = schema, schema_id = unique_schema_id(), dynamic = { 'flag' },
      })
      assert_equal(settings.flag, false)
      assert_true(dynconf.apply('test', 'schema_false', { flag = true }))
      assert_equal(settings.flag, true)
      assert_true(dynconf.apply('test', 'schema_false', nil))
      assert_equal(settings.flag, false)
    end)

    test("updates in place", function()
      local dynconf = fresh()
      local settings = register_basic(dynconf)
      local rules, r1, limits = settings.rules, settings.rules.r1, settings.limits
      assert_true(dynconf.apply('test', 'basic', {
        threshold = 1, rules = { r1 = { score = 50 } }, limits = { a = 100 },
      }))
      assert_equal(dynconf.get('basic'), settings)
      assert_equal(settings.rules, rules)
      assert_equal(settings.rules.r1, r1)
      assert_equal(settings.limits, limits)
      assert_equal(r1.score, 50)
      assert_equal(limits.a, 100)
      -- Reverting keeps identities too
      assert_true(dynconf.apply('test', 'basic', nil))
      assert_equal(settings.rules, rules)
      assert_equal(settings.rules.r1, r1)
      assert_equal(r1.score, 1)
      assert_equal(limits.a, 1)
    end)

    test("a removed override reverts to the static value", function()
      local dynconf = fresh()
      local settings = register_basic(dynconf)
      assert_true(dynconf.apply('test', 'basic', { threshold = 10, rules = { r2 = { score = 3 } } }))
      assert_equal(settings.threshold, 10)
      assert_equal(settings.rules.r2.score, 3)
      assert_true(dynconf.apply('test', 'basic', { threshold = 11 }))
      assert_equal(settings.threshold, 11)
      -- r2 disappeared from the overrides
      assert_equal(settings.rules.r2.score, 2)
      assert_true(dynconf.apply('test', 'basic', false))
      assert_equal(settings.threshold, 7)
      assert_equal(settings.rules.r1.score, 1)
    end)

    test("a removed override leaves no tables that the static config does not have", function()
      local dynconf = fresh()
      local settings = dynconf.register('deep', {
        defaults = {}, opts = false, dynamic = { 'a.b.c', 'a.b.d' },
      })
      assert_nil(settings.a)
      assert_true(dynconf.apply('test', 'deep', { a = { b = { c = 1 } } }))
      assert_equal(settings.a.b.c, 1)
      assert_true(dynconf.apply('test', 'deep', nil))
      assert_nil(settings.a)
    end)

    test("a failed update keeps the previous state", function()
      local dynconf = fresh()
      local settings = register_basic(dynconf)
      assert_true(dynconf.apply('test', 'basic', { threshold = 10 }))
      assert_false(dynconf.apply('test', 'basic', { threshold = 'bad' }))
      assert_equal(settings.threshold, 10)
      local dump = dynconf.dump({ module = 'basic' })
      assert_equal(dump.modules.basic.overrides.test.values.threshold, 10)
    end)

    test("two sources are merged in registration order", function()
      local dynconf = fresh()
      local settings = register_basic(dynconf)
      dynconf.register_backend('first', { check = function() end })
      dynconf.register_backend('second', { check = function() end })

      assert_true(dynconf.apply('second', 'basic', { threshold = 20 }))
      assert_true(dynconf.apply('first', 'basic', { threshold = 10, limits = { a = 50 } }))
      -- `second` registered later: it wins regardless of the arrival order
      assert_equal(settings.threshold, 20)
      assert_equal(settings.limits.a, 50)

      assert_true(dynconf.apply('second', 'basic', nil))
      assert_equal(settings.threshold, 10)
      assert_true(dynconf.apply('first', 'basic', nil))
      assert_equal(settings.threshold, 7)
      assert_equal(settings.limits.a, 1)
    end)

    test("on_change receives the changed paths", function()
      local dynconf = fresh()
      local calls = {}
      local settings = register_basic(dynconf, {
        on_change = function(s, changed) table.insert(calls, { s = s, changed = changed }) end,
      })
      local extra = 0
      assert_true(dynconf.on_change('basic', function() extra = extra + 1 end))

      assert_true(dynconf.apply('test', 'basic', { threshold = 10, rules = { r1 = { score = 4 } } }))
      assert_equal(#calls, 1)
      assert_equal(calls[1].s, settings)
      assert_rspamd_table_eq({ expect = { 'rules.r1.score', 'threshold' }, actual = calls[1].changed })
      assert_equal(extra, 1)

      -- Nothing changed: no hooks, no generation bump
      local gen = dynconf.generation()
      assert_true(dynconf.apply('test', 'basic', { threshold = 10, rules = { r1 = { score = 4 } } }))
      assert_equal(#calls, 1)
      assert_equal(dynconf.generation(), gen)

      assert_true(dynconf.apply('test', 'basic', nil))
      assert_equal(#calls, 2)
      assert_rspamd_table_eq({ expect = { 'rules.r1.score', 'threshold' }, actual = calls[2].changed })
    end)

    test("a failing hook does not break the update", function()
      local dynconf = fresh()
      local settings = register_basic(dynconf, { on_change = function() error('boom') end })
      assert_true(dynconf.apply('test', 'basic', { threshold = 10 }))
      assert_equal(settings.threshold, 10)
    end)
  end)

  context("Validation", function()
    test("validate does not mutate anything", function()
      local dynconf = fresh()
      local settings = register_basic(dynconf)
      local gen = dynconf.generation()
      local called = false
      dynconf.on_change('basic', function() called = true end)

      assert_true(dynconf.validate('basic', { threshold = 10 }))
      assert_equal(settings.threshold, 7)
      assert_equal(dynconf.generation(), gen)
      assert_false(called)
      assert_rspamd_table_eq({ expect = {}, actual = dynconf.dump().modules.basic.overrides })

      local ok, err = dynconf.validate('basic', { name = 'y' })
      assert_false(ok)
      assert_not_nil(err:match('name'))
      ok = dynconf.validate('basic', { threshold = 'bad' })
      assert_false(ok)
      ok = dynconf.validate('missing', {})
      assert_false(ok)
    end)

    test("validate runs the schema", function()
      local dynconf = fresh()
      local schema = T.table({ threshold = T.number({ max = 10 }):with_default(3) })
      dynconf.register('validate_schema', {
        defaults = {}, opts = {}, schema = schema, schema_id = unique_schema_id(), dynamic = { 'threshold' },
      })
      assert_true(dynconf.validate('validate_schema', { threshold = 5 }))
      assert_false(dynconf.validate('validate_schema', { threshold = 50 }))
    end)
  end)

  context("Dump", function()
    test("redacts secrets and describes the registry", function()
      local dynconf = fresh()
      dynconf.register('dumpmod', {
        defaults = { password = 'hunter2', name = 'n', handler = function() return 1 end,
                     auth = { api_key = 'k1', token_ttl = 5 }, custom = { inner = 'sensitive' },
                     max_tokens = 100, key = 'plain-key',
                     rule = { r = { fuzzy_key = 'hk', fuzzy_shingles_key = 'sk', encryption_key = 'pub' } } },
        opts = { redis_password = 'p2' },
        dynamic = { 'name' },
        secret = { 'custom.inner' },
        schema_id = 'plugins.dumpmod',
      })
      assert_true(dynconf.apply('test', 'dumpmod', { name = 'other' }, 3))

      local dump = dynconf.dump()
      assert_equal(dump.enabled, false)
      assert_equal(dump.generation, 1)
      local m = dump.modules.dumpmod
      assert_equal(m.static_only, false)
      assert_equal(m.schema_id, 'plugins.dumpmod')
      assert_equal(m.version, 1)
      assert_rspamd_table_eq({ expect = { 'name' }, actual = m.dynamic })
      assert_equal(m.defaults.password, '***')
      assert_equal(m.defaults.key, '***')
      assert_equal(m.defaults.auth.api_key, '***')
      assert_equal(m.defaults.auth.token_ttl, 5)
      assert_equal(m.defaults.custom.inner, '***')
      assert_equal(m.defaults.max_tokens, 100)
      -- The keys of private fuzzy storages
      assert_equal(m.defaults.rule.r.fuzzy_key, '***')
      assert_equal(m.defaults.rule.r.fuzzy_shingles_key, '***')
      assert_equal(m.defaults.rule.r.encryption_key, 'pub')
      assert_equal(m.defaults.handler, '<function>')
      assert_equal(m.defaults.name, 'n')
      assert_equal(m.static.redis_password, '***')
      assert_equal(m.effective.redis_password, '***')
      assert_equal(m.effective.name, 'other')
      assert_equal(m.overrides.test.version, 3)
      assert_equal(m.overrides.test.values.name, 'other')
      assert_equal(type(m.overrides.test.updated), 'number')

      local raw = dynconf.dump({ redact = false, module = 'dumpmod' })
      assert_equal(raw.modules.dumpmod.defaults.password, 'hunter2')
      assert_equal(raw.modules.dumpmod.static.redis_password, 'p2')

      local filtered = dynconf.dump({ module = 'nothing' })
      assert_rspamd_table_eq({ expect = {}, actual = filtered.modules })
    end)

    test("dump_json is valid and redacted", function()
      local dynconf = fresh()
      dynconf.register('jsonmod', { defaults = { password = 'hunter2', n = 1 }, opts = false })
      local json = dynconf.dump_json({ module = 'jsonmod' })
      assert_equal(type(json), 'string')
      assert_nil(json:find('hunter2', 1, true))
      local ucl = require "ucl"
      local parser = ucl.parser()
      local ok, err = parser:parse_string(json)
      assert_true(ok, err)
      local obj = parser:get_object()
      assert_equal(obj.modules.jsonmod.effective.password, '***')
      assert_equal(obj.modules.jsonmod.effective.n, 1)
    end)

    test("register_static records static config only", function()
      local dynconf = fresh()
      dynconf.register_static('statmod', { opt = 1, password = 'x' })
      assert_nil(dynconf.get('statmod'))
      local m = dynconf.dump().modules.statmod
      assert_equal(m.static_only, true)
      assert_equal(m.static.opt, 1)
      assert_equal(m.static.password, '***')
      assert_equal(m.effective.opt, 1)
      assert_rspamd_table_eq({ expect = {}, actual = m.dynamic })
      -- A real registration replaces the static-only record
      local settings = dynconf.register('statmod', { defaults = { opt = 0 }, opts = { opt = 2 } })
      assert_equal(settings.opt, 2)
      assert_equal(dynconf.dump().modules.statmod.static_only, false)
    end)
  end)

  context("Backends", function()
    test("check_now is disabled without the framework", function()
      local dynconf = fresh()
      register_basic(dynconf)
      local err
      assert_false(dynconf.check_now(nil, function(e) err = e end))
      assert_not_nil(err)
    end)

    test("configure rejects bad sections", function()
      local dynconf = fresh()
      assert_true(dynconf.configure({ enabled = false }))
      assert_false(dynconf.dump().enabled)
      assert_true(dynconf.configure({ enabled = false, policy = 'bogus' }))
      assert_false((dynconf.configure({ enabled = true, backend = 'nonexistent' })))
      assert_false((dynconf.configure({ enabled = true, backend = 'nonexistent', policy = 'bogus' })))
      assert_false(dynconf.dump().enabled)
    end)

    test("check_now applies updates and removals", function()
      local dynconf = fresh()
      local settings = register_basic(dynconf)
      local backend = with_fake_backend(dynconf, 'fake')
      assert_true(dynconf.dump().enabled)

      local result
      assert_true(dynconf.check_now('ev', function(err, applied) result = { err = err, applied = applied } end))
      assert_equal(backend.checks, 1)
      backend.complete(nil, {
        basic = { version = 4, values = { threshold = 15 } },
        unknown_module = { version = 1, values = { a = 1 } },
      })
      assert_nil(result.err)
      assert_rspamd_table_eq({ expect = { 'basic' }, actual = result.applied })
      assert_equal(settings.threshold, 15)

      local dump = dynconf.dump()
      assert_equal(dump.backends.fake.last_error, nil)
      assert_equal(type(dump.backends.fake.last_check), 'number')
      assert_equal(type(dump.backends.fake.last_update), 'number')
      assert_equal(dump.modules.basic.overrides.fake.version, 4)

      -- Nothing changed
      assert_true(dynconf.check_now('ev'))
      backend.complete(nil, nil)
      assert_equal(settings.threshold, 15)

      -- `false` removes the override
      assert_true(dynconf.check_now('ev'))
      backend.complete(nil, { basic = false })
      assert_equal(settings.threshold, 7)
      assert_rspamd_table_eq({ expect = {}, actual = dynconf.dump().modules.basic.overrides })
    end)

    test("errors keep the last good state", function()
      local dynconf = fresh()
      local settings = register_basic(dynconf)
      local backend = with_fake_backend(dynconf, 'fake')

      assert_true(dynconf.check_now('ev'))
      backend.complete(nil, { basic = { version = 1, values = { threshold = 15 } } })
      assert_equal(settings.threshold, 15)

      local cb_err
      assert_true(dynconf.check_now('ev', function(e) cb_err = e end))
      backend.complete('connection refused')
      assert_equal(cb_err, 'connection refused')
      assert_equal(settings.threshold, 15)
      assert_equal(dynconf.dump().backends.fake.last_error, 'connection refused')

      -- An invalid update is rejected, other modules in the same batch still apply
      dynconf.register('second', { defaults = { v = 1 }, opts = false, dynamic = { 'v' } })
      assert_true(dynconf.check_now('ev'))
      backend.complete(nil, {
        basic = { version = 2, values = { threshold = 'bad' } },
        second = { version = 2, values = { v = 2 } },
      })
      assert_equal(settings.threshold, 15)
      assert_equal(dynconf.get('second').v, 2)
      local last_error = dynconf.dump().backends.fake.last_error
      assert_not_nil(last_error)
      assert_not_nil(last_error:match('basic'))

      -- A healthy check clears the error
      assert_true(dynconf.check_now('ev'))
      backend.complete(nil, nil)
      assert_nil(dynconf.dump().backends.fake.last_error)
    end)

    test("a throwing backend is reported", function()
      local dynconf = fresh()
      register_basic(dynconf)
      dynconf.register_backend('thrower', { check = function() error('kaput') end })
      assert_true(dynconf.configure({ enabled = true, backend = 'thrower', policy = 'manual' }))
      local err
      assert_true(dynconf.check_now('ev', function(e) err = e end))
      assert_not_nil(err:match('kaput'))
      -- It does not leave the in-flight flag behind
      assert_true(dynconf.check_now('ev'))
    end)

    test("only one check is in flight", function()
      local dynconf = fresh()
      register_basic(dynconf)
      local backend = with_fake_backend(dynconf, 'fake')

      assert_true(dynconf.check_now('ev'))
      local err
      assert_false(dynconf.check_now('ev', function(e) err = e end))
      assert_not_nil(err)
      assert_equal(backend.checks, 1)

      backend.complete(nil, nil)
      assert_true(dynconf.check_now('ev'))
      assert_equal(backend.checks, 2)
    end)

    test("a stuck check times out and its late result is ignored", function()
      local now = 1000
      local dynconf = fresh(function() return now end)
      local settings = register_basic(dynconf)
      local backend = with_fake_backend(dynconf, 'fake')

      assert_true(dynconf.check_now('ev'))
      local stale = backend.pending
      assert_false(dynconf.check_now('ev'))

      now = now + 1000
      assert_true(dynconf.check_now('ev'))
      assert_equal(backend.checks, 2)

      stale(nil, { basic = { version = 1, values = { threshold = 99 } } })
      assert_equal(settings.threshold, 7)
      -- The fresh check is still the one in flight
      assert_false(dynconf.check_now('ev'))
      backend.complete(nil, { basic = { version = 2, values = { threshold = 12 } } })
      assert_equal(settings.threshold, 12)
    end)

    test("callbacks that fire twice are applied once", function()
      local dynconf = fresh()
      local settings = register_basic(dynconf)
      local backend = with_fake_backend(dynconf, 'fake')
      local count = 0
      assert_true(dynconf.check_now('ev', function() count = count + 1 end))
      local cb = backend.pending
      cb(nil, { basic = { version = 1, values = { threshold = 15 } } })
      cb(nil, { basic = { version = 2, values = { threshold = 16 } } })
      assert_equal(count, 1)
      assert_equal(settings.threshold, 15)
    end)

    test("set writes through the backend and applies locally", function()
      local dynconf = fresh()
      local settings = register_basic(dynconf)
      local written
      dynconf.register_backend('writer', {
        check = function() end,
        set = function(ctx, module, values, cb)
          written = { ctx = ctx, module = module, values = values }
          cb(nil, 42)
        end,
      })
      assert_true(dynconf.configure({ enabled = true, backend = 'writer', policy = 'manual' }))

      local done_err = 'unset'
      assert_true(dynconf.set('basic', { threshold = 30 }, { ev_base = 'ev' }, function(e) done_err = e end))
      assert_equal(written.module, 'basic')
      assert_equal(written.values.threshold, 30)
      assert_nil(done_err)
      assert_equal(settings.threshold, 30)
      assert_equal(dynconf.dump().modules.basic.overrides.writer.version, 42)

      -- Invalid values are not written
      written = nil
      local ok, err = dynconf.set('basic', { name = 'x' }, { ev_base = 'ev' })
      assert_false(ok)
      assert_not_nil(err)
      assert_nil(written)

      assert_true(dynconf.set('basic', nil, { ev_base = 'ev' }))
      assert_equal(settings.threshold, 7)
    end)

    test("a failed write rolls the local change back", function()
      local dynconf = fresh()
      local settings = register_basic(dynconf)
      local fail = false
      dynconf.register_backend('writer', {
        check = function() end,
        set = function(_, _, _, cb)
          if fail then
            cb('redis is down')
          else
            cb(nil, 5)
          end
        end,
      })
      assert_true(dynconf.configure({ enabled = true, backend = 'writer', policy = 'manual' }))
      assert_true(dynconf.set('basic', { threshold = 30 }, { ev_base = 'ev' }))
      assert_equal(settings.threshold, 30)

      fail = true
      local done_err
      assert_true(dynconf.set('basic', { threshold = 40 }, { ev_base = 'ev' }, function(e) done_err = e end))
      assert_equal(done_err, 'redis is down')
      assert_equal(settings.threshold, 30)
      local dump = dynconf.dump({ module = 'basic' })
      assert_equal(dump.modules.basic.overrides.writer.values.threshold, 30)
      assert_equal(dump.modules.basic.overrides.writer.version, 5)
    end)

    test("update hands the patch to the backend and applies what the backend merged", function()
      local dynconf = fresh()
      local settings = register_basic(dynconf)
      local stored = { threshold = 30, limits = { a = 5 } }
      local seen_patch
      dynconf.register_backend('writer', {
        check = function() end,
        update = function(_, module, patch, prepare, cb)
          seen_patch = patch
          -- The backend merges into what it holds, which the registry has never applied
          local merged = {}
          for k, v in pairs(stored) do
            merged[k] = v
          end
          for k, v in pairs(patch) do
            merged[k] = v or nil
          end
          local ok, err = prepare(merged)
          if not ok then
            cb(err, nil, true)
            return
          end
          stored = merged
          cb(nil, 9)
        end,
      })
      assert_true(dynconf.configure({ enabled = true, backend = 'writer', policy = 'manual' }))
      assert_equal(settings.threshold, 7)

      local done_err, rejected = 'unset', nil
      assert_true(dynconf.update('basic', { list = { 8 } }, { ev_base = 'ev' }, function(e, r)
        done_err, rejected = e, r
      end))
      assert_nil(done_err)
      assert_nil(rejected)
      assert_rspamd_table_eq({ expect = { 8 }, actual = seen_patch.list })
      -- What the registry had never seen is applied too
      assert_equal(settings.threshold, 30)
      assert_equal(settings.limits.a, 5)
      assert_rspamd_table_eq({ expect = { 8 }, actual = settings.list })
      assert_equal(dynconf.dump().modules.basic.overrides.writer.version, 9)

      -- A patch that is wrong by itself is refused at once
      local ok, err = dynconf.update('basic', { name = 'y' }, { ev_base = 'ev' }, function() end)
      assert_false(ok)
      assert_not_nil(err:match('not dynamic'))

      -- A merged override that is refused (the backend holds something that is not valid) is reported
      stored.name = 'bad'
      done_err, rejected = nil, nil
      assert_true(dynconf.update('basic', { threshold = 31 }, { ev_base = 'ev' }, function(e, r)
        done_err, rejected = e, r
      end))
      assert_not_nil(done_err)
      assert_true(rejected)
      assert_equal(settings.threshold, 30)
    end)

    test("update needs a backend that merges", function()
      local dynconf = fresh()
      register_basic(dynconf)
      dynconf.register_backend('plain', { check = function() end, set = function(_, _, _, cb) cb(nil, 1) end })
      assert_true(dynconf.configure({ enabled = true, backend = 'plain', policy = 'manual' }))
      local ok, err = dynconf.update('basic', { threshold = 3 }, { ev_base = 'ev' }, function() end)
      assert_false(ok)
      assert_not_nil(err:match('does not support'))
    end)

    test("a failed update rolls the local change back", function()
      local dynconf = fresh()
      local settings = register_basic(dynconf)
      dynconf.register_backend('writer', {
        check = function() end,
        update = function(_, _, patch, prepare, cb)
          assert(prepare(patch))
          cb('redis is down')
        end,
      })
      assert_true(dynconf.configure({ enabled = true, backend = 'writer', policy = 'manual' }))
      local done_err
      assert_true(dynconf.update('basic', { threshold = 30 }, { ev_base = 'ev' }, function(e) done_err = e end))
      assert_equal(done_err, 'redis is down')
      assert_equal(settings.threshold, 7)
    end)

    test("a write that never finishes is rolled back and the backend delivers its state again", function()
      local now = 1000
      local dynconf = fresh(function() return now end)
      local settings = register_basic(dynconf)
      local invalidated = 0
      dynconf.register_backend('writer', {
        check = function(_, cb) cb(nil, nil) end,
        -- The completion callback is lost: the request has been destroyed together with its client
        set = function() end,
        update = function(_, _, patch, prepare) assert(prepare(patch)) end,
        invalidate = function() invalidated = invalidated + 1 end,
      })
      assert_true(dynconf.configure({ enabled = true, backend = 'writer', policy = 'manual' }))
      assert_true(dynconf.set('basic', { threshold = 30 }, { ev_base = 'ev' }))
      assert_equal(settings.threshold, 30)

      -- Not yet: the write may still finish
      now = now + 5
      assert_true(dynconf.check_now(nil, function() end))
      assert_equal(settings.threshold, 30)
      assert_equal(invalidated, 0)

      now = now + 60
      assert_true(dynconf.check_now(nil, function() end))
      assert_equal(settings.threshold, 7)
      assert_equal(invalidated, 1)

      -- The same for update
      assert_true(dynconf.update('basic', { threshold = 31 }, { ev_base = 'ev' }))
      assert_equal(settings.threshold, 31)
      now = now + 60
      assert_true(dynconf.check_now(nil, function() end))
      assert_equal(settings.threshold, 7)
      assert_equal(invalidated, 2)
    end)

    test("a rejection by the C subscriber is reported and nothing is written", function()
      local reject = true
      local written = false
      local proxy = setmetatable({
        get_all_opt = function(_, name)
          if name == 'cset' then
            return { threshold = 3 }
          end
        end,
        add_on_load = function() end,
        dynconf_notify = function()
          if reject then
            return false, 'threshold is out of range'
          end
          return true
        end,
      }, { __index = real_config })
      _G.rspamd_config = proxy
      local ok, err = pcall(function()
        local dynconf = fresh()
        assert_true(dynconf.register_c('cset', { 'threshold', 'other' }))
        local settings = dynconf.get('cset')
        dynconf.register_backend('writer', {
          check = function() end,
          set = function(_, _, _, cb)
            written = true
            cb(nil, 1)
          end,
        })
        assert_true(dynconf.configure({ enabled = true, backend = 'writer', policy = 'manual' }))
        local gen = dynconf.generation()
        local sok, serr = dynconf.set('cset', { threshold = -1 }, { ev_base = 'ev' })
        assert_false(sok)
        assert_not_nil(serr:match('out of range'))
        assert_false(written)
        assert_equal(settings.threshold, 3)
        assert_equal(dynconf.generation(), gen)
        assert_equal(dynconf.dump({ module = 'cset' }).modules.cset.version, 0)

        reject = false
        assert_true(dynconf.set('cset', { threshold = 4 }, { ev_base = 'ev' }))
        assert_true(written)
        assert_equal(settings.threshold, 4)
      end)
      _G.rspamd_config = real_config
      assert(ok, err)
    end)
  end)

  context("Redis backend", function()
    -- Loads the backend against a fake lua_redis that records requests and replies from a script
    local function load_backend(replies)
      local fake = { requests = {}, scripts = {} }
      local real_redis = package.loaded['lua_redis']
      package.loaded['lua_redis'] = setmetatable({
        parse_redis_server = function(name, section)
          fake.parsed = { name = name, section = section }
          return { timeout = 1.0 }
        end,
        add_redis_script = function(script)
          table.insert(fake.scripts, script)
          return #fake.scripts
        end,
        redis_make_request_taskless = function(ev_base, _, _, key, is_write, cb, cmd, args)
          table.insert(fake.requests, { ev_base = ev_base, key = key, is_write = is_write, cmd = cmd, args = args })
          local reply = table.remove(replies, 1)
          cb(reply.err, reply.data)
          return true
        end,
        exec_redis_script = function(id, params, cb, keys, args)
          fake.exec = { id = id, params = params, keys = keys, args = args }
          fake.execs = fake.execs or {}
          table.insert(fake.execs, fake.exec)
          local result = fake.exec_results and table.remove(fake.exec_results, 1)
          cb(nil, result or 8)
          return true
        end,
      }, { __index = real_redis })
      package.loaded['lua_dynconf.redis'] = nil
      local ok, backend = pcall(require, 'lua_dynconf.redis')
      package.loaded['lua_redis'] = real_redis
      assert(ok, backend)
      package.loaded['lua_dynconf.redis'] = nil
      fake.backend = backend
      return fake
    end

    test("update merges the patch into the blob that redis holds", function()
      local null = require("rspamd_redis").null
      local fake = load_backend({
        { data = '{"v":3,"o":{"a":1,"b":2}}' },
        { data = null },
      })
      assert_true(fake.backend.configure({ key = 'my_key' }))
      fake.backend.start()

      local prepared
      local res
      fake.backend.update({ ev_base = 'ev' }, 'basic', { b = false, c = 5 }, function(merged)
        prepared = merged
        return true
      end, function(err, version, rejected) res = { err = err, version = version, rejected = rejected } end)
      assert_equal(fake.requests[1].cmd, 'HGET')
      assert_equal(fake.requests[1].args[2], 'm:basic')
      assert_equal(prepared.a, 1)
      assert_nil(prepared.b)
      assert_equal(prepared.c, 5)
      assert_nil(res.err)
      assert_equal(res.version, 8)
      -- The write is conditional on the blob that has been merged
      assert_equal(fake.exec.args[1], 'm:basic')
      assert_equal(fake.exec.args[4], '{"v":3,"o":{"a":1,"b":2}}')
      assert_true(fake.backend.holds('basic'))

      -- A missing field: the write is conditional on its absence; an empty result removes the override
      fake.backend.update({ ev_base = 'ev' }, 'basic', { z = false }, function(merged)
        prepared = merged
        return true
      end, function(err) res = { err = err } end)
      assert_nil(prepared)
      assert_equal(fake.exec.args[2], '')
      assert_equal(fake.exec.args[4], '')
      assert_false(fake.backend.holds('basic'))
    end)

    test("update merges again when somebody else has changed the blob", function()
      local fake = load_backend({
        { data = '{"v":3,"o":{"a":1}}' },
        { data = '{"v":4,"o":{"a":1,"x":9}}' },
      })
      fake.exec_results = { -1 }
      assert_true(fake.backend.configure({}))
      fake.backend.start()
      local seen = {}
      local res
      fake.backend.update({ ev_base = 'ev' }, 'basic', { c = 5 }, function(merged)
        table.insert(seen, merged)
        return true
      end, function(err, version) res = { err = err, version = version } end)
      assert_equal(#seen, 2)
      assert_nil(seen[1].x)
      assert_equal(seen[2].x, 9)
      assert_equal(seen[2].c, 5)
      assert_nil(res.err)
      assert_equal(res.version, 8)
      assert_equal(#fake.execs, 2)
      assert_equal(fake.execs[2].args[4], '{"v":4,"o":{"a":1,"x":9}}')
    end)

    test("update gives up when the blob keeps changing and reports a refusal", function()
      local fake = load_backend({
        { data = '{"v":1,"o":{}}' }, { data = '{"v":2,"o":{}}' }, { data = '{"v":3,"o":{}}' },
        { data = '{"v":4,"o":{}}' }, { data = '{"v":5,"o":{}}' },
      })
      fake.exec_results = { -1, -1, -1, -1, -1 }
      assert_true(fake.backend.configure({}))
      fake.backend.start()
      local res
      fake.backend.update({ ev_base = 'ev' }, 'basic', { c = 5 }, function() return true end,
          function(err) res = { err = err } end)
      assert_not_nil(res.err:match('too often'))

      -- A refusal by `prepare` writes nothing
      local fake2 = load_backend({ { data = '{"v":1,"o":{}}' } })
      assert_true(fake2.backend.configure({}))
      fake2.backend.start()
      fake2.backend.update({ ev_base = 'ev' }, 'basic', { c = 5 }, function() return false, 'nope' end,
          function(err, _, rejected) res = { err = err, rejected = rejected } end)
      assert_equal(res.err, 'nope')
      assert_true(res.rejected)
      assert_nil(fake2.execs)
    end)

    test("invalidate makes the next check fetch the hash again", function()
      local fake = load_backend({
        { data = '3' }, { data = { 'v', '3', 'm:basic', '{"v":3,"o":{"threshold":9}}' } },
        { data = '3' }, { data = { 'v', '3', 'm:basic', '{"v":3,"o":{"threshold":10}}' } },
      })
      assert_true(fake.backend.configure({}))
      fake.backend.start()
      local res
      local function check()
        fake.backend.check('ev', function(err, updates, commit)
          res = { err = err, updates = updates }
          commit()
        end)
      end
      check()
      assert_equal(fake.backend.version(), 3)
      fake.backend.invalidate()
      assert_equal(fake.backend.version(), 0)
      check()
      assert_equal(res.updates.basic.values.threshold, 10)
    end)

    test("check fetches the hash only when the version changes", function()
      -- A nil reply is the `redis.null` userdata, whose tostring() fails on PUC Lua
      local null = require("rspamd_redis").null
      local replies = {
        { data = null },                                           -- HGET v: missing key == 0
        { data = '3' },                                            -- HGET v
        { data = { 'v', '3', 'm:basic', '{"v":3,"o":{"threshold":9}}', 'm:broken', '{oops',
                   'm:other', '{"v":1,"o":{}}' } },                -- HGETALL
        { data = '3' },                                            -- HGET v: unchanged
        { data = '4' },                                            -- HGET v
        { data = { 'v', '4', 'm:basic', '{"v":4,"o":{"threshold":10}}',
                   'm:broken', '{"v":4,"o":{"a":1}}' } },          -- HGETALL: other vanished
        { data = null },                                           -- HGET v: key deleted
        { data = {} },                                             -- HGETALL: everything vanished
      }
      local fake = load_backend(replies)
      local backend = fake.backend
      assert_true(backend.configure({ key = 'my_key' }))
      assert_equal(fake.parsed.name, 'dynconf')
      assert_equal(#fake.scripts, 1)
      backend.start()

      local function check()
        local res
        backend.check('ev', function(err, updates, commit)
          res = { err = err, updates = updates }
          -- The registry commits an accepted result
          if commit then
            commit()
          end
        end)
        return res
      end

      local res = check()
      assert_nil(res.err)
      assert_nil(res.updates)
      assert_equal(#fake.requests, 1)
      assert_equal(fake.requests[1].cmd, 'HGET')
      assert_equal(fake.requests[1].args[1], 'my_key')
      assert_equal(fake.requests[1].args[2], 'v')
      assert_equal(fake.requests[1].ev_base, 'ev')

      res = check()
      assert_nil(res.err)
      assert_equal(fake.requests[3].cmd, 'HGETALL')
      -- A broken blob is skipped, the other modules are reported
      assert_equal(res.updates.basic.version, 3)
      assert_equal(res.updates.basic.values.threshold, 9)
      assert_equal(res.updates.other.version, 1)
      assert_nil(res.updates.broken)
      assert_equal(backend.version(), 3)

      res = check()
      assert_nil(res.updates)

      res = check()
      assert_equal(res.updates.basic.version, 4)
      assert_equal(res.updates.other, false)
      -- `broken` became valid
      assert_equal(res.updates.broken.version, 4)

      res = check()
      assert_equal(res.updates.basic, false)
      assert_equal(res.updates.broken, false)
      assert_equal(backend.version(), 0)
    end)

    test("a result that is not committed is delivered again", function()
      local fake = load_backend({
        { data = '3' }, { data = { 'v', '3', 'm:basic', '{"v":3,"o":{"threshold":9}}' } },
        { data = '3' }, { data = { 'v', '3', 'm:basic', '{"v":3,"o":{"threshold":9}}' } },
        { data = '3' },
      })
      assert_true(fake.backend.configure({}))
      fake.backend.start()
      local first, second, third
      -- A stale result: dropped without a commit
      fake.backend.check('ev', function(err, updates) first = { err = err, updates = updates } end)
      assert_equal(first.updates.basic.values.threshold, 9)
      assert_equal(fake.backend.version(), 0)
      fake.backend.check('ev', function(err, updates, commit)
        second = { err = err, updates = updates }
        commit()
      end)
      assert_equal(second.updates.basic.values.threshold, 9)
      assert_equal(fake.backend.version(), 3)
      fake.backend.check('ev', function(err, updates) third = { err = err, updates = updates } end)
      assert_nil(third.updates)
    end)

    test("content that changed at the same version is delivered", function()
      local fake = load_backend({
        { data = '3' }, { data = { 'v', '3', 'm:basic', '{"v":3,"o":{"threshold":9}}' } },
        { data = '4' }, { data = { 'v', '4', 'm:basic', '{"v":3,"o":{"threshold":11}}' } },
      })
      assert_true(fake.backend.configure({}))
      fake.backend.start()
      local res
      local function check()
        fake.backend.check('ev', function(err, updates, commit)
          res = { err = err, updates = updates }
          commit()
        end)
      end
      check()
      assert_equal(res.updates.basic.values.threshold, 9)
      check()
      assert_equal(res.updates.basic.values.threshold, 11)
    end)

    test("a local write is known to the backend, so its removal is noticed", function()
      local null = require("rspamd_redis").null
      local fake = load_backend({
        { data = '9' }, { data = { 'v', '9' } },
        { data = null }, { data = {} },
      })
      assert_true(fake.backend.configure({}))
      fake.backend.start()
      local wres
      fake.backend.set({ ev_base = 'ev' }, 'basic', { threshold = 9 }, function(err, version)
        wres = { err = err, version = version }
      end)
      assert_equal(wres.version, 8)
      -- Somebody else removed it before the next poll: the hash has no such field
      local res
      fake.backend.check('ev', function(err, updates, commit)
        res = { err = err, updates = updates }
        commit()
      end)
      assert_equal(res.updates.basic, false)
    end)

    test("the first version of a new hash is a time based number", function()
      local fake = load_backend({})
      assert_true(fake.backend.configure({}))
      fake.backend.set({ ev_base = 'ev' }, 'basic', { threshold = 9 }, function() end)
      assert_not_nil(fake.scripts[1]:match('EXISTS'))
      assert_true(tonumber(fake.exec.args[3]) > 1e12)
    end)

    test("the JSON encoder keeps the precision of numbers", function()
      local fake = load_backend({})
      local enc = fake.backend.encode_json
      assert_equal(enc({ a = 0.12345678 }), '{"a":0.12345678}')
      assert_equal(enc({ a = 1e-7 }), '{"a":1e-07}')
      assert_equal(enc({ a = 5 }), '{"a":5}')
      assert_equal(enc({ list = { 1, 'x', true } }), '{"list":[1,"x",true]}')
      assert_equal(enc({ s = 'a"b\\c\n' }), '{"s":"a\\"b\\\\c\\n"}')
      assert_equal(enc({ e = {} }), '{"e":{}}')
      assert_nil(enc({ a = 0 / 0 }))
      assert_nil(enc({ a = function() end }))
      local ucl = require "ucl"
      local parser = ucl.parser()
      assert_true(parser:parse_text(enc({ a = 0.1 + 0.2, b = { c = 1e-9 }, d = 'x\1y' })))
      local obj = parser:get_object()
      assert_equal(obj.a, 0.1 + 0.2)
      assert_equal(obj.b.c, 1e-9)
      assert_equal(obj.d, 'x\1y')
      local blob
      fake.backend.configure({})
      fake.backend.set({ ev_base = 'ev' }, 'basic', { p = 0.12345678 }, function() end)
      blob = fake.exec.args[2]
      assert_equal(blob, '{"p":0.12345678}')
    end)

    test("redis errors are reported", function()
      local fake = load_backend({ { err = 'timeout' } })
      assert_true(fake.backend.configure({}))
      local err
      fake.backend.check('ev', function(e) err = e end)
      assert_not_nil(err:match('timeout'))
    end)

    test("set goes through the atomic script", function()
      local fake = load_backend({})
      assert_true(fake.backend.configure({ key = 'k' }))
      assert_not_nil(fake.scripts[1]:match('HINCRBY'))

      local res
      fake.backend.set({ ev_base = 'ev' }, 'basic', { threshold = 9 }, function(err, version)
        res = { err = err, version = version }
      end)
      assert_nil(res.err)
      assert_equal(res.version, 8)
      assert_equal(fake.exec.params.ev_base, 'ev')
      assert_true(fake.exec.params.is_write)
      assert_equal(fake.exec.keys[1], 'k')
      assert_equal(fake.exec.args[1], 'm:basic')
      assert_not_nil(fake.exec.args[2]:match('"threshold"'))

      fake.backend.set({ task = 'task' }, 'basic', nil, function() end)
      assert_equal(fake.exec.params.task, 'task')
      assert_equal(fake.exec.args[2], '')

      fake.backend.set({ ev_base = 'ev' }, 'basic', {}, function() end)
      assert_equal(fake.exec.args[2], '{}')
    end)

    test("an unconfigured backend fails cleanly", function()
      local fake = load_backend({})
      local err
      fake.backend.check('ev', function(e) err = e end)
      assert_not_nil(err)
      fake.backend.set({}, 'basic', {}, function(e) err = e end)
      assert_not_nil(err)
    end)

    test("configure fails without redis servers", function()
      local real_redis = package.loaded['lua_redis']
      package.loaded['lua_redis'] = setmetatable({ parse_redis_server = function() return nil end },
          { __index = real_redis })
      package.loaded['lua_dynconf.redis'] = nil
      local backend = require 'lua_dynconf.redis'
      package.loaded['lua_redis'] = real_redis
      package.loaded['lua_dynconf.redis'] = nil
      local ok, err = backend.configure({})
      assert_false(ok)
      assert_equal(type(err), 'string')
    end)
  end)

  context("Policies and C integration", function()
    local function with_config(fields, fn)
      local proxy = setmetatable(fields, { __index = real_config })
      _G.rspamd_config = proxy
      local ok, err = pcall(fn, proxy)
      _G.rspamd_config = real_config
      assert(ok, err)
    end

    test("interval policy arms one periodic", function()
      local periodic = {}
      local on_load = {}
      with_config({
        add_on_load = function(_, fn) table.insert(on_load, fn) end,
        add_periodic = function(_, ev_base, timeout, fn, jitter)
          table.insert(periodic, { ev_base = ev_base, timeout = timeout, fn = fn, jitter = jitter })
        end,
      }, function(cfg)
        local dynconf = fresh()
        local backend = with_fake_backend(dynconf, 'fake')
        -- with_fake_backend uses the manual policy, reconfigure for interval
        assert_true(dynconf.configure({ enabled = true, backend = 'fake', policy = 'interval',
                                        interval = 10, jitter = 0 }))
        assert_equal(#on_load, 1)
        on_load[1](cfg, 'ev', nil)
        assert_equal(#periodic, 1)
        assert_equal(periodic[1].ev_base, 'ev')
        assert_true(periodic[1].timeout < 1.0)

        assert_equal(periodic[1].fn(), 10)
        assert_equal(backend.checks, 1)
        -- A tick while the previous check is still running does not start another one
        assert_equal(periodic[1].fn(), 10)
        assert_equal(backend.checks, 1)
      end)
    end)

    test("manual policy arms nothing", function()
      local armed = false
      with_config({
        add_on_load = function(_, fn) fn(nil, 'ev', nil) end,
        add_periodic = function() armed = true end,
        dynconf_arm = function() armed = true end,
      }, function()
        local dynconf = fresh()
        with_fake_backend(dynconf, 'fake')
        assert_false(armed)
      end)
    end)

    test("on_access policy arms the C trigger", function()
      local arms = {}
      local on_load = {}
      local periodic = false
      with_config({
        add_on_load = function(_, fn) table.insert(on_load, fn) end,
        add_periodic = function() periodic = true end,
        dynconf_arm = function(_, when, fn) table.insert(arms, { when = when, fn = fn }) end,
      }, function(cfg)
        local dynconf = fresh()
        local backend = with_fake_backend(dynconf, 'fake')
        assert_true(dynconf.configure({ enabled = true, backend = 'fake', policy = 'on_access', ttl = 5 }))
        on_load[1](cfg, 'ev', nil)
        assert_false(periodic)
        assert_equal(#arms, 1)
        assert_equal(type(arms[1].fn), 'function')

        -- The task-start trigger re-arms with the ttl and starts a check
        assert_true(arms[1].when >= real_util.get_time() - 1)
        local before = real_util.get_time()
        arms[1].fn()
        assert_equal(#arms, 2)
        assert_true(arms[2].when >= before + 5)
        assert_equal(backend.checks, 1)
      end)
    end)

    test("C modules are notified with the effective dynamic values", function()
      local notified = {}
      local bumps = 0
      with_config({
        get_all_opt = function(_, name)
          if name == 'cmod' then
            return { threshold = 3, max_word_len = 7, other = 1 }
          end
        end,
        dynconf_notify = function(_, module, tbl)
          table.insert(notified, { module = module, tbl = tbl })
          return true
        end,
        dynconf_bump_generation = function() bumps = bumps + 1 end,
      }, function()
        local dynconf = fresh()
        local ok, err = dynconf.register_c('cmod', { 'threshold', 'max_word_len', 'rule.*.score' })
        assert_true(ok, err)
        local settings = dynconf.get('cmod')
        assert_equal(settings.threshold, 3)
        assert_equal(settings.other, 1)

        assert_true(dynconf.apply('test', 'cmod', { threshold = 9 }))
        assert_equal(settings.threshold, 9)
        assert_equal(#notified, 1)
        assert_equal(notified[1].module, 'cmod')
        -- The snapshot has the dynamic paths only, with static values for the untouched ones
        assert_rspamd_table_eq({ expect = { threshold = 9, max_word_len = 7 }, actual = notified[1].tbl })
        assert_equal(bumps, 1)

        assert_false(dynconf.apply('test', 'cmod', { other = 5 }))
        assert_equal(#notified, 1)

        -- Reverting notifies again with the static values
        assert_true(dynconf.apply('test', 'cmod', nil))
        assert_equal(#notified, 2)
        assert_rspamd_table_eq({ expect = { threshold = 3, max_word_len = 7 }, actual = notified[2].tbl })
      end)
    end)

    test("a rejection by the C subscriber leaves the registry untouched", function()
      local hooks = 0
      with_config({
        get_all_opt = function(_, name)
          if name == 'crej' then
            return { threshold = 3, timeout = 1 }
          end
        end,
        dynconf_notify = function(_, _, tbl)
          if tbl.threshold and tbl.threshold < 0 then
            return false, 'bad threshold'
          end
          return true
        end,
      }, function()
        local dynconf = fresh()
        assert_true(dynconf.register_c('crej', { 'threshold', 'timeout' }))
        dynconf.on_change('crej', function() hooks = hooks + 1 end)
        local settings = dynconf.get('crej')
        local gen = dynconf.generation()

        local ok, err = dynconf.apply('test', 'crej', { threshold = -1 })
        assert_false(ok)
        assert_not_nil(err:match('bad threshold'))
        assert_equal(settings.threshold, 3)
        assert_equal(dynconf.generation(), gen)
        assert_equal(hooks, 0)
        local dump = dynconf.dump({ module = 'crej' }).modules.crej
        assert_equal(dump.version, 0)
        assert_nil(dump.overrides.test)

        -- The rejected value does not block later updates of the module
        assert_true(dynconf.apply('test', 'crej', { timeout = 2 }))
        assert_equal(settings.timeout, 2)
        assert_equal(settings.threshold, 3)
        assert_equal(hooks, 1)
      end)
    end)

    test("a C notification that throws is a rejection too", function()
      with_config({
        get_all_opt = function() return { threshold = 3 } end,
        dynconf_notify = function() error('boom') end,
      }, function()
        local dynconf = fresh()
        assert_true(dynconf.register_c('cthrow', { 'threshold' }))
        local ok, err = dynconf.apply('test', 'cthrow', { threshold = 4 })
        assert_false(ok)
        assert_not_nil(err:match('boom'))
        assert_equal(dynconf.get('cthrow').threshold, 3)
      end)
    end)

    test("ttl must be positive", function()
      local dynconf = fresh()
      with_fake_backend(dynconf, 'fake')
      local ok, err = dynconf.configure({ enabled = true, backend = 'fake', policy = 'on_access', ttl = 0 })
      assert_false(ok)
      assert_not_nil(err)
    end)

    test("workers do not share the jitter sequence", function()
      local delays = {}
      local calls = 0
      local util_stub = setmetatable({
        random_hex = function(n)
          calls = calls + 1
          return string.rep(calls == 1 and 'a' or 'b', n)
        end,
      }, { __index = real_util })
      local on_load
      with_config({
        add_on_load = function(_, fn) on_load = fn end,
        add_periodic = function(_, _, timeout, fn)
          table.insert(delays, { first = timeout, second = fn() })
        end,
      }, function(cfg)
        package.loaded['rspamd_util'] = util_stub
        for _ = 1, 2 do
          local dynconf = fresh()
          with_fake_backend(dynconf, 'fake')
          assert_true(dynconf.configure({ enabled = true, backend = 'fake', policy = 'interval',
                                          interval = 10, jitter = 0.5 }))
          on_load(cfg, 'ev', nil)
        end
        package.loaded['rspamd_util'] = real_util
      end)
      package.loaded['rspamd_util'] = real_util
      assert_equal(#delays, 2)
      assert_not_equal(delays[1].first, delays[2].first)
    end)

    test("C snapshot expands wildcards", function()
      local notified = {}
      with_config({
        get_all_opt = function(_, name)
          if name == 'cwild' then
            return { rule = { r1 = { max_score = 1, other = 'x' }, r2 = { max_score = 2 } } }
          end
        end,
        dynconf_notify = function(_, _, tbl)
          table.insert(notified, tbl)
          return true
        end,
      }, function()
        local dynconf = fresh()
        assert_true(dynconf.register_c('cwild', { 'rule.*.max_score' }))
        assert_true(dynconf.apply('test', 'cwild', { rule = { r2 = { max_score = 20 } } }))
        assert_rspamd_table_eq({
          expect = { rule = { r1 = { max_score = 1 }, r2 = { max_score = 20 } } },
          actual = notified[1],
        })
      end)
    end)
  end)

  -- The framework section ------------------------------------------------------------------------

  context("Default configuration", function()
    local function with_config(fields, fn)
      local proxy = setmetatable(fields, { __index = real_config })
      _G.rspamd_config = proxy
      local ok, err = pcall(fn, proxy)
      _G.rspamd_config = real_config
      assert(ok, err)
    end

    local function fake_backend(dynconf, name)
      dynconf.register_backend(name, {
        configure = function() return true end,
        check = function() end,
      })
    end

    -- The assertion functions exist inside tests only, so helpers return a summary to compare
    local DEFAULTS = 'enabled=true policy=interval backend=file modules=actions,scores,symbols'
    local function summary(dump)
      local backend = next(dump.backends)
      return string.format('enabled=%s policy=%s backend=%s modules=%s', tostring(dump.enabled), dump.policy,
          tostring(backend), table.concat(dump.modules_allowed or {}, ','))
    end

    test("a missing section enables the file backend for three modules", function()
      local on_load = {}
      local periodic = 0
      with_config({
        get_all_opt = function() return nil end,
        add_on_load = function(_, fn) table.insert(on_load, fn) end,
        add_periodic = function() periodic = periodic + 1 end,
        dynconf_notify = function() return true end,
        dynconf_bump_generation = function() end,
      }, function(cfg)
        local dynconf = fresh(nil, true)
        local settings = dynconf.register('basic', { defaults = { a = 1 }, opts = false, dynamic = { 'a' } })
        assert_true(dynconf.register_c('actions', { '*' }, { subscriber_keys = true }))
        assert_equal(summary(dynconf.dump()), DEFAULTS)
        assert_equal(require('lua_dynconf.file').path(), rspamd_paths.DBDIR .. '/rspamd_dynconf.json')

        -- Only the listed modules accept overrides
        local ok, err = dynconf.apply('test', 'basic', { a = 2 })
        assert_false(ok)
        assert_not_nil(err:match('does not accept overrides'))
        assert_equal(settings.a, 1)
        assert_true(dynconf.apply('test', 'actions', { reject = 10 }))

        -- Nothing runs until a worker starts, and then there is one periodic and no per-task trigger
        assert_equal(periodic, 0)
        assert_equal(#on_load, 1)
        on_load[1](cfg, 'ev', nil)
        assert_equal(periodic, 1)
      end)
    end)

    test("an empty or missing section resolves the same way", function()
      for _, section in ipairs({ 'nil', 'empty' }) do
        local dynconf = fresh()
        assert_true(dynconf.configure(section == 'empty' and {} or nil))
        assert_equal(summary(dynconf.dump()), DEFAULTS)
      end
    end)

    test("a section without `enabled` keeps the defaults for unset keys", function()
      local dynconf = fresh()
      assert_true(dynconf.configure({ interval = 5, path = '/nonexistent/dynconf.json' }))
      assert_equal(summary(dynconf.dump()), DEFAULTS)
      assert_equal(require('lua_dynconf.file').path(), '/nonexistent/dynconf.json')

      dynconf = fresh()
      fake_backend(dynconf, 'fake')
      assert_true(dynconf.configure({ backend = 'fake' }))
      assert_equal(summary(dynconf.dump()), 'enabled=true policy=interval backend=fake modules=actions,scores,symbols')
    end)

    test("an explicit `enabled = true` accepts all modules", function()
      local dynconf = fresh()
      assert_true(dynconf.configure({ enabled = true }))
      local dump = dynconf.dump()
      assert_true(dump.enabled)
      assert_nil(dump.modules_allowed)
      assert_not_nil(dump.backends.file)
      local settings = dynconf.register('basic', { defaults = { a = 1 }, opts = false, dynamic = { 'a' } })
      assert_true(dynconf.apply('test', 'basic', { a = 2 }))
      assert_equal(settings.a, 2)
    end)

    test("`modules` overrides the allow-list", function()
      local dynconf = fresh()
      assert_true(dynconf.configure({ modules = { 'basic' } }))
      assert_rspamd_table_eq({ expect = { 'basic' }, actual = dynconf.dump().modules_allowed })
      dynconf = fresh()
      assert_true(dynconf.configure({ enabled = true, modules = 'one' }))
      assert_rspamd_table_eq({ expect = { 'one' }, actual = dynconf.dump().modules_allowed })
      dynconf = fresh()
      assert_false((dynconf.configure({ modules = { 1 } })))
      assert_false(dynconf.dump().enabled)
      assert_false((dynconf.configure({ modules = true })))
    end)

    test("an explicit `enabled = false` disables everything", function()
      local on_load = 0
      with_config({
        get_all_opt = function(_, name)
          if name == 'dynconf' then
            return { enabled = false, backend = 'file' }
          end
        end,
        add_on_load = function() on_load = on_load + 1 end,
      }, function()
        local dynconf = fresh(nil, true)
        local settings = dynconf.register('basic', { defaults = { a = 1 }, opts = false, dynamic = { 'a' } })
        local dump = dynconf.dump()
        assert_false(dump.enabled)
        assert_nil(dump.modules_allowed)
        assert_equal(on_load, 0)
        assert_false(dynconf.check_now(nil))
        assert_false((dynconf.set('basic', { a = 3 })))
        -- A passive store still takes overrides of any module
        assert_true(dynconf.apply('test', 'basic', { a = 2 }))
        assert_equal(settings.a, 2)
      end)
    end)

    test("a broken section disables the framework", function()
      with_config({
        get_all_opt = function(_, name)
          if name == 'dynconf' then
            return { backend = 'nonexistent' }
          end
        end,
      }, function()
        local dynconf = fresh(nil, true)
        dynconf.register('basic', { defaults = { a = 1 }, opts = false })
        assert_false(dynconf.dump().enabled)
      end)
    end)
  end)

  context("Module allow-list", function()
    local function register_two(dynconf)
      local a = dynconf.register('allowed', { defaults = { x = 1 }, opts = false, dynamic = { 'x' } })
      local b = dynconf.register('blocked', { defaults = { x = 1 }, opts = false, dynamic = { 'x' } })
      return a, b
    end

    local function with_writer(dynconf)
      local written = {}
      dynconf.register_backend('writer', {
        configure = function() return true end,
        check = function(_, cb) cb(nil, nil) end,
        set = function(_, module, values, cb)
          table.insert(written, { module = module, values = values })
          cb(nil, 1)
        end,
      })
      assert(dynconf.configure({ enabled = true, backend = 'writer', policy = 'manual',
                                 modules = { 'allowed' } }))
      return written
    end

    test("apply and validate reject other modules", function()
      local dynconf = fresh()
      local a, b = register_two(dynconf)
      with_fake_backend(dynconf, 'fake', { modules = { 'allowed' } })

      assert_true(dynconf.validate('allowed', { x = 2 }))
      local ok, err = dynconf.validate('blocked', { x = 2 })
      assert_false(ok)
      assert_not_nil(err:match('blocked'))
      assert_not_nil(err:match('modules'))

      assert_true(dynconf.apply('test', 'allowed', { x = 2 }))
      ok, err = dynconf.apply('test', 'blocked', { x = 2 })
      assert_false(ok)
      assert_not_nil(err:match('does not accept overrides'))
      assert_equal(a.x, 2)
      assert_equal(b.x, 1)
      -- Nothing was recorded for the rejected module
      assert_nil(dynconf.dump().modules.blocked.overrides.test)
      -- Removing an override is always fine
      assert_true(dynconf.apply('test', 'blocked', nil))
    end)

    test("set rejects other modules and writes nothing", function()
      local dynconf = fresh()
      local a, b = register_two(dynconf)
      local written = with_writer(dynconf)

      local ok, err = dynconf.set('blocked', { x = 5 }, { ev_base = 'ev' })
      assert_false(ok)
      assert_not_nil(err:match('does not accept overrides'))
      assert_equal(#written, 0)
      assert_equal(b.x, 1)

      assert_true(dynconf.set('allowed', { x = 5 }, { ev_base = 'ev' }))
      assert_equal(#written, 1)
      assert_equal(a.x, 5)
      -- Resetting a module that is not allowed is still possible (it clears what an older config wrote)
      assert_true(dynconf.set('blocked', nil, { ev_base = 'ev' }))
    end)

    test("modules still appear in dumps and backend updates are reported", function()
      local dynconf = fresh()
      local _, b = register_two(dynconf)
      local backend = with_fake_backend(dynconf, 'fake', { modules = { 'allowed' } })

      local result_err, applied
      assert_true(dynconf.check_now('ev', function(e, a) result_err, applied = e, a end))
      backend.complete(nil, {
        allowed = { version = 1, values = { x = 3 } },
        blocked = { version = 1, values = { x = 4 } },
      })
      assert_not_nil(result_err:match('blocked'))
      assert_rspamd_table_eq({ expect = { 'allowed' }, actual = applied })
      assert_equal(b.x, 1)

      local dump = dynconf.dump()
      assert_not_nil(dump.modules.blocked)
      assert_equal(dump.modules.blocked.effective.x, 1)
      assert_equal(dump.modules.allowed.effective.x, 3)
      assert_rspamd_table_eq({ expect = { 'allowed' }, actual = dump.modules_allowed })
    end)
  end)

  context("Subscriber keys", function()
    local function with_config(fields, fn)
      local proxy = setmetatable(fields, { __index = real_config })
      _G.rspamd_config = proxy
      local ok, err = pcall(fn, proxy)
      _G.rspamd_config = real_config
      assert(ok, err)
    end

    test("a wildcard matches keys that are absent from the static config", function()
      local notified = {}
      with_config({
        get_all_opt = function(_, name)
          if name == 'keyed' then
            return { reject = 15, add_header = 6 }
          end
        end,
        dynconf_notify = function(_, module, tbl)
          table.insert(notified, { module = module, tbl = tbl })
          return true
        end,
        dynconf_bump_generation = function() end,
      }, function()
        local dynconf = fresh()
        assert_true(dynconf.register_c('keyed', { '*' }, { subscriber_keys = true }))
        local settings = dynconf.get('keyed')

        assert_true(dynconf.apply('test', 'keyed', { reject = 20, custom = 3 }))
        assert_equal(settings.reject, 20)
        assert_equal(settings.custom, 3)
        assert_equal(settings.add_header, 6)
        assert_rspamd_table_eq({ expect = { reject = 20, add_header = 6, custom = 3 }, actual = notified[1].tbl })

        -- Removing the override removes the key that has no static value and restores the others
        assert_true(dynconf.apply('test', 'keyed', nil))
        assert_equal(settings.reject, 15)
        assert_nil(settings.custom)
        assert_rspamd_table_eq({ expect = { reject = 15, add_header = 6 }, actual = notified[2].tbl })

        -- The type of a static value is still checked, a new key can have any type
        local ok, err = dynconf.apply('test', 'keyed', { reject = 'x' })
        assert_false(ok)
        assert_not_nil(err:match('type mismatch'))
        assert_true(dynconf.apply('test', 'keyed', { fresh_key = 'x' }))
        assert_equal(settings.fresh_key, 'x')
      end)
    end)

    test("without the option only existing keys can be overridden", function()
      with_config({
        get_all_opt = function(_, name)
          if name == 'plain' then
            return { reject = 15 }
          end
        end,
        dynconf_notify = function() return true end,
        dynconf_bump_generation = function() end,
      }, function()
        local dynconf = fresh()
        assert_true(dynconf.register_c('plain', { '*' }))
        local ok, err = dynconf.apply('test', 'plain', { custom = 3 })
        assert_false(ok)
        assert_not_nil(err:match('no such entry'))
        assert_true(dynconf.apply('test', 'plain', { reject = 3 }))
      end)
    end)

    test("nested patterns work and the subscriber can reject", function()
      local seen
      with_config({
        get_all_opt = function() return { Known = { enabled = true } } end,
        dynconf_notify = function(_, _, tbl)
          seen = tbl
          if tbl.Bad then
            return false, 'unknown symbol Bad'
          end
          return true
        end,
        dynconf_bump_generation = function() end,
      }, function()
        local dynconf = fresh()
        assert_true(dynconf.register_c('symbolish', { '*.enabled' }, { subscriber_keys = true }))
        assert_true(dynconf.apply('test', 'symbolish', { Other = { enabled = false } }))
        assert_rspamd_table_eq({ expect = { Known = { enabled = true }, Other = { enabled = false } }, actual = seen })

        -- A leaf that no pattern matches is still rejected by the registry
        local ok, err = dynconf.apply('test', 'symbolish', { Other = { score = 1 } })
        assert_false(ok)
        assert_not_nil(err:match('not dynamic'))

        -- The subscriber's rejection aborts the update, the previous override stays
        ok, err = dynconf.apply('test', 'symbolish', { Bad = { enabled = false } })
        assert_false(ok)
        assert_not_nil(err:match('unknown symbol Bad'))
        assert_equal(dynconf.get('symbolish').Other.enabled, false)
        assert_nil(dynconf.get('symbolish').Bad)
      end)
    end)

    test("static = false hides the static section from the registry", function()
      local seen
      with_config({
        get_all_opt = function() return { reject = 15, subject = 'spam %s' } end,
        dynconf_notify = function(_, _, tbl)
          seen = tbl
          return true
        end,
        dynconf_bump_generation = function() end,
      }, function()
        local dynconf = fresh()
        assert_true(dynconf.register_c('owned', { '*' }, { subscriber_keys = true, static = false }))
        assert_true(dynconf.apply('test', 'owned', { ['add header'] = 7 }))
        -- Only the overrides are delivered: the static state belongs to the subscriber
        assert_rspamd_table_eq({ expect = { ['add header'] = 7 }, actual = seen })
        assert_rspamd_table_eq({ expect = {}, actual = dynconf.dump({ module = 'owned' }).modules.owned.static })
        -- No type check against a static value that is not seen
        assert_true(dynconf.apply('test', 'owned', { reject = 'whatever' }))
        assert_true(dynconf.apply('test', 'owned', nil))
        assert_rspamd_table_eq({ expect = {}, actual = seen })
      end)
    end)
  end)


  -- Stale names: lenient deliveries and strict writes -----------------------------------------------

  context("Lenient deliveries and strict writes", function()
    local KNOWN = { A = true, B = true }

    -- Behaves like the C subscribers of the metric: an unknown name is skipped by a lenient update
    -- (unless the write names it) and rejects a strict one
    local function with_subscriber(fn)
      local calls = {}
      local proxy = setmetatable({
        get_all_opt = function() return {} end,
        add_on_load = function() end,
        dynconf_notify = function(_, module, tbl, opts)
          table.insert(calls, { module = module, tbl = tbl, opts = opts })
          local strict = {}
          for _, k in ipairs(opts and opts.strict or {}) do
            strict[k] = true
          end
          local skipped
          local names = {}
          for name in pairs(tbl) do
            names[#names + 1] = name
          end
          table.sort(names)
          for _, name in ipairs(names) do
            if not KNOWN[name] then
              local reason = 'unknown symbol ' .. name
              if not (opts and opts.lenient) or strict[name] then
                return false, reason
              end
              skipped = skipped or {}
              table.insert(skipped, reason)
            end
          end
          return true, nil, skipped
        end,
        dynconf_bump_generation = function() end,
      }, { __index = real_config })
      _G.rspamd_config = proxy
      local ok, err = pcall(fn, calls)
      _G.rspamd_config = real_config
      assert(ok, err)
    end

    local function register_keyed(dynconf)
      assert(dynconf.register_c('scoresish', { '*' }, { subscriber_keys = true, static = false }))
      return dynconf.get('scoresish')
    end

    test("a direct apply is strict, a delivery of a backend is lenient", function()
      with_subscriber(function(calls)
        local dynconf = fresh()
        register_keyed(dynconf)
        local ok, err = dynconf.apply('test', 'scoresish', { A = 1, STALE = 2 })
        assert_false(ok)
        assert_not_nil(err:match('unknown symbol STALE'))
        assert_nil(calls[1].opts)

        local backend = with_fake_backend(dynconf, 'fake')
        local cb_err, applied
        assert_true(dynconf.check_now('ev', function(e, a) cb_err, applied = e, a end))
        backend.complete(nil, { scoresish = { version = 1, values = { A = 1, STALE = 2 } } })
        -- The rest is applied; the skipped name is not a failure of the check ...
        assert_nil(cb_err)
        assert_rspamd_table_eq({ expect = { 'scoresish' }, actual = applied })
        assert_equal(dynconf.get('scoresish').A, 1)
        assert_true(calls[#calls].opts.lenient)
        -- ... but the operator can see it, in the state of the backend and in the dump of the module
        local dump = dynconf.dump()
        assert_not_nil(dump.backends.fake.last_error:match('unknown symbol STALE'))
        assert_rspamd_table_eq({ expect = { 'unknown symbol STALE' }, actual = dump.modules.scoresish.skipped })
        -- The stale entry is stored as it is
        assert_equal(dump.modules.scoresish.overrides.fake.values.STALE, 2)

        -- A later delivery that does not carry it clears the report
        assert_true(dynconf.check_now('ev'))
        backend.complete(nil, { scoresish = { version = 2, values = { A = 1 } } })
        dump = dynconf.dump()
        assert_nil(dump.backends.fake.last_error)
        assert_nil(dump.modules.scoresish.skipped)
      end)
    end)

    test("a stale stored name does not block a write that does not touch it", function()
      with_subscriber(function(calls)
        local dynconf = fresh()
        local settings = register_keyed(dynconf)
        local stored = { A = 1, STALE = 2 }
        dynconf.register_backend('writer', {
          check = function() end,
          update = function(_, _, patch, prepare, cb)
            local merged = {}
            for k, v in pairs(stored) do
              merged[k] = v
            end
            for k, v in pairs(patch) do
              merged[k] = v or nil
            end
            local ok, err = prepare(next(merged) and merged or nil)
            if not ok then
              cb(err, nil, true)
              return
            end
            stored = merged
            cb(nil, 1)
          end,
          set = function(_, _, values, cb)
            stored = values or {}
            cb(nil, 1)
          end,
        })
        assert_true(dynconf.configure({ enabled = true, backend = 'writer', policy = 'manual' }))

        -- The write changes B only: the stale entry stays where it is
        local done_err, rejected = 'unset', nil
        assert_true(dynconf.update('scoresish', { B = 5 }, { ev_base = 'ev' }, function(e, r)
          done_err, rejected = e, r
        end))
        assert_nil(done_err)
        assert_nil(rejected)
        assert_equal(stored.B, 5)
        assert_equal(stored.STALE, 2)
        assert_equal(settings.B, 5)
        assert_rspamd_table_eq({ expect = { 'B' }, actual = calls[#calls].opts.strict })
        assert_true(calls[#calls].opts.lenient)

        -- A name that the write itself brings is still refused, and nothing is stored
        done_err, rejected = 'unset', nil
        assert_true(dynconf.update('scoresish', { NEW_STALE = 3 }, { ev_base = 'ev' }, function(e, r)
          done_err, rejected = e, r
        end))
        assert_not_nil(done_err:match('unknown symbol NEW_STALE'))
        assert_true(rejected)
        assert_nil(stored.NEW_STALE)
        assert_nil(settings.NEW_STALE)
        assert_equal(settings.B, 5)

        -- Removing the stale entry is a write like any other
        done_err = 'unset'
        assert_true(dynconf.update('scoresish', { STALE = false }, { ev_base = 'ev' }, function(e) done_err = e end))
        assert_nil(done_err)
        assert_nil(stored.STALE)
        assert_nil(settings.STALE)
        assert_nil(dynconf.dump().modules.scoresish.skipped)
      end)
    end)

    test("a write that sets a stored entry that was skipped is validated nevertheless", function()
      with_subscriber(function(calls)
        local dynconf = fresh()
        register_keyed(dynconf)
        local stored = { A = 1, STALE = 2 }
        dynconf.register_backend('writer', {
          check = function() end,
          update = function(_, _, patch, prepare, cb)
            local merged = {}
            for k, v in pairs(stored) do
              merged[k] = v
            end
            for k, v in pairs(patch) do
              merged[k] = v or nil
            end
            local ok, err = prepare(next(merged) and merged or nil)
            if not ok then
              cb(err, nil, true)
              return
            end
            stored = merged
            cb(nil, 1)
          end,
          set = function(_, _, values, cb)
            stored = values or {}
            cb(nil, 1)
          end,
        })
        assert_true(dynconf.configure({ enabled = true, backend = 'writer', policy = 'manual' }))
        -- The stored entry has been delivered and skipped: the value that the write sets is the same one
        assert_true(dynconf.apply('writer', 'scoresish', stored, 1, { lenient = true }))
        assert_equal(#dynconf.dump().modules.scoresish.skipped, 1)
        local before = #calls

        local done_err, rejected = 'unset', nil
        assert_true(dynconf.update('scoresish', { STALE = 2 }, { ev_base = 'ev' }, function(e, r)
          done_err, rejected = e, r
        end))
        -- Not a silent success: the subscriber has been asked, although no value differs
        assert_true(#calls > before)
        assert_not_nil(tostring(done_err):match('unknown symbol STALE'))
        assert_true(rejected)

        -- The same for set
        local ok, err = dynconf.set('scoresish', { A = 1, STALE = 3 }, { ev_base = 'ev' })
        assert_false(ok)
        assert_not_nil(err:match('unknown symbol STALE'))
      end)
    end)

    test("the skipped entries are offered again at every check, and stay in last_error", function()
      with_subscriber(function(calls)
        local dynconf = fresh()
        local settings = register_keyed(dynconf)
        local backend = with_fake_backend(dynconf, 'fake')
        assert_true(dynconf.check_now('ev'))
        backend.complete(nil, { scoresish = { version = 1, values = { A = 1, LATE = 2 } } })
        assert_not_nil(dynconf.dump().backends.fake.last_error:match('unknown symbol LATE'))
        assert_equal(settings.A, 1)

        -- A check that delivers nothing does not clear the report, and offers the entry again, quietly
        local before = #calls
        assert_true(dynconf.check_now('ev'))
        backend.complete(nil, {})
        assert_true(#calls > before)
        assert_true(calls[#calls].opts.lenient)
        assert_true(calls[#calls].opts.quiet)
        assert_not_nil(dynconf.dump().backends.fake.last_error:match('unknown symbol LATE'))
        assert_rspamd_table_eq({ expect = { 'unknown symbol LATE' },
                                 actual = dynconf.dump().modules.scoresish.skipped })

        -- The name appears later (a map has loaded): the next check applies the entry
        KNOWN.LATE = true
        local ok, err = pcall(function()
          assert_true(dynconf.check_now('ev'))
          backend.complete(nil, {})
        end)
        KNOWN.LATE = nil
        assert(ok, err)
        local dump = dynconf.dump()
        assert_nil(dump.modules.scoresish.skipped)
        assert_nil(dump.backends.fake.last_error)
        assert_equal(dump.modules.scoresish.overrides.fake.values.LATE, 2)

        -- Nothing is offered when nothing is skipped
        before = #calls
        assert_true(dynconf.check_now('ev'))
        backend.complete(nil, {})
        assert_equal(#calls, before)
      end)
    end)

    test("a retry keeps the time of the update", function()
      with_subscriber(function()
        local dynconf = fresh()
        register_keyed(dynconf)
        local backend = with_fake_backend(dynconf, 'fake')
        assert_true(dynconf.check_now('ev'))
        backend.complete(nil, { scoresish = { version = 1, values = { A = 1, LATE = 2 } } })
        local updated = dynconf.dump().modules.scoresish.overrides.fake.updated
        assert_not_nil(updated)

        assert_true(dynconf.check_now('ev'))
        backend.complete(nil, {})
        assert_equal(dynconf.dump().modules.scoresish.overrides.fake.updated, updated)
      end)
    end)

    test("set is strict about the entries that it changes only", function()
      with_subscriber(function(calls)
        local dynconf = fresh()
        register_keyed(dynconf)
        dynconf.register_backend('writer', {
          check = function() end,
          set = function(_, _, _, cb) cb(nil, 1) end,
        })
        assert_true(dynconf.configure({ enabled = true, backend = 'writer', policy = 'manual' }))
        -- A stale entry that has been delivered
        assert_true(dynconf.apply('writer', 'scoresish', { A = 1, STALE = 2 }, 1, { lenient = true }))

        -- The same document with a change of a known entry: accepted
        assert_true(dynconf.set('scoresish', { A = 9, STALE = 2 }, { ev_base = 'ev' }))
        assert_rspamd_table_eq({ expect = { 'A' }, actual = calls[#calls].opts.strict })
        assert_equal(dynconf.get('scoresish').A, 9)

        -- A changed stale entry, or a new one, is refused
        local ok, err = dynconf.set('scoresish', { A = 9, STALE = 3 }, { ev_base = 'ev' })
        assert_false(ok)
        assert_not_nil(err:match('unknown symbol STALE'))
        ok, err = dynconf.set('scoresish', { A = 9, STALE = 2, OTHER = 1 }, { ev_base = 'ev' })
        assert_false(ok)
        assert_not_nil(err:match('unknown symbol OTHER'))
        assert_equal(dynconf.get('scoresish').A, 9)
      end)
    end)

    test("override returns the stored override, stale names included; backend names the backend", function()
      with_subscriber(function()
        local dynconf = fresh()
        register_keyed(dynconf)
        -- Disabled: no backend, no override
        assert_nil(dynconf.backend())
        local backend = with_fake_backend(dynconf, 'fake')
        assert_equal(dynconf.backend(), 'fake')
        assert_nil(dynconf.override('scoresish'))
        assert_nil(dynconf.override('nosuchmodule'))

        assert_true(dynconf.check_now('ev'))
        backend.complete(nil, { scoresish = { version = 1, values = { A = 1, STALE = 2 } } })
        local ov = dynconf.override('scoresish')
        assert_rspamd_table_eq({ expect = { A = 1, STALE = 2 }, actual = ov })
        -- A copy: changing it does not change the registry
        ov.A = 100
        assert_equal(dynconf.override('scoresish').A, 1)
      end)
    end)

    test("a write that fails is rolled back to a state that may hold stale names", function()
      with_subscriber(function()
        local dynconf = fresh()
        register_keyed(dynconf)
        local fail = false
        dynconf.register_backend('writer', {
          check = function() end,
          set = function(_, _, _, cb) cb(fail and 'disk is full' or nil, 1) end,
        })
        assert_true(dynconf.configure({ enabled = true, backend = 'writer', policy = 'manual' }))
        assert_true(dynconf.apply('writer', 'scoresish', { A = 1, STALE = 2 }, 1, { lenient = true }))

        fail = true
        local done_err
        assert_true(dynconf.set('scoresish', { A = 5, STALE = 2 }, { ev_base = 'ev' }, function(e) done_err = e end))
        assert_equal(done_err, 'disk is full')
        -- The rollback has restored the previous override, the stale entry included
        assert_equal(dynconf.get('scoresish').A, 1)
        assert_equal(dynconf.get('scoresish').STALE, 2)
      end)
    end)
  end)


  -- File backend ---------------------------------------------------------------------------------

  context("File backend", function()
    local dirs = {}

    local function temp_dir()
      local name = os.tmpname()
      os.remove(name)
      assert(real_util.mkdir(name))
      table.insert(dirs, name)
      return name
    end

    local function cleanup()
      for _, dir in ipairs(dirs) do
        for _, f in ipairs({ 'dynconf.json', 'dynconf.json.lock', 'dynconf.json.tmp' }) do
          os.remove(dir .. '/' .. f)
        end
        os.remove(dir)
      end
      dirs = {}
    end

    local function write_file(path, content)
      local f = assert(io.open(path, 'wb'))
      f:write(content)
      f:close()
    end

    local function read_file(path)
      local f = io.open(path, 'rb')
      if not f then
        return nil
      end
      local data = f:read('*a')
      f:close()
      return data
    end

    local function decode(str)
      local parser = require("ucl").parser()
      local ok, err = parser:parse_string(str)
      assert(ok, err)
      return parser:get_object()
    end

    -- A registry that uses the file backend of `dir`, with two modules
    local function file_registry(dir, extra)
      local dynconf = fresh()
      local section = { enabled = true, backend = 'file', policy = 'manual', path = dir .. '/dynconf.json' }
      for k, v in pairs(extra or {}) do
        section[k] = v
      end
      assert(dynconf.configure(section))
      local a = dynconf.register('alpha', { defaults = { n = 1, s = 'x', list = { 1, 2 } }, opts = false,
                                            dynamic = { 'n', 'list' } })
      local b = dynconf.register('beta', { defaults = { n = 10 }, opts = false, dynamic = { 'n' } })
      return dynconf, a, b
    end

    local function check(dynconf)
      local err, applied
      assert(dynconf.check_now(nil, function(e, a) err, applied = e, a end))
      return err, applied
    end

    test("a missing file means no overrides and no errors", function()
      local dir = temp_dir()
      local dynconf, a = file_registry(dir)
      for _ = 1, 3 do
        local err, applied = check(dynconf)
        assert_nil(err)
        assert_equal(#applied, 0)
      end
      assert_equal(a.n, 1)
      local dump = dynconf.dump()
      assert_nil(dump.backends.file.last_error)
      assert_not_nil(dump.backends.file.last_check)
      -- Reading never creates the file
      assert_nil(read_file(dir .. '/dynconf.json'))
      cleanup()
    end)

    test("reads, changes and removes overrides", function()
      local dir = temp_dir()
      local path = dir .. '/dynconf.json'
      local dynconf, a, b = file_registry(dir)

      write_file(path, '{"v":3,"modules":{"alpha":{"v":3,"o":{"n":5,"list":[7,8,9]}}}}')
      local err, applied = check(dynconf)
      assert_nil(err)
      assert_rspamd_table_eq({ expect = { 'alpha' }, actual = applied })
      assert_equal(a.n, 5)
      assert_rspamd_table_eq({ expect = { 7, 8, 9 }, actual = a.list })
      assert_equal(b.n, 10)
      assert_equal(dynconf.dump().modules.alpha.overrides.file.version, 3)
      assert_equal(dynconf.dump().backends.file.version, 3)

      -- Nothing changed: nothing is applied
      err, applied = check(dynconf)
      assert_nil(err)
      assert_equal(#applied, 0)

      -- Another module appears and the first one changes
      write_file(path, '{"v":4,"modules":{"alpha":{"v":4,"o":{"n":6}},"beta":{"v":4,"o":{"n":11}}}}')
      err, applied = check(dynconf)
      assert_nil(err)
      assert_rspamd_table_eq({ expect = { 'alpha', 'beta' }, actual = applied })
      assert_equal(a.n, 6)
      assert_rspamd_table_eq({ expect = { 1, 2 }, actual = a.list })
      assert_equal(b.n, 11)

      -- A module that vanished reverts
      write_file(path, '{"v":5,"modules":{"beta":{"v":4,"o":{"n":11}}}}')
      err, applied = check(dynconf)
      assert_nil(err)
      assert_rspamd_table_eq({ expect = { 'alpha' }, actual = applied })
      assert_equal(a.n, 1)
      assert_equal(b.n, 11)

      -- So does a deleted file
      os.remove(path)
      err, applied = check(dynconf)
      assert_nil(err)
      assert_rspamd_table_eq({ expect = { 'beta' }, actual = applied })
      assert_equal(b.n, 10)
      cleanup()
    end)

    test("a rewrite within the same second with the same size is noticed", function()
      local dir = temp_dir()
      local path = dir .. '/dynconf.json'
      local dynconf, a = file_registry(dir)
      write_file(path, '{"v":1,"modules":{"alpha":{"v":1,"o":{"n":5}}}}')
      assert_nil((check(dynconf)))
      assert_equal(a.n, 5)
      write_file(path, '{"v":2,"modules":{"alpha":{"v":2,"o":{"n":6}}}}')
      assert_nil((check(dynconf)))
      assert_equal(a.n, 6)
      write_file(path, '{"v":3,"modules":{"alpha":{"v":3,"o":{"n":7}}}}')
      assert_nil((check(dynconf)))
      assert_equal(a.n, 7)
      cleanup()
    end)

    test("a broken file keeps the last good values", function()
      local dir = temp_dir()
      local path = dir .. '/dynconf.json'
      local dynconf, a = file_registry(dir)
      write_file(path, '{"v":1,"modules":{"alpha":{"v":1,"o":{"n":5}}}}')
      assert_nil((check(dynconf)))

      write_file(path, '{"v":2,"modules":{"alpha":')
      local err = check(dynconf)
      assert_not_nil(err)
      assert_not_nil(err:match('cannot parse'))
      assert_equal(a.n, 5)
      assert_not_nil(dynconf.dump().backends.file.last_error)
      -- One broken module entry does not hide the others
      write_file(path, '{"v":3,"modules":{"alpha":{"v":3,"o":{"n":6}},"beta":"oops"}}')
      assert_nil((check(dynconf)))
      assert_equal(a.n, 6)

      -- A directory is not a file
      os.remove(path)
      assert_true(real_util.mkdir(path))
      err = check(dynconf)
      assert_not_nil(err)
      assert_equal(a.n, 6)
      os.remove(path)
      cleanup()
    end)

    test("the file size is bounded", function()
      local dir = temp_dir()
      local path = dir .. '/dynconf.json'
      local dynconf, a = file_registry(dir, { max_size = 64 })
      write_file(path, '{"v":1,"modules":{"alpha":{"v":1,"o":{"n":5}}}}' .. string.rep(' ', 100))
      local err = check(dynconf)
      assert_not_nil(err)
      assert_not_nil(err:match('larger than'))
      assert_equal(a.n, 1)
      cleanup()
    end)

    test("overrides that the registry rejects are reported", function()
      local dir = temp_dir()
      local path = dir .. '/dynconf.json'
      local dynconf, a = file_registry(dir)
      write_file(path, '{"v":1,"modules":{"alpha":{"v":1,"o":{"s":"y"}},"beta":{"v":1,"o":{"n":12}}}}')
      local err, applied = check(dynconf)
      assert_not_nil(err)
      assert_not_nil(err:match('alpha'))
      assert_rspamd_table_eq({ expect = { 'beta' }, actual = applied })
      assert_equal(a.s, 'x')
      cleanup()
    end)

    test("set creates the file, merges modules and removes overrides", function()
      local dir = temp_dir()
      local path = dir .. '/dynconf.json'
      local dynconf, a, b = file_registry(dir)

      local done_err = 'unset'
      assert_true(dynconf.set('alpha', { n = 3, list = { 4, 5 } }, nil, function(e) done_err = e end))
      assert_nil(done_err)
      assert_equal(a.n, 3)
      local doc = decode(read_file(path))
      assert_equal(doc.v, 1)
      assert_equal(doc.modules.alpha.v, 1)
      assert_equal(doc.modules.alpha.o.n, 3)
      assert_rspamd_table_eq({ expect = { 4, 5 }, actual = doc.modules.alpha.o.list })

      assert_true(dynconf.set('beta', { n = 2.5 }, nil, function(e) done_err = e end))
      assert_nil(done_err)
      assert_equal(b.n, 2.5)
      doc = decode(read_file(path))
      assert_equal(doc.v, 2)
      assert_equal(doc.modules.beta.v, 2)
      assert_equal(doc.modules.beta.o.n, 2.5)
      assert_equal(doc.modules.alpha.o.n, 3)
      -- The writer's own write is not applied again
      assert_equal(#select(2, check(dynconf)), 0)

      -- A second worker reads what the controller wrote
      local other, oa, ob = file_registry(dir)
      assert_nil((check(other)))
      assert_equal(oa.n, 3)
      assert_equal(ob.n, 2.5)

      assert_true(dynconf.set('alpha', nil, nil, function(e) done_err = e end))
      assert_nil(done_err)
      assert_equal(a.n, 1)
      doc = decode(read_file(path))
      assert_nil(doc.modules.alpha)
      assert_equal(doc.modules.beta.o.n, 2.5)
      -- and the other worker follows
      assert_nil((check(other)))
      assert_equal(oa.n, 1)
      assert_equal(ob.n, 2.5)

      -- No temporary files are left
      assert_nil(read_file(path .. '.tmp'))
      cleanup()
    end)

    test("set keeps what another writer stored in the meantime", function()
      local dir = temp_dir()
      local path = dir .. '/dynconf.json'
      local dynconf = file_registry(dir)
      -- Another controller has written `beta` after this one has looked at the file
      write_file(path, '{"v":7,"modules":{"beta":{"v":7,"o":{"n":99}}}}')
      assert_true(dynconf.set('alpha', { n = 4 }, nil))
      local doc = decode(read_file(path))
      assert_equal(doc.v, 8)
      assert_equal(doc.modules.alpha.o.n, 4)
      assert_equal(doc.modules.beta.o.n, 99)
      assert_equal(doc.modules.beta.v, 7)
      -- and this one learns about it with the next check
      local _, applied = check(dynconf)
      assert_rspamd_table_eq({ expect = { 'beta' }, actual = applied })
      assert_equal(dynconf.get('beta').n, 99)
      cleanup()
    end)

    test("set does not overwrite a file it cannot read", function()
      local dir = temp_dir()
      local path = dir .. '/dynconf.json'
      local dynconf, a = file_registry(dir)
      write_file(path, 'this is not json')
      local done_err
      assert_true(dynconf.set('alpha', { n = 4 }, nil, function(e) done_err = e end))
      assert_not_nil(done_err)
      assert_equal(read_file(path), 'this is not json')
      -- The local change is rolled back
      assert_equal(a.n, 1)
      cleanup()
    end)

    test("set reports an unwritable location and rolls back", function()
      local dynconf, a = file_registry('/nonexistent-dynconf-dir')
      local done_err
      assert_true(dynconf.set('alpha', { n = 4 }, nil, function(e) done_err = e end))
      assert_not_nil(done_err)
      assert_equal(a.n, 1)
    end)

    test("set validates before it writes", function()
      local dir = temp_dir()
      local dynconf = file_registry(dir)
      local ok, err = dynconf.set('alpha', { s = 'y' }, nil)
      assert_false(ok)
      assert_not_nil(err)
      assert_nil(read_file(dir .. '/dynconf.json'))
      cleanup()
    end)

    test("load_offline reads the file without an event loop", function()
      local dir = temp_dir()
      local path = dir .. '/dynconf.json'
      write_file(path, '{"v":2,"modules":{"alpha":{"v":2,"o":{"n":8}}}}')
      local dynconf, a = file_registry(dir)
      assert_equal(a.n, 1)
      assert_true(dynconf.load_offline())
      assert_equal(a.n, 8)
      assert_equal(dynconf.dump().modules.alpha.overrides.file.values.n, 8)
      assert_equal(dynconf.dump().modules.alpha.effective.n, 8)

      -- A missing file is fine too
      os.remove(path)
      assert_true(dynconf.load_offline())
      assert_equal(a.n, 1)

      -- A broken one is reported
      write_file(path, '{')
      local ok, err = dynconf.load_offline()
      assert_false(ok)
      assert_not_nil(err)
      cleanup()
    end)

    test("load_offline needs a synchronous backend", function()
      local dynconf = fresh()
      with_fake_backend(dynconf, 'fake')
      local ok, err = dynconf.load_offline()
      assert_false(ok)
      assert_nil(err)
      -- and neither does the passive store
      ok, err = fresh().load_offline()
      assert_false(ok)
      assert_nil(err)
    end)

    test("the interval policy polls the file from the periodic", function()
      local dir = temp_dir()
      local path = dir .. '/dynconf.json'
      local periodic, on_load
      local proxy = setmetatable({
        add_on_load = function(_, fn) on_load = fn end,
        add_periodic = function(_, _, timeout, fn) periodic = { timeout = timeout, fn = fn } end,
        get_all_opt = function() return nil end,
      }, { __index = real_config })
      _G.rspamd_config = proxy
      local ok, err = pcall(function()
        local dynconf = fresh()
        assert_true(dynconf.configure({ backend = 'file', path = path, interval = 7, jitter = 0 }))
        local a = dynconf.register('alpha', { defaults = { n = 1 }, opts = false, dynamic = { 'n' } })
        dynconf.register_c('actions', { '*' }, { subscriber_keys = true })
        on_load(proxy, 'ev', nil)
        -- No file: ticks are silent and cost one stat
        assert_equal(periodic.fn(), 7)
        assert_nil(dynconf.dump().backends.file.last_error)
        -- `alpha` is not in the default allow-list, so the update is refused, and `actions` has no C
        -- subscriber here: only the framework path is under test
        write_file(path, '{"v":1,"modules":{"alpha":{"v":1,"o":{"n":5}}}}')
        assert_equal(periodic.fn(), 7)
        assert_equal(a.n, 1)
        assert_not_nil(dynconf.dump().backends.file.last_error:match('alpha'))
      end)
      _G.rspamd_config = real_config
      cleanup()
      assert(ok, err)
    end)

    test("update changes some keys of the override and keeps the others", function()
      local dir = temp_dir()
      local path = dir .. '/dynconf.json'
      local dynconf, a = file_registry(dir)
      -- Both modules accept overrides when the framework is configured explicitly
      local function update(module, patch)
        local done, derr
        local ok, err = dynconf.update(module, patch, nil, function(e)
          done, derr = true, e
        end)
        assert_true(ok, err)
        assert_true(done)
        assert_nil(derr)
      end

      update('alpha', { n = 5 })
      assert_equal(a.n, 5)
      update('alpha', { list = { 3, 4 } })
      assert_equal(a.n, 5)
      assert_rspamd_table_eq({ expect = { 3, 4 }, actual = a.list })
      local written = decode(read_file(path))
      assert_equal(written.modules.alpha.o.n, 5)
      assert_rspamd_table_eq({ expect = { 3, 4 }, actual = written.modules.alpha.o.list })

      -- `false` removes a key, the other one stays
      update('alpha', { n = false })
      assert_equal(a.n, 1)
      assert_rspamd_table_eq({ expect = { 3, 4 }, actual = a.list })
      assert_nil(decode(read_file(path)).modules.alpha.o.n)

      -- The override goes away with its last key
      update('alpha', { list = false })
      assert_rspamd_table_eq({ expect = { 1, 2 }, actual = a.list })
      assert_nil(decode(read_file(path)).modules.alpha)
      assert_equal(next(dynconf.dump().modules.alpha.overrides), nil)

      -- Errors are reported before anything is written
      local ok, err = dynconf.update('alpha', { s = 'y' }, nil, function() end)
      assert_false(ok)
      assert_not_nil(err:match('not dynamic'))
      ok, err = dynconf.update('nosuch', { n = 1 }, nil, function() end)
      assert_false(ok)
      assert_not_nil(err:match('unknown module'))
      ok, err = dynconf.update('alpha', 'x', nil, function() end)
      assert_false(ok)
      cleanup()
    end)

    test("update is refused when dynconf is disabled", function()
      local dynconf = fresh()
      dynconf.register('alpha', { defaults = { n = 1 }, opts = false, dynamic = { 'n' } })
      local ok, err = dynconf.update('alpha', { n = 2 }, nil, function() end)
      assert_false(ok)
      assert_not_nil(err:match('not enabled'))
    end)

    test("update merges into what the file holds, not into what was applied", function()
      local dir = temp_dir()
      local path = dir .. '/dynconf.json'
      local dynconf, a = file_registry(dir)
      write_file(path, '{"v":1,"modules":{"alpha":{"v":1,"o":{"n":5}}}}')
      assert_nil((check(dynconf)))
      assert_equal(a.n, 5)

      -- Somebody else has stored one more key since the last check
      write_file(path, '{"v":2,"modules":{"alpha":{"v":2,"o":{"n":5,"list":[9]}}}}')
      local done, derr, rejected
      assert_true(dynconf.update('alpha', { n = 6 }, nil, function(e, r) done, derr, rejected = true, e, r end))
      assert_true(done)
      assert_nil(derr)
      assert_nil(rejected)
      local o = decode(read_file(path)).modules.alpha.o
      assert_equal(o.n, 6)
      assert_rspamd_table_eq({ expect = { 9 }, actual = o.list })
      assert_equal(a.n, 6)
      assert_rspamd_table_eq({ expect = { 9 }, actual = a.list })
      cleanup()
    end)

    test("update does not lose an override that the registry has refused", function()
      local dir = temp_dir()
      local path = dir .. '/dynconf.json'
      local dynconf, a = file_registry(dir)
      -- `s` is not dynamic: the registry rejects the whole entry, but it is still in the file
      local content = '{"v":1,"modules":{"alpha":{"v":1,"o":{"n":3,"s":"y"}}}}'
      write_file(path, content)
      assert_not_nil((check(dynconf)))
      assert_equal(a.n, 1)

      local done, derr, rejected
      assert_true(dynconf.update('alpha', { n = 7 }, nil, function(e, r) done, derr, rejected = true, e, r end))
      assert_true(done)
      -- The merged override is refused, nothing is written and nothing is lost
      assert_not_nil(derr)
      assert_true(rejected)
      assert_equal(read_file(path), content)
      assert_equal(a.n, 1)
      cleanup()
    end)

    test("the backend knows what it holds, whether or not the registry has applied it", function()
      local dir = temp_dir()
      local path = dir .. '/dynconf.json'
      local dynconf = file_registry(dir)
      write_file(path, '{"v":1,"modules":{"alpha":{"v":1,"o":{"s":"y"}}}}')
      assert_not_nil((check(dynconf)))
      -- The entry is refused (nothing applied), yet the backend holds it
      assert_nil(next(dynconf.dump().modules.alpha.overrides))
      assert_true(require("lua_dynconf.file").holds('alpha'))
      assert_false(require("lua_dynconf.file").holds('beta'))
      cleanup()
    end)

    test("an empty file removes the applied overrides", function()
      local dir = temp_dir()
      local path = dir .. '/dynconf.json'
      local dynconf, a = file_registry(dir)
      write_file(path, '{"v":1,"modules":{"alpha":{"v":1,"o":{"n":5}}}}')
      assert_nil((check(dynconf)))
      assert_equal(a.n, 5)
      write_file(path, '')
      local err, applied = check(dynconf)
      assert_nil(err)
      assert_rspamd_table_eq({ expect = { 'alpha' }, actual = applied })
      assert_equal(a.n, 1)
      cleanup()
    end)

    test("a failure that a retry cannot fix is reported once", function()
      local dir = temp_dir()
      local path = dir .. '/dynconf.json'
      local dynconf, a = file_registry(dir)
      -- A directory is not a file
      assert_true(real_util.mkdir(path))
      local errors = 0
      for _ = 1, 4 do
        local err = check(dynconf)
        if err then
          errors = errors + 1
        end
      end
      assert_equal(errors, 1)
      assert_equal(a.n, 1)
      -- and the file that replaces it is read as usual
      os.remove(path)
      write_file(path, '{"v":1,"modules":{"alpha":{"v":1,"o":{"n":5}}}}')
      assert_nil((check(dynconf)))
      assert_equal(a.n, 5)
      os.remove(path)
      cleanup()
    end)

    test("a worker reads the file as soon as it starts", function()
      local dir = temp_dir()
      local path = dir .. '/dynconf.json'
      write_file(path, '{"v":1,"modules":{"alpha":{"v":1,"o":{"n":5}}}}')
      local periodic, on_load
      local proxy = setmetatable({
        add_on_load = function(_, fn) on_load = fn end,
        add_periodic = function(_, _, timeout, fn) periodic = { timeout = timeout, fn = fn } end,
        get_all_opt = function() return nil end,
      }, { __index = real_config })
      _G.rspamd_config = proxy
      local ok, err = pcall(function()
        local dynconf = fresh()
        assert_true(dynconf.configure({ enabled = true, backend = 'file', path = path, interval = 7, jitter = 0 }))
        local a = dynconf.register('alpha', { defaults = { n = 1 }, opts = false, dynamic = { 'n' } })
        assert_equal(a.n, 1)
        on_load(proxy, 'ev', nil)
        -- No waiting for the first tick of the periodic
        assert_equal(a.n, 5)
        assert_not_nil(periodic)
      end)
      _G.rspamd_config = real_config
      cleanup()
      assert(ok, err)
    end)
  end)

  context("Legacy import", function()
    local ucl = require "ucl"
    local dirs = {}

    local function temp_dir()
      local name = os.tmpname()
      os.remove(name)
      assert(real_util.mkdir(name))
      table.insert(dirs, name)
      return name
    end

    local function cleanup()
      for _, dir in ipairs(dirs) do
        for _, f in ipairs({ 'dynconf.json', 'dynconf.json.lock', 'dynconf.json.tmp', 'rspamd_dynamic',
                             'rspamd_dynamic.imported' }) do
          os.remove(dir .. '/' .. f)
        end
        os.remove(dir)
      end
      dirs = {}
    end

    local function write_file(path, content)
      local f = assert(io.open(path, 'wb'))
      f:write(content)
      f:close()
    end

    local function read_file(path)
      local f = io.open(path, 'rb')
      if not f then
        return nil
      end
      local data = f:read('*a')
      f:close()
      return data
    end

    local function decode(str)
      local parser = ucl.parser()
      local ok, err = parser:parse_string(str)
      assert(ok, err)
      return parser:get_object()
    end

    -- What the C side knows: symbols with scores, actions with thresholds, a few actions without one
    local function make_lookup()
      -- SYM_FIXED and `quarantine` are defined in override.d: no override can change them
      local scores = { SYM_A = 2.0, SYM_B = 1.0, SYM_FIXED = 3.0 }
      local symbols = { SYM_A = true, SYM_B = true, SYM_C = true }
      local thresholds = { reject = 15, ['add header'] = 6, quarantine = 25 }
      local no_threshold = { greylist = true, ['rewrite subject'] = true }
      local masked = { SYM_FIXED = true, quarantine = true }
      return function(module, key)
        if module == 'scores' then
          return scores[key], false, scores[key] ~= nil, masked[key] == true
        elseif module == 'symbols' then
          return nil, false, symbols[key] == true, false
        elseif module == 'actions' then
          -- `add_header` and `add header` are one action
          local name = key:gsub('_', ' ')
          return thresholds[name], false, thresholds[name] ~= nil or no_threshold[name] == true,
              masked[name] == true
        end
        return nil, false, false, false
      end
    end

    local LEGACY_FILE = [=[[
      {"metric": "default",
       "symbols": [{"name": "SYM_A", "value": 10}, {"name": "SYM_B", "value": 1.0},
                   {"name": "NO_SUCH", "value": 3}, {"name": "SYM_A", "value": 12}, {"name": "BAD"}],
       "actions": [{"name": "reject", "value": 20}, {"name": "add_header", "value": 6},
                   {"name": "greylist", "value": 4}, {"name": "nonsense", "value": 1},
                   {"name": "rewrite subject", "value": null}]},
      {"metric": "other", "symbols": [{"name": "SYM_B", "value": 5}]},
      {"no": "metric attribute"}
    ]]=]

    context("Conversion", function()
      test("a legacy file is merged and filtered", function()
        local legacy = require "lua_dynconf.legacy"
        local res, err = legacy.convert_file(decode(LEGACY_FILE), make_lookup())
        assert_nil(err)
        -- A later entry wins, unknown names, nulls and static values are left out
        assert_rspamd_table_eq({ expect = { SYM_A = 12, SYM_B = 5 }, actual = res.overrides.scores })
        assert_rspamd_table_eq({ expect = { reject = 20, greylist = 4 }, actual = res.overrides.actions })
        assert_nil(res.overrides.symbols)
        assert_equal(res.counts.scores, 2)
        assert_equal(res.counts.actions, 2)
        local skipped = table.concat(res.skipped, '\n')
        for _, what in ipairs({ 'NO_SUCH', 'nonsense', 'rewrite subject', 'add header', 'metric' }) do
          assert_not_nil(skipped:find(what, 1, true), what)
        end
      end)

      test("an entry that override.d defines is left out, not imported to fail the write", function()
        local legacy = require "lua_dynconf.legacy"
        local doc = decode('[{"metric": "default", ' ..
            '"symbols": [{"name": "SYM_FIXED", "value": 9}, {"name": "SYM_A", "value": 9}], ' ..
            '"actions": [{"name": "quarantine", "value": 40}, {"name": "reject", "value": 40}]}]')
        local res = legacy.convert_file(doc, make_lookup())
        assert_rspamd_table_eq({ expect = { SYM_A = 9 }, actual = res.overrides.scores })
        assert_rspamd_table_eq({ expect = { reject = 40 }, actual = res.overrides.actions })
        local skipped = table.concat(res.skipped, '\n')
        assert_not_nil(skipped:find('the score of SYM_FIXED is defined with a higher priority', 1, true))
        assert_not_nil(skipped:find('the threshold of the action quarantine is defined with a higher priority', 1, true))

        res = legacy.convert_redis(decode('{"scores": {"SYM_FIXED": 9, "SYM_B": 4}, "actions": {"quarantine": 40}}'),
            make_lookup())
        assert_rspamd_table_eq({ expect = { SYM_B = 4 }, actual = res.overrides.scores })
        assert_nil(res.overrides.actions)
        assert_equal(#res.skipped, 2)
      end)

      test("the spellings of an action are one action", function()
        local legacy = require "lua_dynconf.legacy"
        local doc = decode('[{"metric": "default", "actions": [{"name": "add_header", "value": 8}, ' ..
            '{"name": "add header", "value": 9}]}]')
        local res = legacy.convert_file(doc, make_lookup())
        assert_rspamd_table_eq({ expect = { ['add header'] = 9 }, actual = res.overrides.actions })
      end)

      test("only an array is a legacy file", function()
        local legacy = require "lua_dynconf.legacy"
        local res, err = legacy.convert_file(decode('{"metric": "default"}'), make_lookup())
        assert_nil(res)
        assert_not_nil(err)
        res = legacy.convert_file(decode('[]'), make_lookup())
        assert_equal(next(res.overrides), nil)
      end)

      test("the redis data of the dynamic_conf module", function()
        local legacy = require "lua_dynconf.legacy"
        local doc = decode([[
          {"scores": {"SYM_A": 9, "NO_SUCH": 1, "SYM_B": {"score": 3}},
           "actions": {"reject": 18, "add_header": 7, "greylist": null},
           "symbols_disabled": ["SYM_C", "NOPE"], "symbols_enabled": ["SYM_A"]}
        ]])
        local res = legacy.convert_redis(doc, make_lookup())
        assert_rspamd_table_eq({ expect = { SYM_A = 9 }, actual = res.overrides.scores })
        assert_rspamd_table_eq({ expect = { reject = 18, ['add header'] = 7 }, actual = res.overrides.actions })
        -- The lists of symbols are not imported, and the reason is logged
        assert_nil(res.overrides.symbols)
        local skipped = table.concat(res.skipped, '\n')
        for _, what in ipairs({ 'NO_SUCH', 'SYM_B', 'greylist' }) do
          assert_not_nil(skipped:find(what, 1, true), what)
        end
        assert_not_nil(skipped:find('symbols_disabled (2 entries) is not imported', 1, true))
        assert_not_nil(skipped:find('symbols_enabled (1 entries) is not imported', 1, true))
        assert_not_nil(skipped:find('never applied', 1, true))
      end)

      test("symbols_disabled in the map form is skipped as well", function()
        local legacy = require "lua_dynconf.legacy"
        local res = legacy.convert_redis(decode('{"symbols_disabled": {"SYM_C": 1, "SYM_B": true}, ' ..
            '"symbols_enabled": {}}'), make_lookup())
        assert_nil(res.overrides.symbols)
        assert_equal(next(res.overrides), nil)
        -- Reported once, for the list that holds something; an empty list is nothing to report
        local skipped = table.concat(res.skipped, '\n')
        assert_not_nil(skipped:find('symbols_disabled (2 entries) is not imported', 1, true))
        assert_nil(skipped:find('symbols_enabled', 1, true))
        assert_equal(#res.skipped, 1)
      end)

      test("a document without symbol lists has nothing to report about them", function()
        local legacy = require "lua_dynconf.legacy"
        local res = legacy.convert_redis(decode('{"scores": {"SYM_A": 9}, "symbols_disabled": []}'), make_lookup())
        assert_equal(#res.skipped, 0)
      end)

      test("redis data that is not an object is refused", function()
        local legacy = require "lua_dynconf.legacy"
        local bad, err = legacy.convert_redis('x', make_lookup())
        assert_nil(bad)
        assert_not_nil(err)
      end)

      test("read_file tells a missing file from a broken one", function()
        local legacy = require "lua_dynconf.legacy"
        local dir = temp_dir()
        local doc, err = legacy.read_file(dir .. '/rspamd_dynamic')
        assert_nil(doc)
        assert_nil(err)
        write_file(dir .. '/rspamd_dynamic', '[{')
        doc, err = legacy.read_file(dir .. '/rspamd_dynamic')
        assert_nil(doc)
        assert_not_nil(err)
        write_file(dir .. '/rspamd_dynamic', LEGACY_FILE)
        doc, err = legacy.read_file(dir .. '/rspamd_dynamic')
        assert_nil(err)
        assert_equal(#doc, 3)
        cleanup()
      end)
    end)

    context("Import at start", function()
      -- A registry with the file backend and the three metric modules, started in a worker
      local function start_worker(dir, primary, extra_fields)
        local on_load
        local fields = {
          add_on_load = function(_, fn) on_load = fn end,
          add_periodic = function() end,
          get_all_opt = function(_, name)
            if name == 'options' then
              return { dynamic_conf = dir .. '/rspamd_dynamic' }
            end
          end,
          dynconf_baseline = function(_, module, key) return make_lookup()(module, key) end,
          dynconf_notify = function() return true end,
          dynconf_bump_generation = function() end,
        }
        for k, v in pairs(extra_fields or {}) do
          fields[k] = v
        end
        local proxy = setmetatable(fields, { __index = real_config })
        _G.rspamd_config = proxy
        local result = {}
        local ok, err = pcall(function()
          local dynconf = fresh()
          assert(dynconf.configure({ backend = 'file', path = dir .. '/dynconf.json', interval = 7,
                                          jitter = 0 }))
          assert(dynconf.register_c('actions', { '*' }, { subscriber_keys = true, static = false }))
          assert(dynconf.register_c('scores', { '*' }, { subscriber_keys = true, static = false }))
          assert(dynconf.register_c('symbols', { '*.enabled' }, { subscriber_keys = true, static = false }))
          on_load(proxy, 'ev', { is_primary_controller = function() return primary end })
          result.dynconf = dynconf
        end)
        _G.rspamd_config = real_config
        assert(ok, err)
        return result.dynconf
      end

      test("the primary controller imports the file once and renames it", function()
        local dir = temp_dir()
        write_file(dir .. '/rspamd_dynamic', LEGACY_FILE)
        local dynconf = start_worker(dir, true)

        local written = decode(read_file(dir .. '/dynconf.json'))
        assert_rspamd_table_eq({ expect = { SYM_A = 12, SYM_B = 5 }, actual = written.modules.scores.o })
        assert_rspamd_table_eq({ expect = { reject = 20, greylist = 4 }, actual = written.modules.actions.o })
        assert_nil(written.modules.symbols)
        assert_nil(read_file(dir .. '/rspamd_dynamic'))
        assert_equal(read_file(dir .. '/rspamd_dynamic.imported'), LEGACY_FILE)
        -- and it is in effect in this worker
        assert_equal(dynconf.get('scores').SYM_A, 12)
        assert_equal(dynconf.get('actions').reject, 20)

        -- A restart finds the overrides and nothing to import
        os.rename(dir .. '/rspamd_dynamic.imported', dir .. '/rspamd_dynamic')
        local before = read_file(dir .. '/dynconf.json')
        start_worker(dir, true)
        assert_equal(read_file(dir .. '/dynconf.json'), before)
        assert_not_nil(read_file(dir .. '/rspamd_dynamic'))
        cleanup()
      end)

      test("a module that holds an override is not imported", function()
        local dir = temp_dir()
        write_file(dir .. '/dynconf.json', '{"v":1,"modules":{"scores":{"v":1,"o":{"SYM_B":3}}}}')
        write_file(dir .. '/rspamd_dynamic', LEGACY_FILE)
        local dynconf = start_worker(dir, true)
        local written = decode(read_file(dir .. '/dynconf.json'))
        assert_rspamd_table_eq({ expect = { SYM_B = 3 }, actual = written.modules.scores.o })
        assert_rspamd_table_eq({ expect = { reject = 20, greylist = 4 }, actual = written.modules.actions.o })
        assert_equal(dynconf.get('scores').SYM_B, 3)
        assert_nil(dynconf.get('scores').SYM_A)
        cleanup()
      end)

      test("a module whose stored override has been refused is not imported over", function()
        local dir = temp_dir()
        local content = '{"v":1,"modules":{"scores":{"v":1,"o":{"GONE_SYM":3}}}}'
        write_file(dir .. '/dynconf.json', content)
        write_file(dir .. '/rspamd_dynamic', LEGACY_FILE)
        -- The subscriber of `scores` does not know GONE_SYM
        local dynconf = start_worker(dir, true, {
          dynconf_notify = function(_, module, values)
            if module == 'scores' and values.GONE_SYM ~= nil then
              return false, 'unknown symbol GONE_SYM'
            end
            return true
          end,
        })
        local written = decode(read_file(dir .. '/dynconf.json'))
        assert_rspamd_table_eq({ expect = { GONE_SYM = 3 }, actual = written.modules.scores.o })
        assert_rspamd_table_eq({ expect = { reject = 20, greylist = 4 }, actual = written.modules.actions.o })
        assert_nil(dynconf.get('scores').GONE_SYM)
        cleanup()
      end)

      test("entries that override.d defines do not fail the import", function()
        local dir = temp_dir()
        write_file(dir .. '/rspamd_dynamic', [=[[{"metric": "default",
          "symbols": [{"name": "SYM_FIXED", "value": 9}, {"name": "SYM_A", "value": 12}],
          "actions": [{"name": "quarantine", "value": 40}, {"name": "reject", "value": 20}]}]]=])
        -- The subscribers refuse what override.d defines, like the C ones do for a write
        local dynconf = start_worker(dir, true, {
          dynconf_notify = function(_, _, values)
            if values.SYM_FIXED ~= nil or values.quarantine ~= nil then
              return false, 'defined with the priority 10'
            end
            return true
          end,
        })
        local written = decode(read_file(dir .. '/dynconf.json'))
        assert_rspamd_table_eq({ expect = { SYM_A = 12 }, actual = written.modules.scores.o })
        assert_rspamd_table_eq({ expect = { reject = 20 }, actual = written.modules.actions.o })
        assert_nil(read_file(dir .. '/rspamd_dynamic'))
        assert_not_nil(read_file(dir .. '/rspamd_dynamic.imported'))
        assert_equal(dynconf.get('scores').SYM_A, 12)
        cleanup()
      end)

      test("a module that fails does not stop the import of the others", function()
        local dir = temp_dir()
        write_file(dir .. '/rspamd_dynamic', LEGACY_FILE)
        local dynconf = start_worker(dir, true, {
          dynconf_notify = function(_, module)
            if module == 'actions' then
              return false, 'refused'
            end
            return true
          end,
        })
        local written = decode(read_file(dir .. '/dynconf.json'))
        assert_rspamd_table_eq({ expect = { SYM_A = 12, SYM_B = 5 }, actual = written.modules.scores.o })
        assert_nil(written.modules.actions)
        assert_equal(dynconf.get('scores').SYM_A, 12)
        -- The file stays: the next start tries the module that has failed again
        assert_not_nil(read_file(dir .. '/rspamd_dynamic'))
        assert_nil(read_file(dir .. '/rspamd_dynamic.imported'))
        cleanup()
      end)

      test("only the primary controller imports", function()
        local dir = temp_dir()
        write_file(dir .. '/rspamd_dynamic', LEGACY_FILE)
        start_worker(dir, false)
        assert_nil(read_file(dir .. '/dynconf.json'))
        assert_not_nil(read_file(dir .. '/rspamd_dynamic'))
        cleanup()
      end)

      test("a file that cannot be parsed stays where it is", function()
        local dir = temp_dir()
        write_file(dir .. '/rspamd_dynamic', '[{"metric": ')
        start_worker(dir, true)
        assert_nil(read_file(dir .. '/dynconf.json'))
        assert_not_nil(read_file(dir .. '/rspamd_dynamic'))
        assert_nil(read_file(dir .. '/rspamd_dynamic.imported'))
        cleanup()
      end)

      test("nothing is imported into modules that do not accept overrides", function()
        local dir = temp_dir()
        write_file(dir .. '/rspamd_dynamic', LEGACY_FILE)
        local on_load
        local proxy = setmetatable({
          add_on_load = function(_, fn) on_load = fn end,
          add_periodic = function() end,
          get_all_opt = function(_, name)
            if name == 'options' then
              return { dynamic_conf = dir .. '/rspamd_dynamic' }
            end
          end,
          dynconf_baseline = function(_, module, key) return make_lookup()(module, key) end,
          dynconf_notify = function() return true end,
          dynconf_bump_generation = function() end,
        }, { __index = real_config })
        _G.rspamd_config = proxy
        local ok, err = pcall(function()
          local dynconf = fresh()
          assert_true(dynconf.configure({ backend = 'file', path = dir .. '/dynconf.json', modules = { 'scores' } }))
          assert_true(dynconf.register_c('actions', { '*' }, { subscriber_keys = true, static = false }))
          assert_true(dynconf.register_c('scores', { '*' }, { subscriber_keys = true, static = false }))
          on_load(proxy, 'ev', { is_primary_controller = function() return true end })
        end)
        _G.rspamd_config = real_config
        assert(ok, err)
        local written = decode(read_file(dir .. '/dynconf.json'))
        assert_rspamd_table_eq({ expect = { SYM_A = 12, SYM_B = 5 }, actual = written.modules.scores.o })
        assert_nil(written.modules.actions)
        cleanup()
      end)
    end)

    context("Redis hash", function()
      -- Runs the import against a fake lua_redis; `replies` answers the requests in order
      local function run_import(replies, opts)
        local null = require("rspamd_redis").null
        local fake = { requests = {}, updates = {} }
        local real_redis = package.loaded['lua_redis']
        package.loaded['lua_redis'] = setmetatable({
          parse_redis_server = function(name, section)
            fake.parsed = { name = name, section = section }
            return { timeout = 1.0 }
          end,
          redis_make_request_taskless = function(ev_base, _, _, key, is_write, cb, cmd, args)
            table.insert(fake.requests, { ev_base = ev_base, key = key, is_write = is_write, cmd = cmd, args = args })
            local reply = table.remove(replies, 1)
            local data = reply.data
            if data == 'null' then
              data = null
            elseif type(data) == 'table' then
              for i, v in ipairs(data) do
                if v == 'null' then
                  data[i] = null
                end
              end
            end
            cb(reply.err, data)
            return true
          end,
        }, { __index = real_redis })
        package.loaded['lua_dynconf.legacy'] = nil
        local lok, legacy = pcall(require, 'lua_dynconf.legacy')
        package.loaded['lua_redis'] = real_redis
        assert(lok, legacy)

        local stub = {
          update = function(module, patch, _, cb)
            table.insert(fake.updates, { module = module, patch = patch })
            if opts and opts.fail == module then
              cb('write failed')
            else
              cb(nil)
            end
            return true
          end,
        }
        local proxy = setmetatable({
          get_all_opt = function(_, name)
            if name == 'dynamic_conf' then
              if opts and opts.section ~= nil then
                return opts.section or nil
              end
              return { redis_key = 'old_hash', servers = 'localhost' }
            end
          end,
        }, { __index = real_config })
        _G.rspamd_config = proxy
        local ok, err = pcall(function()
          legacy.configure()
          legacy.run(stub, { targets = { actions = true, scores = true }, redis = true, ev_base = 'ev',
                             lookup = make_lookup(), ctx = {} })
        end)
        _G.rspamd_config = real_config
        assert(ok, err)
        return fake
      end

      local HASH = '{"scores": {"SYM_A": 9}, "actions": {"reject": 18}, "symbols_disabled": ["SYM_C"]}'

      test("the hash is converted, written and marked, not deleted", function()
        local fake = run_import({
          { data = { HASH, 'null' } },   -- HMGET d marker
          { data = 1 },                  -- HSETNX marker
        })
        assert_equal(fake.parsed.name, 'dynamic_conf')
        assert_equal(fake.requests[1].cmd, 'HMGET')
        assert_equal(fake.requests[1].args[1], 'old_hash')
        assert_equal(fake.requests[1].args[2], 'd')
        -- symbols_disabled is not imported
        assert_equal(#fake.updates, 2)
        assert_equal(fake.updates[1].module, 'actions')
        assert_equal(fake.updates[1].patch.reject, 18)
        assert_equal(fake.updates[2].module, 'scores')
        assert_equal(fake.updates[2].patch.SYM_A, 9)
        assert_equal(#fake.requests, 2)
        assert_equal(fake.requests[2].cmd, 'HSETNX')
        assert_true(fake.requests[2].is_write)
        assert_equal(fake.requests[2].args[1], 'old_hash')
      end)

      test("a hash that has been imported or is empty is left alone", function()
        local fake = run_import({ { data = { HASH, '1700000000' } } })
        assert_equal(#fake.updates, 0)
        assert_equal(#fake.requests, 1)
        fake = run_import({ { data = { 'null', 'null' } } })
        assert_equal(#fake.updates, 0)
        fake = run_import({ { err = 'connection refused' } })
        assert_equal(#fake.updates, 0)
      end)

      test("a failed write is not marked as imported", function()
        local fake = run_import({ { data = { HASH, 'null' } } }, { fail = 'scores' })
        assert_equal(#fake.updates, 2)
        assert_equal(#fake.requests, 1)
      end)

      test("without the dynamic_conf section there is nothing to import", function()
        local fake = run_import({}, { section = false })
        assert_equal(#fake.requests, 0)
        assert_equal(#fake.updates, 0)
      end)
    end)
  end)
end)
