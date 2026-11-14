context("Dynamic configuration registry", function()
  local T = require "lua_shape.core"
  local real_config = rspamd_config
  local real_util = require "rspamd_util"
  local schema_counter = 0

  -- Each test gets a fresh registry: the module keeps its state in upvalues
  local function fresh(time_fn)
    package.loaded['lua_dynconf'] = nil
    package.loaded['lua_dynconf.redis'] = nil
    if time_fn then
      package.loaded['rspamd_util'] = setmetatable({ get_time = time_fn }, { __index = real_util })
    end
    local ok, res = pcall(require, 'lua_dynconf')
    package.loaded['rspamd_util'] = real_util
    assert(ok, res)
    return res
  end

  local function unique_schema_id()
    schema_counter = schema_counter + 1
    return 'plugins.dynconf_test_' .. schema_counter
  end

  -- Registers a fake backend and enables the framework with the manual policy; returns a handle that
  -- lets the test complete the pending check by hand
  local function with_fake_backend(dynconf, name)
    local handle = { checks = 0 }
    dynconf.register_backend(name, {
      configure = function() return true end,
      check = function(_, cb)
        handle.checks = handle.checks + 1
        handle.pending = cb
      end,
    })
    local ok, err = dynconf.configure({ enabled = true, backend = name, policy = 'manual' })
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
      assert_true(dynconf.configure(nil))
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
          cb(nil, 8)
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
end)
