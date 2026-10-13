local lua_util = require 'lua_util'
local compat_env = require 'compat_env'

context('ARC seal completion', function()
  local function assert_nil(value)
    assert(value == nil, 'expected nil, got ' .. tostring(value))
  end

  local function start_checks(opts)
    opts = opts or {}
    local callbacks, requested, symbols, cache = {}, {}, {}, {}
    local headers = { ['ARC-Seal'] = {}, ['ARC-Message-Signature'] = {},
      ['ARC-Authentication-Results'] = {} }
    local count = opts.count or 3
    -- Received headers are normally in reverse instance order.
    for i = count, 1, -1 do
      local domain = 'forwarder' .. i .. '.example'
      local seal = string.format('i=%d; cv=%s; d=%s; s=arc; b=test',
        i, i == 1 and 'none' or 'pass', domain)
      local signature = string.format('i=%d; d=%s; s=arc; b=test', i, domain)
      local aar = string.format('i=%d; %s; dmarc=pass header.from=sender.example', i, domain)
      headers['ARC-Seal'][#headers['ARC-Seal'] + 1] = { decoded = seal, value = seal }
      headers['ARC-Message-Signature'][#headers['ARC-Message-Signature'] + 1] = {
        decoded = signature, value = signature }
      headers['ARC-Authentication-Results'][#headers['ARC-Authentication-Results'] + 1] = {
        decoded = aar, value = aar }
    end
    if opts.drop_aar then
      table.remove(headers['ARC-Authentication-Results'], count - opts.drop_aar + 1)
    end
    if opts.extra_aar then
      -- Prepended above the real AARs, so no seal covers it
      table.insert(headers['ARC-Authentication-Results'], 1,
        { decoded = opts.extra_aar, value = opts.extra_aar })
    end
    local task = {
      get_header_full = function(_, name) return headers[name] end,
      cache_set = function(_, name, value) cache[name] = value end,
      insert_result = function(_, name, weight, option)
        symbols[name] = symbols[name] or {}
        table.insert(symbols[name], { weight = weight, option = option })
      end,
    }
    local check
    local config = {
      get_all_opt = function(_, name)
        if name == 'arc' then return opts end
      end,
      register_symbol = function(_, symbol)
        if symbol.name == 'ARC_CHECK' then check = symbol.callback end
        return 1
      end,
      register_dependency = function() end,
    }
    local noop = function() end
    local mocks = {
      rspamd_logger = { infox = noop, warnx = noop, errx = noop,
        slog = function(message) return message end },
      lua_util = setmetatable({ debugm = noop, dns_timeout_augmentation = noop }, { __index = lua_util }),
      lua_dkim_tools = { process_signing_settings = noop,
        validate_signing_settings = function() return true end },
      lua_maps = { map_add_from_ucl = function(entries)
        return { get_key = function(_, key) return entries[key] end }
      end },
    }
    local env = setmetatable({
      rspamd_config = config,
      require = function(name) return mocks[name] or require(name) end,
      rspamd_plugins = { dkim = {
        sign = noop, canon_header_relaxed = noop,
        verify = function(_, header, callback, kind)
          local index = tonumber(header:match('i=(%d+)'))
          local domain = 'forwarder' .. index .. '.example'
          if kind == 'arc-sign' then
            if opts.signature_immediate then
              return false, 'cannot start verification'
            end
            callback(task, not opts.signature_failure, 'signature failure', domain)
            return true
          end
          requested[#requested + 1] = index
          if opts.immediate and opts.immediate[index] then
            return false, 'cannot start verification'
          elseif opts.synchronous == true or
              (type(opts.synchronous) == 'table' and opts.synchronous[index]) then
            callback(task, not (opts.failures and opts.failures[index]), 'seal failure', domain)
          else
            callbacks[index] = function(success)
              callback(task, success, 'seal failure', domain)
            end
          end
          return true
        end,
      } },
    }, { __index = _G })
    local plugin = lua_util.join_path(rspamd_paths.PLUGINSDIR, 'arc.lua')
    assert(compat_env.loadfile(plugin, 't', env))()
    assert(check, 'ARC_CHECK must be registered')
    check(task)
    return callbacks, symbols, cache, requested
  end

  local function assert_pending(symbols, cache)
    assert_nil(symbols.ARC_ALLOW)
    assert_nil(symbols.ARC_ALLOW_TRUSTED)
    assert_nil(symbols.ARC_REJECT)
    assert_nil(cache['arc-allow'])
    assert_nil(cache.arc_trusted_aar)
  end

  for _, order in ipairs({ { 3, 2, 1 }, { 1, 3, 2 }, { 2, 1, 3 } }) do
    test('success waits for every seal: ' .. table.concat(order, ','), function()
      local callbacks, symbols, cache, requested = start_checks()
      assert_equal(3, #requested) -- All checks start without waiting for another callback.
      assert_pending(symbols, cache)
      for n, index in ipairs(order) do
        callbacks[index](true)
        if n < #order then assert_pending(symbols, cache) end
      end
      assert_equal(1, #symbols.ARC_ALLOW)
      assert_equal('forwarder3.example:s=arc:i=3', cache['arc-allow'])
      assert_nil(symbols.ARC_REJECT)
    end)

    test('failure never publishes trust: ' .. table.concat(order, ','), function()
      local callbacks, symbols, cache = start_checks({ whitelisted_signers_map = {
        ['forwarder3.example'] = true } })
      for n, index in ipairs(order) do
        callbacks[index](index ~= 1)
        if n < #order then assert_pending(symbols, cache) end
      end
      assert_equal(1, #symbols.ARC_REJECT)
      assert_nil(symbols.ARC_ALLOW)
      assert_nil(symbols.ARC_ALLOW_TRUSTED)
      assert_nil(cache['arc-allow'])
      assert_nil(cache.arc_trusted_aar)
    end)
  end

  test('trusted AAR selection follows instance order', function()
    local callbacks, symbols, cache = start_checks({ whitelisted_signers_map = {
      ['forwarder1.example'] = true, ['forwarder3.example'] = true } })
    callbacks[3](true)
    assert_pending(symbols, cache)
    callbacks[2](true)
    assert_pending(symbols, cache)
    callbacks[1](true)
    assert_equal(1, #symbols.ARC_ALLOW)
    assert_equal(2, #symbols.ARC_ALLOW_TRUSTED)
    assert_equal('3', cache.arc_trusted_aar.i)
  end)

  for _, immediate in ipairs({ { [1] = true }, { [3] = true }, { true, true, true } }) do
    test('immediate failure completes the chain: ' .. table.concat({
      tostring(immediate[1]), tostring(immediate[3]) }, ','), function()
      local callbacks, symbols, cache, requested = start_checks({ immediate = immediate })
      assert_equal(3, #requested)
      for i = 3, 1, -1 do
        if callbacks[i] then callbacks[i](true) end
      end
      assert_equal(1, #(symbols.ARC_REJECT or {}))
      assert_nil(symbols.ARC_ALLOW)
      assert_nil(cache['arc-allow'])
    end)
  end

  test('whitelisted immediate failure still completes', function()
    local callbacks, symbols, cache = start_checks({ immediate = { [3] = true },
      whitelist = { ['forwarder3.example'] = true } })
    assert_pending(symbols, cache)
    callbacks[2](true)
    assert_pending(symbols, cache)
    callbacks[1](true)
    assert_equal(1, #(symbols.ARC_ALLOW or {}))
    assert_equal('forwarder3.example:s=arc:i=3', cache['arc-allow'])
  end)

  test('whitelisted callback failure still completes', function()
    local callbacks, symbols, cache = start_checks({ whitelist = { ['forwarder1.example'] = true } })
    callbacks[3](true)
    callbacks[2](true)
    callbacks[1](false)
    assert_equal(1, #symbols.ARC_ALLOW)
    assert_nil(symbols.ARC_REJECT)
    assert_equal('forwarder3.example:s=arc:i=3', cache['arc-allow'])
  end)

  for _, count in ipairs({ 1, 3 }) do
    test('synchronous callbacks: ' .. count .. ' seals', function()
      local _, symbols, cache, requested = start_checks({ count = count, synchronous = true })
      assert_equal(count, #requested)
      assert_equal(1, #symbols.ARC_ALLOW)
      assert_equal(string.format('forwarder%d.example:s=arc:i=%d', count, count), cache['arc-allow'])
    end)
  end

  test('synchronous failure completes once', function()
    local _, symbols = start_checks({ synchronous = true, failures = { [1] = true } })
    assert_equal(1, #symbols.ARC_REJECT)
    assert_nil(symbols.ARC_ALLOW)
  end)

  test('cached newest seal waits for pending DNS checks', function()
    local callbacks, symbols, cache, requested = start_checks({ synchronous = { [3] = true },
      whitelisted_signers_map = { ['forwarder3.example'] = true } })
    assert_equal(3, #requested)
    assert_pending(symbols, cache)
    callbacks[2](true)
    assert_pending(symbols, cache)
    callbacks[1](false)
    assert_equal(1, #symbols.ARC_REJECT)
    assert_nil(symbols.ARC_ALLOW)
    assert_nil(symbols.ARC_ALLOW_TRUSTED)
    assert_nil(cache.arc_trusted_aar)
  end)

  test('pending newest seal waits for cached earlier checks', function()
    local callbacks, symbols, cache = start_checks({ synchronous = { true, true },
      whitelisted_signers_map = { ['forwarder1.example'] = true } })
    assert_pending(symbols, cache)
    callbacks[3](true)
    assert_equal(1, #symbols.ARC_ALLOW)
    assert_equal(1, #symbols.ARC_ALLOW_TRUSTED)
    assert_equal('1', cache.arc_trusted_aar.i)
  end)

  test('failed AMS starts no seal verification', function()
    local _, symbols, cache, requested = start_checks({ signature_failure = true })
    assert_equal(0, #requested)
    assert_equal(1, #symbols.ARC_REJECT)
    assert_nil(symbols.ARC_ALLOW)
    assert_nil(cache['arc-allow'])
  end)

  test('immediate AMS failure rejects', function()
    local _, symbols, cache, requested = start_checks({ signature_immediate = true })
    assert_equal(0, #requested)
    assert_equal(1, #(symbols.ARC_REJECT or {}))
    assert_nil(symbols.ARC_ALLOW)
    assert_nil(cache['arc-allow'])
  end)

  test('whitelisted immediate AMS failure verifies seals', function()
    local _, symbols, cache, requested = start_checks({ signature_immediate = true,
      synchronous = true, whitelist = { ['forwarder3.example'] = true } })
    assert_equal(3, #requested)
    assert_equal(1, #(symbols.ARC_ALLOW or {}))
    assert_nil(symbols.ARC_REJECT)
    assert_equal('forwarder3.example:s=arc:i=3', cache['arc-allow'])
  end)

  for name, aar_opts in pairs({
    ['unsealed extra AAR'] = { extra_aar = 'i=1; forwarder1.example; dmarc=pass header.from=bank.example' },
    ['missing AAR'] = { drop_aar = 2 },
    ['duplicate AAR instance'] = { drop_aar = 2,
      extra_aar = 'i=1; forwarder1.example; dmarc=pass header.from=bank.example' },
  }) do
    test(name .. ' invalidates the chain', function()
      aar_opts.whitelisted_signers_map = { ['forwarder1.example'] = true }
      aar_opts.synchronous = true
      local _, symbols, cache, requested = start_checks(aar_opts)
      assert_equal(0, #requested)
      assert_equal(1, #(symbols.ARC_INVALID or {}))
      assert_pending(symbols, cache)
    end)
  end
end)
