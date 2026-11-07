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
    if opts.aar_from then
      -- What each forwarder saw in From
      for n, hdr in ipairs(headers['ARC-Authentication-Results']) do
        local i = count - n + 1
        if opts.aar_from[i] then
          hdr.decoded = string.format('i=%d; forwarder%d.example; dmarc=pass header.from=%s',
            i, i, opts.aar_from[i])
          hdr.value = hdr.decoded
        end
      end
    end
    if opts.aar_text then
      -- The results part of the AAR of an instance, as its forwarder wrote it
      for n, hdr in ipairs(headers['ARC-Authentication-Results']) do
        local i = count - n + 1
        if opts.aar_text[i] then
          hdr.decoded = string.format('i=%d; forwarder%d.example; %s', i, i, opts.aar_text[i])
          hdr.value = hdr.decoded
        end
      end
    end
    if opts.aar_decoded then
      -- What decoding encoded-words in an AAR gives, its raw value unchanged
      for n, hdr in ipairs(headers['ARC-Authentication-Results']) do
        local i = count - n + 1
        if opts.aar_decoded[i] then
          hdr.decoded = string.format('i=%d; forwarder%d.example; %s', i, i, opts.aar_decoded[i])
        end
      end
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
    local registered = {}
    local config = {
      get_all_opt = function(_, name)
        if name == 'arc' then return opts end
      end,
      register_symbol = function(_, symbol)
        if symbol.name == 'ARC_CHECK' then check = symbol.callback end
        if symbol.name then registered[symbol.name] = symbol.callback end
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
          if kind == 'arc-seal' and opts.seal_domain then
            -- The d= the C parser read, which verified the seal
            domain = opts.seal_domain
          end
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
    return callbacks, symbols, cache, requested, registered
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

  test('trusted AARs are kept in instance order', function()
    local callbacks, symbols, cache = start_checks({ whitelisted_signers_map = {
      ['forwarder2.example'] = true, ['forwarder3.example'] = true } })
    callbacks[3](true)
    assert_pending(symbols, cache)
    callbacks[2](true)
    assert_pending(symbols, cache)
    callbacks[1](true)
    assert_equal(1, #symbols.ARC_ALLOW)
    assert_equal(2, #symbols.ARC_ALLOW_TRUSTED)
    assert_equal(2, #cache.arc_trusted_aar)
    assert_equal('2', cache.arc_trusted_aar[1].i)
    assert_equal('3', cache.arc_trusted_aar[2].i)
  end)

  -- Anyone can add their own ARC set after a genuine one of a trusted
  -- forwarder, and change the message, From included
  for name, signers in pairs({
    ['an untrusted later hop'] = { ['forwarder1.example'] = true },
    ['an untrusted hop between'] = { ['forwarder1.example'] = true, ['forwarder3.example'] = true },
  }) do
    test('a trusted forwarder before ' .. name .. ' is not trusted', function()
      local _, symbols, cache = start_checks({ synchronous = true,
        whitelisted_signers_map = signers })
      assert_equal(1, #symbols.ARC_ALLOW)
      if signers['forwarder3.example'] then
        assert_equal(1, #symbols.ARC_ALLOW_TRUSTED)
        assert_equal('forwarder3.example:s=arc:i=3', symbols.ARC_ALLOW_TRUSTED[1].option)
        assert_equal(1, #cache.arc_trusted_aar)
        assert_equal('3', cache.arc_trusted_aar[1].i)
      else
        assert_nil(symbols.ARC_ALLOW_TRUSTED)
        assert_nil(cache.arc_trusted_aar)
      end
    end)
  end

  test('an unverified newest seal cuts the trust of earlier forwarders', function()
    local _, symbols, cache = start_checks({ synchronous = true, failures = { [3] = true },
      whitelist = { ['forwarder3.example'] = true },
      whitelisted_signers_map = { ['forwarder2.example'] = true, ['forwarder3.example'] = true } })
    assert_equal(1, #symbols.ARC_ALLOW)
    assert_nil(symbols.ARC_ALLOW_TRUSTED)
    assert_nil(cache.arc_trusted_aar)
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

  for mode, fail_opts in pairs({ callback = {}, immediate = { immediate = { [1] = true } } }) do
    test('whitelisted ' .. mode .. ' seal failure earns no trust', function()
      fail_opts.whitelist = { ['forwarder1.example'] = true }
      fail_opts.whitelisted_signers_map = { ['forwarder1.example'] = true,
        ['forwarder3.example'] = true }
      local callbacks, symbols, cache = start_checks(fail_opts)
      if callbacks[1] then callbacks[1](false) end
      callbacks[2](true)
      callbacks[3](true)
      assert_equal(1, #symbols.ARC_ALLOW)
      assert_nil(symbols.ARC_REJECT)
      assert_equal(1, #symbols.ARC_ALLOW_TRUSTED)
      assert_equal('forwarder3.example:s=arc:i=3', symbols.ARC_ALLOW_TRUSTED[1].option)
      assert_equal(1, #cache.arc_trusted_aar)
      assert_equal('3', cache.arc_trusted_aar[1].i)
    end)
  end

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
      whitelisted_signers_map = { ['forwarder1.example'] = true, ['forwarder2.example'] = true,
        ['forwarder3.example'] = true } })
    assert_pending(symbols, cache)
    callbacks[3](true)
    assert_equal(1, #symbols.ARC_ALLOW)
    assert_equal(3, #symbols.ARC_ALLOW_TRUSTED)
    assert_equal('1', cache.arc_trusted_aar[1].i)
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

  test('trust follows the d= that verified the seal', function()
    -- The C parser verified the seal with d=attacker.example, whatever d= our own split saw
    local callbacks, symbols, cache = start_checks({ count = 1, seal_domain = 'attacker.example',
      whitelisted_signers_map = { ['forwarder1.example'] = true } })
    callbacks[1](true)
    assert_equal(1, #symbols.ARC_ALLOW)
    assert_nil(symbols.ARC_ALLOW_TRUSTED)
    assert_nil(cache.arc_trusted_aar)
  end)

  -- Runs ARC_DMARC_ADJUSTMENT after a chain where forwarder3 is trusted
  local function adjust_dmarc(opts)
    local check_opts = { synchronous = true, aar_from = opts.aar_from, aar_text = opts.aar_text,
      aar_decoded = opts.aar_decoded,
      signature_failure = opts.signature_failure, whitelist = opts.whitelist,
      whitelisted_signers_map = opts.signers or { ['forwarder3.example'] = true } }
    local _, _, cache, _, registered = start_checks(check_opts)
    local adjust = registered.ARC_DMARC_ADJUSTMENT
    assert(adjust, 'ARC_DMARC_ADJUSTMENT must be registered')
    local adjusted = {}
    local task = {
      cache_get = function(_, name) return cache[name] end,
      has_symbol = function(_, name) return name == 'DMARC_POLICY_REJECT' end,
      get_from = function(_, flavour)
        -- What DMARC has checked
        assert(flavour[1] == 'mime' and flavour[2] == 'orig', 'the original From is expected')
        return opts.from
      end,
      adjust_result = function(_, name, weight)
        table.insert(adjusted, { name = name, weight = weight })
      end,
      get_mempool = function() return nil end,
      get_resolver = function()
        return { idna_convert_utf8 = function(_, name)
          -- What does not convert becomes U+FFFD, as with ICU
          return (name:gsub('[bB]\195[\164\132]nk', 'xn--bnk-sna'):gsub('[\254\255]', '\239\191\189'))
        end }
      end,
    }
    adjust(task)
    return adjusted
  end

  local function from(...)
    local res = {}
    for _, domain in ipairs({ ... }) do
      table.insert(res, { addr = 'user@' .. domain, domain = domain })
    end
    return res
  end

  test('DMARC reject is adjusted for the From that a trusted forwarder saw', function()
    local adjusted = adjust_dmarc({ from = from('Sender.Example') })
    assert_equal(1, #adjusted)
    assert_equal('DMARC_POLICY_REJECT', adjusted[1].name)
    assert_equal(0.1, adjusted[1].weight)
  end)

  test('a comment before the DMARC result does not stop the adjustment', function()
    local adjusted = adjust_dmarc({ from = from('sender.example'), aar_text = {
      [3] = '(forwarder result) dmarc=pass header.from=sender.example' } })
    assert_equal(1, #adjusted)
  end)

  test('a DMARC result in capitals or with a version adjusts the reject', function()
    -- Methods, results and names of properties are case-insensitive (RFC 8601)
    for _, text in ipairs({
      'DMARC=PASS Header.From=sender.example',
      'dmarc/1=pass header.from=sender.example',
      'dmarc / 1 = pass (policy=none) header.from=sender.example',
    }) do
      assert_equal(1, #adjust_dmarc({ from = from('sender.example'), aar_text = { [3] = text } }), text)
    end
  end)

  test('a pass after the DMARC result of an element is not its result', function()
    -- Text that a comment failed to hide, after the result the forwarder wrote
    assert_equal(0, #adjust_dmarc({ from = from('bank.example'), aar_text = {
      [3] = 'dmarc=fail (x)dmarc=pass header.from=bank.example' } }))
  end)

  test('an encoded-word in an AAR comment adds no result', function()
    -- The sender that a forwarder wrote into a comment; decoded, it would close
    -- the comment and add a DMARC pass
    local spf = 'dkim=none; spf=pass (fwd.example: domain of "%s@attacker.example" ' ..
        'designates 192.0.2.1 as permitted sender) smtp.mailfrom=x'
    assert_equal(0, #adjust_dmarc({ from = from('bank.example'),
      aar_text = { [3] = string.format(spf,
          '=?us-ascii?q?x=29=3B_dmarc=3Dpass_header=2Efrom=3Dbank=2Eexample_=28y?=') },
      aar_decoded = { [3] = string.format(spf,
          'x); dmarc=pass header.from=bank.example (y') } }))
  end)

  test('DMARC pass for another domain does not adjust the reject', function()
    assert_equal(0, #adjust_dmarc({ from = from('bank.example') }))
  end)

  test('a whole address in header.from is matched by its domain', function()
    local adjusted = adjust_dmarc({ from = from('bank.example'),
      aar_from = { [3] = 'someone@Bank.Example' } })
    assert_equal(1, #adjusted)
  end)

  test('DMARC pass of a forwarder before an untrusted hop does not adjust', function()
    assert_equal(0, #adjust_dmarc({ from = from('bank.example'),
      aar_from = { [1] = 'bank.example', [3] = 'attacker.example' },
      signers = { ['forwarder1.example'] = true } }))
  end)

  test('DMARC pass of any trusted forwarder adjusts the reject', function()
    local adjusted = adjust_dmarc({ from = from('bank.example'),
      aar_from = { [2] = 'bank.example', [3] = 'list.example' },
      signers = { ['forwarder2.example'] = true, ['forwarder3.example'] = true } })
    assert_equal(1, #adjusted)
  end)

  for name, f in pairs({
    ['no From'] = false,
    ['two From'] = from('sender.example', 'sender.example'),
    ['From without a domain'] = { { addr = 'user', domain = '' } },
  }) do
    test('DMARC reject is not adjusted with ' .. name, function()
      assert_equal(0, #adjust_dmarc({ from = f or nil }))
    end)
  end

  -- Another implementation may not escape the sender in its comments
  test('a DMARC result in the comment of an SPF result does not adjust', function()
    local adjusted = adjust_dmarc({ from = from('bank.example'), aar_text = {
      [3] = 'spf=pass (x)dmarc=pass header.from=bank.example(y) smtp.mailfrom=a@attacker.example; '
          .. 'dmarc=fail header.from=bank.example' } })
    assert_equal(0, #adjusted)
  end)

  test('two DMARC results in one AAR do not adjust', function()
    -- The sender split the comment, and the forwarder wrote its own result
    local adjusted = adjust_dmarc({ from = from('bank.example'), aar_text = {
      [3] = 'spf=pass (x); dmarc=pass header.from=bank.example (y) smtp.mailfrom=a@attacker.example; '
          .. 'dmarc=fail header.from=bank.example' } })
    assert_equal(0, #adjusted)
  end)

  test('an empty element does not hide the DMARC result after it', function()
    -- The sender ended its text with ";;", which ended the split there
    local adjusted = adjust_dmarc({ from = from('bank.example'), aar_text = {
      [3] = 'spf=pass (x); dmarc=pass header.from=bank.example;; (y) smtp.mailfrom=a@attacker.example; '
          .. 'dmarc=fail header.from=bank.example' } })
    assert_equal(0, #adjusted)
  end)

  test('a quote or a comment of the sender does not hide the DMARC result after it', function()
    -- The quote is closed by one the forwarder writes after its own result
    assert_equal(0, #adjust_dmarc({ from = from('bank.example'), aar_text = {
      [3] = 'spf=fail (x); dmarc=pass header.from=bank.example ") smtp.mailfrom=a@attacker.example; '
          .. 'dmarc=fail (p=reject) header.from=bank.example; dkim=none reason="no signature"' } }))
    assert_equal(0, #adjust_dmarc({ from = from('bank.example'), aar_text = {
      [3] = 'spf=fail (x); dmarc=pass header.from=bank.example (\\) smtp.mailfrom=a@attacker.example; '
          .. 'dmarc=fail (p=reject) header.from=bank.example; x-note=none (closing))' } }))
  end)

  test('a comment in front of an injected pass does not hide it from the count', function()
    for _, comment in ipairs({ '(;)', '(a\\))', '(\\()' }) do
      assert_equal(0, #adjust_dmarc({ from = from('bank.example'), aar_text = {
        [3] = 'spf=fail (x); ' .. comment .. ' dmarc=pass header.from=bank.example ") smtp.mailfrom=a@attacker.example; '
            .. 'dmarc=fail (p=reject) header.from=bank.example; dkim=none reason="no signature"' } }), comment)
    end
  end)

  test('an AAR too long to be read gives no DMARC result to trust', function()
    local dkim = {}
    for i = 1, 240 do
      dkim[#dkim + 1] = string.format('dkim=pass header.d=sig%d.bank.example header.s=selector%d-long-selector-name', i, i)
    end
    assert_equal(0, #adjust_dmarc({ from = from('bank.example'), aar_text = {
      [3] = table.concat(dkim, '; ') .. '; dmarc=pass header.from=bank.example' } }))
  end)

  test('a chain that fails before its seals are read is not sealed further', function()
    local _, symbols, cache = start_checks({ synchronous = true, count = 51 })
    assert_not_nil(symbols.ARC_INVALID)
    assert_not_nil(cache['arc-failure'])
    -- Comments nested deeper than the parser goes
    _, symbols, cache = start_checks({ synchronous = true, aar_text = {
      [3] = string.rep('(', 420) .. 'dmarc=pass' } })
    assert_not_nil(symbols.ARC_INVALID)
    assert_not_nil(cache['arc-failure'])
  end)

  test('a method property makes no DMARC result', function()
    assert_equal(0, #adjust_dmarc({ from = from('bank.example'), aar_text = {
      [3] = '"x" method=dmarc dmarc=pass header.from=bank.example' } }))
  end)

  test('a DMARC result in a comment does not lift the weight of trust', function()
    local _, symbols = start_checks({ synchronous = true,
      whitelisted_signers_map = { ['forwarder3.example'] = true }, aar_text = {
        [3] = 'dmarc=fail header.from=bank.example; '
            .. 'spf=pass (x)dmarc=pass header.from=bank.example(y) smtp.mailfrom=a@attacker.example' } })
    assert_equal(1, #symbols.ARC_ALLOW_TRUSTED)
    assert_equal(0.0, symbols.ARC_ALLOW_TRUSTED[1].weight)
  end)

  test('a DMARC result split off a comment does not lift the weight of trust', function()
    -- The forwarder wrote its own result first, the sender split the comment
    local _, symbols = start_checks({ synchronous = true,
      whitelisted_signers_map = { ['forwarder3.example'] = true }, aar_text = {
        [3] = 'dmarc=fail header.from=bank.example (policy=reject); spf=pass (x); '
            .. 'dmarc=pass header.from=bank.example; (y) smtp.mailfrom=a@attacker.example' } })
    assert_equal(1, #symbols.ARC_ALLOW_TRUSTED)
    assert_equal(0.0, symbols.ARC_ALLOW_TRUSTED[1].weight)
  end)

  test('domains that do not convert to A-labels never match', function()
    local adjusted = adjust_dmarc({ from = from('\255.example'), aar_text = {
      [3] = 'dmarc=pass header.from=\254.example' } })
    assert_equal(0, #adjusted)
  end)

  for name, hfrom in pairs({
    quoted = '"bank.example"',
    ['with a trailing dot'] = 'bank.example.',
    ['in angle brackets'] = '<bank.example>',
    ['as A-label of an IDN From'] = 'XN--BNK-SNA.example',
  }) do
    test('header.from ' .. name .. ' matches the From domain', function()
      local f = name:find('IDN') and from('B\195\132nk.example') or from('bank.example')
      local adjusted = adjust_dmarc({ from = f, aar_text = {
        [3] = 'dmarc=pass header.from=' .. hfrom } })
      assert_equal(1, #adjusted)
    end)
  end

  test('a newest AMS forgiven by the whitelist earns no trust', function()
    -- Nothing binds the sealed AARs to this message then: they can be
    -- replayed with another body and From
    local callbacks, symbols, cache = start_checks({ synchronous = true, signature_failure = true,
      whitelist = { ['forwarder3.example'] = true },
      whitelisted_signers_map = { ['forwarder3.example'] = true } })
    assert_nil(next(callbacks))
    assert_equal(1, #symbols.ARC_ALLOW)
    assert_nil(symbols.ARC_ALLOW_TRUSTED)
    assert_nil(cache.arc_trusted_aar)
    assert_equal(0, #adjust_dmarc({ from = from('sender.example'), signature_failure = true,
      whitelist = { ['forwarder3.example'] = true } }))
  end)
end)
