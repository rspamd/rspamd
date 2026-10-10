-- Vectors below are generated, not copied: every checksummed address is a real
-- Base58Check / bech32 / bech32m / CRC16 encoding of a known payload, and each
-- NEG_* entry is the same address with its last character changed.

context("Crypto addresses test", function()
  local lua_crypto_addresses = require "lua_crypto_addresses"

  local valid = {
    -- Bitcoin
    ['16L5yRNPTuciSgXGHqYwn9N6NeoKqopAu'] = 'bitcoin',                     -- P2PKH
    ['31nM1WuowNDzocNxPPW9NQWJEtwWpjfcLj'] = 'bitcoin',                    -- P2SH
    ['bc1qqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5fcj4z3'] = 'bitcoin',            -- bech32 P2WPKH
    -- BIP-350 bech32m: uses checksum constant 0x2bc830a3, not 1
    ['bc1pqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusqwk0jyn'] = 'bitcoin',
    -- v1 permits any 2-40 byte program, so a 21 byte one with clean padding is fine
    ['bc1pqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5kxkvra'] = 'bitcoin',
    ['BC1QQYPQXPQ9QCRSSZG2PVXQ6RS0ZQG3YYC5FCJ4Z3'] = 'bitcoin',            -- uppercase bech32
    ['bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a'] = 'bitcoin',
    ['BITCOINCASH:QPM2QSZNHKS23Z7629MMS6S4CWEF74VCWVY22GDX6A'] = 'bitcoin', -- uppercase cashaddr
    ['qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a'] = 'bitcoin',            -- bare cashaddr
    ['QPM2QSZNHKS23Z7629MMS6S4CWEF74VCWVY22GDX6A'] = 'bitcoin',            -- bare cashaddr, uppercase
    ['bitcoincash:qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpkch56vmk'] = 'bitcoin',
    ['bitcoincash:zqqszqgpqyqszqgpqyqszqgpqyqszqgpqyywmxr8cj'] = 'bitcoin', -- token-aware P2PKH
    -- Litecoin: distinguished from bitcoin by the decoded version byte
    ['LKKHMBjCU89fyFNgSRprDoD8Jb25N8uWvd'] = 'litecoin',
    ['M7zVKQKmtV5Rc7erVGVVC3khZbXxsS5HEX'] = 'litecoin',
    ['ltc1qqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5dyg36p'] = 'litecoin',
    ['LTC1QQYPQXPQ9QCRSSZG2PVXQ6RS0ZQG3YYC5DYG36P'] = 'litecoin',          -- uppercase bech32
    ['D5ERdEN1gsouFSs7zsq7VYJxyWP6dP28H1'] = 'dogecoin',
    ['TA4Y62o6YC2Zsck9rZVGTvqW1AQ7X9zTnj'] = 'tron',
    ['raLnyR4PTuc5SgXGHqYA894a4eoKqoFwu'] = 'xrp',
    ['t1Hxw6JqWMnhDK5jRCieg5bFHM2qt7UtQvu'] = 'zcash',
    ['t3Jex1rKwuh1bQFRrKpKGWDcDVZ8bbQuNrB'] = 'zcash',
    -- CIP-19 mainnet Shelley addresses: base (57 bytes), pointer, enterprise (29 bytes)
    ['addr1qyqqzqsrqszsvpcgpy9qkrqdpc83qygjzv2p29shrqv35xcur50p7gppyg3jgffxyu5zj23t9skjutesxyerxdp4xcmskm46z7'] = 'cardano',
    [('addr1qyqqzqsrqszsvpcgpy9qkrqdpc83qygjzv2p29shrqv35xcur50p7gppyg3jgffxyu5zj23t9skjutesxyerxdp4xcmskm46z7'):upper()] = 'cardano', -- uppercase
    ['addr1gyqqzqsrqszsvpcgpy9qkrqdpc83qygjzv2p29shrqv35xcpqgps5xhtvl'] = 'cardano',
    ['addr1vyqqzqsrqszsvpcgpy9qkrqdpc83qygjzv2p29shrqv35xcjrvarg'] = 'cardano',
    -- Cosmos SDK: 20 byte accounts and 32 byte module/contract addresses
    ['cosmos1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5lzv7xu'] = 'cosmos',
    ['COSMOS1QYPQXPQ9QCRSSZG2PVXQ6RS0ZQG3YYC5LZV7XU'] = 'cosmos',                -- uppercase
    ['cosmos1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0sxaggsw'] = 'cosmos',
    -- Leading zero symbols are significant: this payload starts with two zero bytes
    ['112D2adLM3UKy4Z4giRbReR6gjWuvHUqB'] = 'bitcoin',
    ['GAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPSABOV'] = 'stellar',
    ['EQABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fIP8B'] = 'ton',
    -- Format-only, no checksum available
    ['0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed'] = 'ethereum',
    ['4Ah82pJGF9p7kpzb6eU326EFZf2cDnimbTFVeJtx1qtBmUNJAEqN76R7PwPfHt3oWb8R6cKvhgyxQdDn53jFrK6wFx7RJWh'] = 'monero',
  }

  -- Same addresses with a busted checksum: every one of these must be rejected
  local invalid = {
    '16L5yRNPTuciSgXGHqYwn9N6NeoKqopAX',
    '31nM1WuowNDzocNxPPW9NQWJEtwWpjfcLX',
    'bc1qqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5fcj4z4',
    'bc1pqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusqwk0jyq',
    -- Structurally impossible SegWit programs that nonetheless carry a correct
    -- bech32/bech32m checksum. A checksum only proves the string survived
    -- transit; the witness version and program length still have to be real.
    'bc13qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5rkyx9v',                         -- witness version 17
    'bc1lqypqxpq9qcrsszg2pvxq6rs0zqg3yyc56x3l34',                         -- witness version 31
    'bc1qqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z53mkjx4',                       -- v0 with a 21 byte program
    'bc1pqum7079u',                                                       -- v1 program below the 2 byte floor
    'bc1pqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ruszzg3rysjjvfeg9yfzvla3', -- v1 above the 40 byte ceiling
    'ltc13qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5827zau',                        -- litecoin, witness version 17
    'bc1pqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z4tsze70',                       -- non-zero bits in the 5->8 padding
    -- BIP-173 requires decoders to reject mixed case. One per entry point:
    -- the bech32 branch, the prefixed cashaddr branch and the bare one.
    'bC1qqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5fcj4z3',                         -- mixed case bech32
    'bitcoinCash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a',             -- mixed case cashaddr
    'Qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a',                         -- mixed case bare cashaddr
    'LKKHMBjCU89fyFNgSRprDoD8Jb25N8uWvX',
    'ltc1qqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5dyg36q',
    'D5ERdEN1gsouFSs7zsq7VYJxyWP6dP28HX',
    'TA4Y62o6YC2Zsck9rZVGTvqW1AQ7X9zTnX',
    'raLnyR4PTuc5SgXGHqYA894a4eoKqoFwX',
    't1Hxw6JqWMnhDK5jRCieg5bFHM2qt7UtQvX',
    'addr1qyqqzqsrqszsvpcgpy9qkrqdpc83qygjzv2p29shrqv35xcur50p7gppyg3jgffxyu5zj23t9skjutesxyerxdp4xcmskm46z8',
    'cosmos1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5lzv7xq',
    -- A correct checksum on a payload that cannot be an address of the chain
    'cosmos1qqqqk0wkhp',                                                  -- 2 byte payload
    'addr1qqqqxn5hht',                                                    -- 2 byte payload
    'cosmos1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzszga8hs',                    -- 21 byte payload
    'addr1qyqqzqsrqszsvpcgpy9qkrqdpc83qygjzv2p29shrqv35xcur50p7gppyg3jgffxyu5zj23t9skjutesxyerxdp4xcgg24wk', -- base address of 56 bytes
    'addr1qqqqzqsrqszsvpcgpy9qkrqdpc83qygjzv2p29shrqv35xcur50p7gppyg3jgffxyu5zj23t9skjutesxyerxdp4xcms8duasr', -- testnet network id under the mainnet prefix
    'addr1syqqzqsrqszsvpcgpy9qkrqdpc83qygjzv2p29shrqv35xcur50p7gppyg3jgffxyu5zj23t9skjutesxyerxdp4xcms4czay6', -- Byron type
    'addr1uyqqzqsrqszsvpcgpy9qkrqdpc83qygjzv2p29shrqv35xcg36alg',         -- reward address type
    'addr1gxqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqq3acw9e',
    'addr1gyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqvqqqqqqat9c3h',
    'addr1gyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgqqqqqqvv4y2k',
    'addr1gyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqvzllllllllllll7lcqqq2ruxtk',
    'bitcoincash:sqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc3zsmrpy',
    'bitcoincash:yqqszqgpqyqszqgpqyqszqgpqyqszqgpqyds8d3dsw',             -- unsupported type 4
    'bitcoincash:qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyvada2h6p',
    'bitcoincash:qqqszqgpqyqszqgpqyqszqgpqyqszqgpq9s83n5z5q',
    -- Prepending zero symbols decodes to the same bytes but is not the address
    '1' .. '16L5yRNPTuciSgXGHqYwn9N6NeoKqopAu',
    '1' .. '112D2adLM3UKy4Z4giRbReR6gjWuvHUqB',
    'r' .. 'raLnyR4PTuc5SgXGHqYA894a4eoKqoFwu',
    'GAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPSABOA',
    'EQABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fIP8A',
  }

  test("classifies valid addresses", function()
    for addr, expected in pairs(valid) do
      local got = lua_crypto_addresses.classify(nil, addr)
      assert_equal(got, expected,
          string.format('%s: expected %s, got %s', addr, expected, tostring(got)))
    end
  end)

  test("rejects addresses with a broken checksum", function()
    for _, addr in ipairs(invalid) do
      local got = lua_crypto_addresses.classify(nil, addr)
      assert_nil(got, string.format('%s must not validate, got %s', addr, tostring(got)))
    end
  end)

  test("rejects things that merely look like addresses", function()
    local junk = {
      '',
      'hello',
      '0xdeadbeef',                                   -- too short for EVM
      '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeZ',   -- non-hex in EVM
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',           -- Base58 shaped, bad checksum
      'notanaddress1qqqqqqqqqqqqqqqqqqqq',            -- unknown bech32 hrp
      -- 43-44 char Base58 runs are not claimed by anything: Solana has no
      -- checksum to verify, so that shape is indistinguishable from base64 noise
      'So11111111111111111111111111111111111111112',
      'vQBQPEjJmki5fhBboGBWRJhmcFkMvrr4Fu3tMSJ5Edyn',
    }

    for _, addr in ipairs(junk) do
      assert_nil(lua_crypto_addresses.classify(nil, addr),
          string.format('%s must not validate', addr))
    end
  end)

  local rspamd_task = require "rspamd_task"

  local ltc = 'LKKHMBjCU89fyFNgSRprDoD8Jb25N8uWvd'
  local ltc_bad = 'LKKHMBjCU89fyFNgSRprDoD8Jb25N8uWvX'
  local xrp = 'raLnyR4PTuc5SgXGHqYA894a4eoKqoFwu'
  local btc = '16L5yRNPTuciSgXGHqYwn9N6NeoKqopAu'

  -- Cuts an address into groups of `n` characters joined by `sep`
  local function split(addr, n, sep)
    local parts = {}

    for i = 1, #addr, n do
      parts[#parts + 1] = addr:sub(i, i + n - 1)
    end

    return table.concat(parts, sep)
  end

  local function with_task(body, fn)
    local msg = "From: <>\r\nTo: <nobody@example.com>\r\nSubject: test\r\n" ..
        "Content-Type: text/plain\r\n\r\n" .. body .. "\r\n"
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)

    assert(res, "failed to load message")
    task:process_message()
    fn(task)
    task:destroy()
  end

  local function flat(task)
    return lua_crypto_addresses.get_addresses_flat(task)
  end

  test("finds a plain address in a message", function()
    with_task('send it to ' .. btc .. ' please', function(task)
      assert_rspamd_table_eq({ actual = flat(task), expect = { btc } })
    end)
  end)

  test("finds addresses split by whitespace and reports them joined", function()
    with_task('pay ' .. split(ltc, 4, ' ') .. ' today', function(task)
      assert_rspamd_table_eq({ actual = flat(task), expect = { ltc } })
    end)

    with_task('pay ' .. split(xrp, 5, '\t') .. ' today', function(task)
      assert_rspamd_table_eq({ actual = flat(task), expect = { xrp } })
    end)
  end)

  test("finds a split address next to words that join the same run", function()
    -- None of these words contain l, I, O or 0, so they all land in one run
    -- together with the address and the real tokens have to be cut out of it
    with_task('send to ' .. split(ltc, 4, ' ') .. ' now thanks', function(task)
      assert_rspamd_table_eq({ actual = flat(task), expect = { ltc } })
    end)
  end)

  test("does not report a split address twice", function()
    with_task(ltc .. ' also written as ' .. split(ltc, 4, ' '), function(task)
      assert_rspamd_table_eq({ actual = flat(task), expect = { ltc } })
    end)
  end)

  test("rejects a split address with a broken checksum", function()
    with_task('pay ' .. split(ltc_bad, 4, ' '), function(task)
      assert_rspamd_table_eq({ actual = flat(task), expect = {} })
    end)
  end)

  test("ignores prose that merely looks like split tokens", function()
    with_task('the quick brown fox jumps over 13 lazy dogs and then some more words ' ..
        'that go on for a while 2024', function(task)
      assert_rspamd_table_eq({ actual = flat(task), expect = {} })
    end)
  end)

  test("spaced scan stops at its candidate budget", function()
    local limits = lua_crypto_addresses.limits
    local saved = limits.max_spaced_candidates

    limits.max_spaced_candidates = 0
    with_task('pay ' .. split(ltc, 4, ' '), function(task)
      assert_rspamd_table_eq({ actual = flat(task), expect = {} })
    end)

    -- Distinct runs that all pass the cheap filters but fail the checksum use
    -- the budget up, so an address after them is never reached
    limits.max_spaced_candidates = 2
    local filler = {}

    for i = 1, 20 do
      -- Two digits from 1-9 each: 0 is not a Base58 character
      filler[#filler + 1] = split(string.format('1Nabcdefghijkmnopqrstuvwxy%d%d',
          i % 9 + 1, math.floor(i / 9) + 1), 4, ' ')
    end

    with_task(table.concat(filler, ' ') .. ' ' .. split(ltc, 4, ' '), function(task)
      assert_rspamd_table_eq({ actual = flat(task), expect = {} })
    end)

    limits.max_spaced_candidates = saved
    with_task('pay ' .. split(ltc, 4, ' '), function(task)
      assert_rspamd_table_eq({ actual = flat(task), expect = { ltc } })
    end)
  end)

  test("add_from_string only stores text until get_addresses runs", function()
    with_task('nothing to see here', function(task)
      lua_crypto_addresses.add_from_string(task, 'qr: ' .. btc)

      -- Scanning here would cache a result for a message whose text parts do
      -- not exist yet when lua_content handlers call this
      assert_nil(task:cache_get('crypto_addresses'))
      assert_rspamd_table_eq({ actual = flat(task), expect = { btc } })

      -- The deferred scan ends up in the same cache the later consumers read
      assert_rspamd_table_eq({ actual = task:cache_get('crypto_addresses').bitcoin, expect = { btc } })
    end)
  end)

  test("add_from_string merges several early calls with the message", function()
    with_task('already here: ' .. btc, function(task)
      lua_crypto_addresses.add_from_string(task, ltc)
      lua_crypto_addresses.add_from_string(task, split(xrp, 5, ' '))
      lua_crypto_addresses.add_from_string(task, btc)
      assert_rspamd_table_eq({ actual = flat(task), expect = { btc, ltc, xrp } })
    end)
  end)

  test("add_from_string scans at once after get_addresses", function()
    with_task('nothing to see here', function(task)
      assert_rspamd_table_eq({ actual = flat(task), expect = {} })

      lua_crypto_addresses.add_from_string(task, 'qr: ' .. btc)
      assert_rspamd_table_eq({ actual = flat(task), expect = { btc } })

      -- Split form, and a repeat of something already on record
      lua_crypto_addresses.add_from_string(task, split(ltc, 4, ' ') .. ' ' .. btc)
      lua_crypto_addresses.add_from_string(task, btc)
      assert_rspamd_table_eq({ actual = flat(task), expect = { btc, ltc } })
    end)
  end)

  test("add_from_string tolerates empty input", function()
    with_task('nothing to see here', function(task)
      lua_crypto_addresses.add_from_string(task, nil)
      lua_crypto_addresses.add_from_string(task, '')
      assert_nil(task:cache_get('crypto_addresses_pending'))
      assert_rspamd_table_eq({ actual = flat(task), expect = {} })
    end)
  end)

  test("add_from_string ignores input past the size limit", function()
    local limits = lua_crypto_addresses.limits
    local saved = limits.max_string_size

    limits.max_string_size = 64
    with_task('nothing to see here', function(task)
      lua_crypto_addresses.add_from_string(task, string.rep(' ', 64) .. btc)
      assert_rspamd_table_eq({ actual = flat(task), expect = {} })
    end)

    limits.max_string_size = saved
  end)

  test("add_from_string stops storing past the pending limit", function()
    local limits = lua_crypto_addresses.limits
    local saved = limits.max_pending_size

    limits.max_pending_size = 40
    with_task('nothing to see here', function(task)
      lua_crypto_addresses.add_from_string(task, string.rep(' ', 30))
      -- Only 10 bytes of room are left, so this is cut inside the address
      lua_crypto_addresses.add_from_string(task, btc)
      lua_crypto_addresses.add_from_string(task, ltc)
      assert_rspamd_table_eq({ actual = flat(task), expect = {} })
    end)

    limits.max_pending_size = saved
  end)

  test("finds a TON address that ends in a dash", function()
    -- '-' belongs to the URL safe alphabet but is not a word character, so a
    -- plain \b after the address would never match
    local ton = 'EQ' .. string.rep('A', 42) .. 'IOs-'

    assert_equal(lua_crypto_addresses.classify(nil, ton), 'ton')

    for _, body in ipairs({ 'ton: ' .. ton .. ' thanks', 'ton: ' .. ton, ton .. '.', '(' .. ton .. ')' }) do
      with_task(body, function(task)
        assert_rspamd_table_eq({ actual = flat(task), expect = { ton } })
      end)
    end
  end)

  test("candidate budget stops the scan", function()
    local limits = lua_crypto_addresses.limits
    local saved = limits.max_candidates
    local junk = {}

    -- Base58 shaped, so each one reaches the checksum, and distinct, so the
    -- memo does not make them free
    for i = 1, 6 do
      junk[i] = '1Nabcdefghijkmnopqrstuvwxyz' .. i
    end

    local body = table.concat(junk, ' ') .. ' ' .. btc

    limits.max_candidates = 3
    with_task(body, function(task)
      assert_rspamd_table_eq({ actual = flat(task), expect = {} })
    end)

    limits.max_candidates = saved
    with_task(body, function(task)
      assert_rspamd_table_eq({ actual = flat(task), expect = { btc } })
    end)
  end)

  test("address cap ends the scan", function()
    local limits = lua_crypto_addresses.limits
    local saved = limits.max_addresses

    limits.max_addresses = 1
    with_task(ltc .. ' ' .. btc, function(task)
      assert_rspamd_table_eq({ actual = flat(task), expect = { ltc } })
    end)

    limits.max_addresses = saved
  end)

  test("does not treat slice edges as address boundaries", function()
    local limits = lua_crypto_addresses.limits
    local saved = limits.chunk_size
    local ton = 'EQ' .. string.rep('A', 42) .. 'IOs-'

    limits.chunk_size = 512

    for _, address in ipairs({ btc, ton }) do
      local bodies = {
        string.rep('.', 512 - #address) .. address .. 'a' .. string.rep('.', 600),
        string.rep('.', 255) .. 'a' .. address .. string.rep('.', 600),
        string.rep('.', 768 - #address) .. address .. 'a' .. string.rep('.', 600),
        string.rep('.', 511) .. 'a' .. address .. string.rep('.', 600),
      }

      for _, body in ipairs(bodies) do
        with_task(body, function(task)
          assert_rspamd_table_eq({ actual = flat(task), expect = {} })
        end)
      end

      for _, body in ipairs({ address .. string.rep('.', 600), string.rep('.', 600) .. address }) do
        with_task(body, function(task)
          assert_rspamd_table_eq({ actual = flat(task), expect = { address } })
        end)
      end
    end

    limits.chunk_size = saved
  end)

  test("finds addresses at the borders of the slices a large text is searched in", function()
    local limits = lua_crypto_addresses.limits
    local saved = limits.chunk_size

    limits.chunk_size = 512

    for _, offset in ipairs({ 0, 100, 240, 300, 480, 500, 511, 512, 700, 1500 }) do
      with_task(string.rep('.', offset) .. btc .. string.rep('.', 600), function(task)
        assert_rspamd_table_eq({ actual = flat(task), expect = { btc } })
      end)
    end

    limits.chunk_size = saved
  end)
end)
