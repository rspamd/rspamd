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
    ['addr1qyqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qz42jwu'] = 'cardano',
    ['ADDR1QYQSYQCYQ5RQWZQFPG9SCRGWPUGPZYSNZS23V9CCRYDPK8QZ42JWU'] = 'cardano',  -- uppercase
    ['cosmos1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5lzv7xu'] = 'cosmos',
    ['COSMOS1QYPQXPQ9QCRSSZG2PVXQ6RS0ZQG3YYC5LZV7XU'] = 'cosmos',                -- uppercase
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
    'addr1qyqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qz42jwq',
    'cosmos1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5lzv7xq',
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
end)
