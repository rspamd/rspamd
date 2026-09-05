--[[
Copyright (c) 2022, Vsevolod Stakhov <vsevolod@rspamd.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
]]--

--[[[
-- @module lua_crypto_addresses
-- Extraction and validation of cryptocurrency wallet addresses.
--
-- The entry point is `get_addresses(task)`, which scans the subject and all
-- text parts once and memoises the result on the task. Both the rule symbols
-- and the `crypto_addresses` selector go through it, so a message is scanned
-- at most once no matter how many consumers ask, and it is not scanned at all
-- when nobody does.
--
-- Currencies whose addresses carry a verifiable checksum are validated in full
-- (Bitcoin and forks, XRP, Zcash transparent, Cardano, Cosmos, Stellar, TON).
-- The `*_maybe` ones have no checksum that can be verified here and are matched
-- on shape only - treat them as weak signals.
--]]

local bit = require "bit"
local hash = require "rspamd_cryptobox_hash"
local lua_util = require "lua_util"
local rspamd_regexp = require "rspamd_regexp"
local rspamd_util = require "rspamd_util"

local N = "crypto_addresses"
local E = {}
local unpack_function = table.unpack or unpack

local exports = {}

-- Base58 --------------------------------------------------------------------

-- Byte indexed lookup tables: indexing by `string.byte` avoids building a
-- one-character string and hashing it for every character of every candidate
local function make_b58_lut(alphabet)
  local lut = {}

  for i = 1, #alphabet do
    lut[alphabet:byte(i)] = i - 1
  end

  return lut
end

-- Bitcoin/Litecoin/Tron/Dogecoin/Zcash Base58 alphabet (excludes 0, O, I, l)
local btc_lut = make_b58_lut("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
-- XRP Base58: same character set, different ordering
local xrp_lut = make_b58_lut("rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz")

--[[[
-- Decodes a Base58Check string of `total_len` bytes and verifies the trailing
-- 4 byte double SHA256 checksum. Returns the decoded bytes (a table of
-- integers, checksum included) or nil when the input is not valid.
--]]
local function base58check_decode(word, lut, total_len)
  local bytes = {}

  for i = 1, total_len do
    bytes[i] = 0
  end

  local byte = string.byte

  for i = 1, #word do
    local acc = lut[byte(word, i)]

    if not acc then
      -- Character outside of the alphabet
      return nil
    end

    for j = total_len, 1, -1 do
      acc = acc + 58 * bytes[j]
      local rem = acc % 256
      bytes[j] = rem
      acc = (acc - rem) / 256
    end

    if acc ~= 0 then
      -- Does not fit into total_len bytes
      return nil
    end
  end

  local body_len = total_len - 4
  -- A single update on the whole body: one C call instead of body_len calls,
  -- each of which would otherwise allocate a one byte string
  local body = string.char(unpack_function(bytes, 1, body_len))
  local sha = hash.create_specific('sha256', body):bin()
  sha = hash.create_specific('sha256', sha):bin()

  for i = 1, 4 do
    if string.sub(sha, i, i) ~= string.char(bytes[body_len + i]) then
      return nil
    end
  end

  return bytes
end

-- Version byte of a 25 byte Base58Check payload identifies the currency, so
-- there is no need to guess it from the leading character
local b58_versions = {
  [0x00] = 'bitcoin',  -- P2PKH
  [0x05] = 'bitcoin',  -- P2SH
  [0x30] = 'litecoin', -- P2PKH
  [0x32] = 'litecoin', -- P2SH (M...)
  [0x1e] = 'dogecoin', -- P2PKH
  [0x16] = 'dogecoin', -- P2SH
  [0x41] = 'tron',     -- TRX / TRC-20
}

-- Zcash transparent addresses use a two byte version prefix
local zcash_versions = {
  [0x1cb8] = true, -- t1, P2PKH
  [0x1cbd] = true, -- t3, P2SH
}

-- Bech32 / Bech32m ----------------------------------------------------------

local BECH32_CONST = 1
local BECH32M_CONST = 0x2bc830a3
local bech32_charset = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
local bech32_lut = {}

do
  for i = 1, #bech32_charset do
    bech32_lut[bech32_charset:byte(i)] = i - 1
  end
end

local function bech32_polymod(values)
  local chk = 1
  local gen = { 0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3 }

  for _, v in ipairs(values) do
    local top = bit.rshift(chk, 25)

    chk = bit.bxor(bit.lshift(bit.band(chk, 0x1ffffff), 5), v)

    for i = 1, 5 do
      if bit.band(bit.rshift(top, i - 1), 0x1) ~= 0 then
        chk = bit.bxor(chk, gen[i])
      end
    end
  end

  return chk
end

local function hrp_expand(hrp)
  local ret = {}
  local byte = string.byte

  for i = 1, #hrp do
    ret[#ret + 1] = bit.rshift(byte(hrp, i), 5)
  end

  ret[#ret + 1] = 0

  for i = 1, #hrp do
    ret[#ret + 1] = bit.band(byte(hrp, i), 0x1f)
  end

  return ret
end

local function bech32_data(input)
  local d = {}
  local byte = string.byte

  for i = 1, #input do
    local v = bech32_lut[byte(input, i)]

    if not v then
      return nil
    end

    d[i] = v
  end

  return d
end

-- Returns the checksum constant the input verifies against, or nil
local function bech32_checksum(hrp, data)
  local values = hrp_expand(hrp)

  for _, v in ipairs(data) do
    values[#values + 1] = v
  end

  return bech32_polymod(values)
end

--[[[
-- Regroups the 5 bit values in `data[first..last]` into bytes, the way BIP-173
-- specifies. Returns nil when the trailing padding is not a valid tail: more
-- than four leftover bits, or leftover bits that are not zero.
--]]
local function bech32_to_bytes(data, first, last)
  local acc, bits = 0, 0
  local out = {}

  for i = first, last do
    acc = bit.bor(bit.lshift(acc, 5), data[i])
    bits = bits + 5

    while bits >= 8 do
      bits = bits - 8
      out[#out + 1] = bit.band(bit.rshift(acc, bits), 0xff)
    end

    -- Keep only the bits still owed to the next byte, so acc cannot overflow
    acc = bit.band(acc, bit.lshift(1, bits) - 1)
  end

  if bits >= 5 or acc ~= 0 then
    return nil
  end

  return out
end

-- Bech32 human readable parts we care about, mapped to a currency. Segwit like
-- chains (bc/ltc) carry a witness version that selects the checksum constant.
local bech32_hrps = {
  bc = { currency = 'bitcoin', segwit = true },
  ltc = { currency = 'litecoin', segwit = true },
  addr = { currency = 'cardano' },
  cosmos = { currency = 'cosmos' },
}

--[[[
-- Validates a bech32/bech32m string and returns the currency name, or nil.
--]]
local function check_bech32(word)
  local lower = word:lower()

  if word ~= lower and word ~= word:upper() then
    return nil
  end

  -- The separator is the *last* '1', as the hrp may itself contain one
  local sep = lower:find('1[^1]*$')

  if not sep or sep < 2 or sep + 7 > #lower then
    return nil
  end

  local hrp = lower:sub(1, sep - 1)
  local known = bech32_hrps[hrp]

  if not known then
    return nil
  end

  local data = bech32_data(lower:sub(sep + 1))

  if not data then
    return nil
  end

  local chk = bech32_checksum(hrp, data)

  if known.segwit then
    local witver = data[1]

    -- The 5 bit field holds 0..31, but only 0..16 are real witness versions
    if witver > 16 then
      return nil
    end

    -- BIP-173 (v0) uses the constant 1, BIP-350 (v1+, i.e. taproot) uses
    -- 0x2bc830a3. Accepting only the former silently drops every P2TR address.
    local expected = (witver == 0) and BECH32_CONST or BECH32M_CONST

    if chk ~= expected then
      return nil
    end

    -- A correct checksum only says the string was not corrupted in transit; the
    -- witness program itself still has to be one that could exist on chain.
    -- Everything between the version and the 6 checksum characters is the program.
    local prog = bech32_to_bytes(data, 2, #data - 6)

    if not prog then
      return nil
    end

    local plen = #prog

    if plen < 2 or plen > 40 then
      return nil
    end

    -- v0 is only ever P2WPKH (20 bytes) or P2WSH (32 bytes)
    if witver == 0 and plen ~= 20 and plen ~= 32 then
      return nil
    end

    return known.currency
  end

  if chk == BECH32_CONST then
    return known.currency
  end

  return nil
end

-- Bitcoin Cash cashaddr -----------------------------------------------------

local function check_cashaddr(task, word)
  local lower = word:lower()

  if word ~= lower and word ~= word:upper() then
    return nil
  end

  local colon = lower:find(':', 1, true)
  local prefix = 'bitcoincash'
  local address_part = lower

  if colon then
    prefix = lower:sub(1, colon - 1)
    address_part = lower:sub(colon + 1)
  end

  if prefix ~= 'bitcoincash' and prefix ~= 'bchtest' then
    return nil
  end

  local decoded = bech32_data(address_part)

  if not decoded or #decoded <= 8 then
    return nil
  end

  local polymod_tbl = {}
  local byte = string.byte

  for i = 1, #prefix do
    polymod_tbl[#polymod_tbl + 1] = bit.band(byte(prefix, i), 0x1f)
  end

  -- For the separator
  polymod_tbl[#polymod_tbl + 1] = 0

  for _, v in ipairs(decoded) do
    polymod_tbl[#polymod_tbl + 1] = v
  end

  lua_util.debugm(N, task, 'cashaddr polymod table for %s: %s', word, polymod_tbl)

  if rspamd_util.btc_polymod(polymod_tbl) then
    return 'bitcoin'
  end

  return nil
end

-- CRC16/XMODEM (Stellar and TON) --------------------------------------------

local function crc16_xmodem(str, len)
  local crc = 0
  local byte = string.byte

  for i = 1, len do
    crc = bit.band(bit.bxor(crc, bit.lshift(byte(str, i), 8)), 0xffff)

    for _ = 1, 8 do
      if bit.band(crc, 0x8000) ~= 0 then
        crc = bit.band(bit.bxor(bit.lshift(crc, 1), 0x1021), 0xffff)
      else
        crc = bit.band(bit.lshift(crc, 1), 0xffff)
      end
    end
  end

  return crc
end

-- Stellar: RFC4648 base32 of version byte + 32 byte key + CRC16 (little endian)
local function check_stellar(word)
  local raw = rspamd_util.decode_base32(word, 'rfc')

  if not raw then
    return nil
  end

  raw = tostring(raw)

  if #raw ~= 35 or string.byte(raw, 1) ~= 0x30 then
    return nil
  end

  local crc = crc16_xmodem(raw, 33)
  local stored = string.byte(raw, 34) + bit.lshift(string.byte(raw, 35), 8)

  if crc == stored then
    return 'stellar'
  end

  return nil
end

-- TON: base64url of tag + workchain + 32 byte hash + CRC16 (big endian)
local function check_ton(word)
  -- rspamd only decodes standard base64, so translate the URL safe alphabet
  local std = word:gsub('%-', '+'):gsub('_', '/')
  local raw = rspamd_util.decode_base64(std)

  if not raw then
    return nil
  end

  raw = tostring(raw)

  if #raw ~= 36 then
    return nil
  end

  -- Tag: 0x11 bounceable, 0x51 non bounceable, +0x80 for testnet only
  local tag = bit.band(string.byte(raw, 1), 0x7f)

  if tag ~= 0x11 and tag ~= 0x51 then
    return nil
  end

  local crc = crc16_xmodem(raw, 34)
  local stored = bit.lshift(string.byte(raw, 35), 8) + string.byte(raw, 36)

  if crc == stored then
    return 'ton'
  end

  return nil
end

-- Format only checks --------------------------------------------------------

-- Ethereum and every EVM compatible chain (BSC, Polygon, Arbitrum, Avalanche
-- C-chain, Base, ...) share this format. EIP-55 mixed case checksum needs
-- Keccak-256, which rspamd Lua does not provide.
local function check_evm(word)
  if #word == 42 and word:match('^0x%x+$') then
    return 'ethereum'
  end

  return nil
end

-- Monero standard address: 95 Base58 chars starting with 4. The checksum is a
-- Keccak-256 digest, so only the shape can be verified here.
local function check_monero(word)
  if #word == 95 and word:match('^4[1-9AB][1-9A-HJ-NP-Za-km-z]+$') then
    return 'monero'
  end

  return nil
end

-- Classification ------------------------------------------------------------

--[[[
-- @function lua_crypto_addresses.classify(task, word)
-- Returns the currency name for `word`, or nil when it is not a valid address.
-- Validators are tried in order of specificity; each has a cheap shape guard,
-- so a candidate reaches the expensive Base58Check decode only as a last resort.
--]]
local function classify(task, word)
  local len = #word

  -- Cheap and unambiguous shapes first
  if word:sub(1, 2) == '0x' then
    return check_evm(word)
  end

  if word:find(':', 1, true) then
    return check_cashaddr(task, word)
  end

  -- Bitcoin Cash addresses are frequently pasted without their 'bitcoincash:'
  -- prefix. The payload of a hash160 cashaddr is always 42 characters, which is
  -- tight enough to keep this from matching arbitrary lowercase runs.
  if len == 42 and word:lower():match('^[qpzry9x8gf2tvdw0s3jn54khce6mua7l]+$') then
    return check_cashaddr(task, word)
  end

  if len == 56 and word:match('^G[A-Z2-7]+$') then
    return check_stellar(word)
  end

  if len == 48 and word:match('^[EUk0]Q[A-Za-z0-9_%-]+$') then
    return check_ton(word)
  end

  -- Bech32 family: anything shaped hrp + '1' + data. This is tried before the
  -- Base58 decode so that a lowercase bech32 string is never mistaken for an
  -- XRP address (both alphabets overlap).
  if word:match('^[%a]+1[%w]+$') then
    local res = check_bech32(word)

    if res then
      return res
    end
  end

  -- Zcash transparent: two byte version, 26 byte payload
  if len == 35 and word:sub(1, 1) == 't' then
    local bytes = base58check_decode(word, btc_lut, 26)

    if bytes then
      local version = bit.lshift(bytes[1], 8) + bytes[2]

      if zcash_versions[version] then
        return 'zcash'
      end
    end

    return nil
  end

  -- XRP shares the Base58 character set but uses its own ordering
  if word:sub(1, 1) == 'r' and len >= 25 and len <= 35 then
    local bytes = base58check_decode(word, xrp_lut, 25)

    if bytes and bytes[1] == 0x00 then
      return 'xrp'
    end
  end

  -- Bitcoin and its Base58Check forks: supported version bytes have stable
  -- leading characters, which avoids decoding arbitrary Base58-like tokens.
  if len >= 25 and len <= 35 and word:sub(1, 1):match('^[13LM9ADT]$') then
    local bytes = base58check_decode(word, btc_lut, 25)

    if bytes then
      local currency = b58_versions[bytes[1]]

      if currency then
        return currency
      end

      return nil
    end
  end

  -- Checksum-less formats last: they accept on shape alone
  if len == 95 then
    return check_monero(word)
  end

  return nil
end

exports.classify = classify

--[[[
-- Every currency `classify` can return, in a fixed order. Kept here rather than
-- in the rules so that the symbols and the selector agree on the ordering, which
-- is what makes the selector output and the symbol options stable across runs.
--]]
exports.currencies = {
  'bitcoin',
  'litecoin',
  'dogecoin',
  'tron',
  'xrp',
  'zcash',
  'cardano',
  'cosmos',
  'stellar',
  'ton',
  'ethereum',
  'monero',
}

-- Extraction ----------------------------------------------------------------

-- A single candidate regexp keeps the scan to one pass per text part; the
-- validators above decide what a candidate actually is.
local wallet_re = rspamd_regexp.create([[/\b(?:]] ..
    [[0x[0-9a-fA-F]{40}|]] ..                                  -- EVM
    [[G[A-Z2-7]{55}|]] ..                                      -- Stellar
    [[[EUk0]Q[A-Za-z0-9_-]{46}|]] ..                           -- TON
    [[[A-Za-z]{2,12}1[qpzry9x8gf2tvdw0s3jn54khce6mua7lQPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{10,100}|]] .. -- bech32/bech32m
    [[[A-Za-z]+:[qpzry9x8gf2tvdw0s3jn54khce6mua7lQPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{14,}|]] .. -- cashaddr with prefix
    [[[qpzry9x8gf2tvdw0s3jn54khce6mua7lQPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{42}|]] .. -- cashaddr without prefix
    [[4[1-9AB][1-9A-HJ-NP-Za-km-z]{93}|]] ..                   -- Monero
    [[[13LM9ADTrt][1-9A-HJ-NP-Za-km-z]{24,34}]] ..             -- Base58Check family
    [[)\b/]])

-- Subject (decoded) plus every text part
local function get_haystacks(task)
  local haystacks = {}

  local subject = task:get_header('Subject')

  if subject and #subject > 0 then
    haystacks[#haystacks + 1] = subject
  end

  for _, part in ipairs(task:get_text_parts() or E) do
    local content = part:get_content('content_oneline')

    if content and #content > 0 then
      haystacks[#haystacks + 1] = content
    end
  end

  return haystacks
end

--[[[
-- @function lua_crypto_addresses.get_addresses(task)
-- Returns a table of `currency -> {address, ...}` for the message, computing it
-- on the first call and memoising it on the task. Returns an empty table when
-- the message has no wallet addresses.
--]]
local function get_addresses(task)
  local cached = task:cache_get('crypto_addresses')

  if cached then
    return cached
  end

  local found = {}
  local seen = {}

  for _, hay in ipairs(get_haystacks(task)) do
    for _, raw_word in ipairs(wallet_re:search(hay) or E) do
      local word = tostring(raw_word)
      local currency = seen[word]

      if currency == nil then
        -- Memoise failures too: without this, every repetition of a candidate
        -- (the same body in a text and an html part, say) pays for the full
        -- Base58Check decode again
        currency = classify(task, word) or false
        seen[word] = currency

        if currency then
          local lst = found[currency]

          if not lst then
            lst = {}
            found[currency] = lst
          end

          lst[#lst + 1] = word
          lua_util.debugm(N, task, 'found valid %s address: %s', currency, word)
        end
      end
    end
  end

  task:cache_set('crypto_addresses', found)

  return found
end

exports.get_addresses = get_addresses

--[[[
-- @function lua_crypto_addresses.get_addresses_flat(task, currency, typed)
-- Flat list of the addresses found in the message, restricted to `currency`
-- when it is given. Addresses are returned bare, so that they can be matched
-- against a map or looked up in DNS directly; pass a truthy `typed` to get
-- `currency:address` strings instead.
--
-- The order follows `exports.currencies`, so the result is stable across runs.
--]]
exports.get_addresses_flat = function(task, currency, typed)
  local found = get_addresses(task)
  local res = {}

  if currency == '' then
    -- An empty first argument is how a config asks for "all currencies" while
    -- still passing a second one
    currency = nil
  end

  for _, cur in ipairs(exports.currencies) do
    if not currency or cur == currency then
      for _, addr in ipairs(found[cur] or E) do
        res[#res + 1] = typed and (cur .. ':' .. addr) or addr
      end
    end
  end

  return res
end

return exports
