--[[
Copyright (c) 2019, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

-- Bitcoin filter rules

local fun = require "fun"
local bit = require "bit"
local off = 0
local base58_dec = fun.tomap(fun.map(
    function(c)
      off = off + 1
      return c,(off - 1)
    end,
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"))

local function is_traditional_btc_address(word)
  local hash = require "rspamd_cryptobox_hash"

  local bytes = {}
  for i=1,25 do bytes[i] = 0 end
  -- Base58 decode loop
  fun.each(function(ch)
    local acc = base58_dec[ch] or 0
    for i=25,1,-1 do
      acc = acc + (58 * bytes[i]);
      bytes[i] = acc % 256
      acc = math.floor(acc / 256);
    end
  end, word)
  -- Now create a validation tag
  local sha256 = hash.create_specific('sha256')
  for i=1,21 do
    sha256:update(string.char(bytes[i]))
  end
  sha256 = hash.create_specific('sha256', sha256:bin()):bin()

  -- Compare tags
  local valid = true
  for i=1,4 do
    if string.sub(sha256, i, i) ~= string.char(bytes[21 + i]) then
      valid = false
    end
  end

  return valid
end

-- Beach32 checksum combiner
local function polymod(...)
  local chk = 1;
  local gen = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
  for _,t in ipairs({...}) do
    for _,v in ipairs(t) do
      local top = bit.rshift(chk, 25)

      chk = bit.bxor(bit.lshift(bit.band(chk, 0x1ffffff), 5), v)
      for i=1,5 do
        if bit.band(bit.rshift(top, i - 1), 0x1) ~= 0 then
          chk = bit.bxor(chk, gen[i])
        end
      end
    end
  end

  return chk
end

-- Beach32 expansion function
local function hrpExpand(hrp)
  local ret = {}
  fun.each(function(byte)
    ret[#ret + 1] = bit.rshift(byte, 5)
  end, fun.map(string.byte, fun.iter(hrp)))
  ret[#ret + 1] = 0
  fun.each(function(byte)
    ret[#ret + 1] = bit.band(byte, 0x1f)
  end, fun.map(string.byte, fun.iter(hrp)))

  return ret
end

local function verify_beach32_cksum(hrp, elts)
  return polymod(hrpExpand(hrp), elts) == 1
end

local function is_segwit_bech32_address(word)
  local has_upper, has_lower, has_invalid

  if #word > 90 then return false end

  fun.each(function(ch)
    if ch < 33 or ch > 126 then
      has_invalid = true
    elseif ch >= 97 and ch <= 122 then
      has_lower = true
    elseif ch >= 65 and ch <= 90 then
      has_upper = true;
    end
  end, fun.map(string.byte, fun.iter(word)))

  if has_invalid or (has_lower and has_upper) then
    return false
  end

  word = word:lower()
  local last_one_pos = word:find('1[^1]*$')
  if not last_one_pos or (last_one_pos < 1 or last_one_pos + 7 > #word) then
    return false
  end
  local hrp = word:sub(1, last_one_pos - 1)
  local d = {}
  local charset = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  for i=last_one_pos + 1,#word do
    local c = word:sub(i, i)
    local pos = charset:find(c)

    if not pos then
      return false
    end
    d[#d + 1] = pos - 1
  end

  return verify_beach32_cksum(hrp, d)
end


rspamd_config:register_symbol{
  name = 'BITCOIN_ADDR',
  description = 'Message has a valid bitcoin wallet address',
  callback = function(task)
    local rspamd_re = require "rspamd_regexp"

    local btc_wallet_re = rspamd_re.create_cached('^[13LM][1-9A-Za-z]{25,34}$')
    local segwit_wallet_re = rspamd_re.create_cached('^[b][c]1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{14,74}$', 'i')
    local words_matched = {}
    local segwit_words_matched = {}
    local valid_wallets = {}

    for _,part in ipairs(task:get_text_parts() or {}) do
      local pw = part:filter_words(btc_wallet_re, 'raw', 3)

      if pw and #pw > 0 then
        for _,w in ipairs(pw) do
          words_matched[#words_matched + 1] = w
        end
      end

      pw = part:filter_words(segwit_wallet_re, 'raw', 3)
      if pw and #pw > 0 then
        for _,w in ipairs(pw) do
          segwit_words_matched[#segwit_words_matched + 1] = w
        end
      end
    end

    for _,word in ipairs(words_matched) do
      local valid = is_traditional_btc_address(word)
      if valid then
        valid_wallets[#valid_wallets + 1] = word
      end
    end
    for _,word in ipairs(segwit_words_matched) do
      local valid = is_segwit_bech32_address(word)
      if valid then
        valid_wallets[#valid_wallets + 1] = word
      end
    end

    if #valid_wallets > 0 then
      return true,1.0,valid_wallets
    end
  end,
  score = 0.0,
  group = 'scams'
}