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
local lua_util = require "lua_util"
local rspamd_util = require "rspamd_util"
local N = "bitcoin"

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


local function gen_bleach32_table(input)
  local d = {}
  local i = 1
  local res = true
  local charset = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'

  fun.each(function(byte)
    if res then
      local pos = charset:find(byte, 1, true)
      if not pos then
        res = false
      else
        d[i] = pos - 1
        i = i + 1
      end
    end
  end, fun.iter(input))

  return res and d or nil
end

local function is_segwit_bech32_address(task, word)
  local semicolon_pos = string.find(word, ':')
  local address_part = word
  if semicolon_pos then
    address_part = string.sub(word, semicolon_pos + 1)
  end

  local prefix = address_part:sub(1, 3)

  if prefix == 'bc1' or prefix:sub(1, 1) == '1' or prefix:sub(1, 1) == '3' then
    -- Strip beach32 prefix in bitcoin
    address_part = address_part:lower()
    local last_one_pos = address_part:find('1[^1]*$')
    if not last_one_pos or (last_one_pos < 1 or last_one_pos + 7 > #address_part) then
      return false
    end
    local hrp = address_part:sub(1, last_one_pos - 1)
    local addr = address_part:sub(last_one_pos + 1, -1)
    local decoded = gen_bleach32_table(addr)

    if decoded then
      return verify_beach32_cksum(hrp, decoded)
    end
  else
    -- Bitcoin cash address
    -- https://www.bitcoincash.org/spec/cashaddr.html
    local decoded = gen_bleach32_table(address_part)
    lua_util.debugm(N, task, 'check %s, %s decoded', word, decoded)

    if decoded and #decoded > 8 then
      if semicolon_pos then
        prefix = word:sub(1, semicolon_pos - 1)
      else
        prefix = 'bitcoincash'
      end

      local polymod_tbl = {}
      fun.each(function(byte)
        local b = bit.band(string.byte(byte), 0x1f)
        table.insert(polymod_tbl, b)
      end, fun.iter(prefix))

      -- For semicolon
      table.insert(polymod_tbl, 0)

      fun.each(function(byte) table.insert(polymod_tbl, byte) end, decoded)
      lua_util.debugm(N, task, 'final polymod table: %s', polymod_tbl)

      return rspamd_util.btc_polymod(polymod_tbl)
    end
  end
end

local normal_wallet_re = [[/\b[13LM][1-9A-Za-z]{25,34}\b/AL{sa_body}]]
local btc_bleach_re = [[/\b(?:(?:[a-zA-Z]\w+:)|(?:bc1))?[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{14,}\b/AL{sa_body}]]

config.regexp['BITCOIN_ADDR'] = {
  description = 'Message has a valid bitcoin wallet address',
  -- Use + operator to ensure that each expression is always evaluated
  re = string.format('(%s) + (%s) > 0', normal_wallet_re, btc_bleach_re),
  re_conditions = {
    [normal_wallet_re] = function(task, txt, s, e)
      local len = e - s
      if len <= 2 or len > 1024 then
        return false
      end

      local word = lua_util.str_trim(txt:sub(s + 1, e))
      local valid = is_traditional_btc_address(word)

      if valid then
        -- To save option
        task:insert_result('BITCOIN_ADDR', 1.0, word)
        lua_util.debugm(N, task, 'found valid traditional bitcoin addr in the word: %s',
            word)
        return true
      else
        lua_util.debugm(N, task, 'found invalid bitcoin addr in the word: %s',
            word)

        return false
      end
    end,
    [btc_bleach_re] = function(task, txt, s, e)
      local len = e - s
      if len <= 2 or len > 1024 then
        return false
      end

      local word = tostring(lua_util.str_trim(txt:sub(s + 1, e)))
      local valid = is_segwit_bech32_address(task, word)

      if valid then
        -- To save option
        task:insert_result('BITCOIN_ADDR', 1.0, word)
        lua_util.debugm(N, task, 'found valid bleach bitcoin addr in the word: %s',
            word)
        return true
      else
        lua_util.debugm(N, task, 'found invalid bitcoin addr in the word: %s',
            word)

        return false
      end
    end,
  },
  score = 0.0,
  one_shot = true,
  group = 'scams',
}
