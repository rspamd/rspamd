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
local off = 0
local base58_dec = fun.tomap(fun.map(
    function(c)
      off = off + 1
      return c,(off - 1)
    end,
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"))

rspamd_config:register_symbol{
  name = 'BITCOIN_ADDR',
  description = 'Message has a valid bitcoin wallet address',
  callback = function(task)
    local rspamd_re = require "rspamd_regexp"
    local hash = require "rspamd_cryptobox_hash"

    local wallet_re = rspamd_re.create_cached('^[13][1-9A-Za-z]{25,34}$')
    local words_matched = {}
    local valid_wallets = {}

    for _,part in ipairs(task:get_text_parts() or {}) do
      local pw = part:filter_words(wallet_re, 'raw', 3)

      if pw and #pw > 0 then
        for _,w in ipairs(pw) do
          words_matched[#words_matched + 1] = w
        end
      end
    end

    for _,word in ipairs(words_matched) do
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