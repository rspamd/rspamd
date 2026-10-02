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

-- Cryptocurrency wallet address filter rules.
--
-- Matching and validation live in `lua_crypto_addresses`, which scans a message
-- at most once and memoises the result on the task. Both the symbols below and
-- the `crypto_addresses` selector go through it, so:
--
--  * a message is never scanned twice, however many consumers ask;
--  * a message nobody asks about is never scanned at all;
--  * the selector needs no dependency on this symbol, because it computes the
--    addresses itself rather than reading a symbol's results.

local lua_crypto_addresses = require "lua_crypto_addresses"

-- One entry per currency `lua_crypto_addresses.classify` can return. The
-- registration order is taken from the library's `currencies` list so that the
-- symbols and the selector cannot drift apart.
local wallet_checks = {
  bitcoin = { symbol = 'BITCOIN_ADDR',
    description = 'Message has a valid Bitcoin (or Bitcoin Cash) wallet address' },
  litecoin = { symbol = 'LITECOIN_ADDR',
    description = 'Message has a valid Litecoin wallet address' },
  dogecoin = { symbol = 'DOGECOIN_ADDR',
    description = 'Message has a valid Dogecoin wallet address' },
  tron = { symbol = 'TRON_ADDR',
    description = 'Message has a valid Tron (TRX / TRC-20) wallet address' },
  xrp = { symbol = 'XRP_ADDR',
    description = 'Message has a valid XRP/Ripple wallet address' },
  zcash = { symbol = 'ZCASH_ADDR',
    description = 'Message has a valid Zcash transparent wallet address' },
  cardano = { symbol = 'CARDANO_ADDR',
    description = 'Message has a valid Cardano wallet address' },
  cosmos = { symbol = 'COSMOS_ADDR',
    description = 'Message has a valid Cosmos wallet address' },
  stellar = { symbol = 'STELLAR_ADDR',
    description = 'Message has a valid Stellar (XLM) wallet address' },
  ton = { symbol = 'TON_ADDR',
    description = 'Message has a valid TON wallet address' },
  ethereum = { symbol = 'ETHEREUM_ADDR_MAYBE',
    description = 'Message has a possible Ethereum or other EVM chain (BSC, Polygon, ' ..
        'Arbitrum, ...) wallet address (format-only: 0x + 40 hex chars; EIP-55 checksum ' ..
        'not verified)' },
  monero = { symbol = 'MONERO_ADDR_MAYBE',
    description = 'Message has a possible Monero wallet address ' ..
        '(format-only: 95-char Base58 starting with 4; Keccak-256 checksum not verified)' },
}

local function check_crypto_addresses(task)
  local found = lua_crypto_addresses.get_addresses(task)
  local combined_opts = {}

  for _, currency in ipairs(lua_crypto_addresses.currencies) do
    local addresses = found[currency]

    if addresses and #addresses > 0 then
      task:insert_result(wallet_checks[currency].symbol, 1.0, addresses)

      for _, addr in ipairs(addresses) do
        combined_opts[#combined_opts + 1] = currency .. ':' .. addr
      end
    end
  end

  if #combined_opts > 0 then
    task:insert_result('CRYPTO_ADDR_CHECK', 1.0, combined_opts)
  end
end

local crypto_id = rspamd_config:register_symbol({
  name = 'CRYPTO_ADDR_CHECK',
  type = 'normal',
  callback = check_crypto_addresses,
  score = 0.0,
  flags = 'empty,nostat',
  group = 'scams',
  description = 'Message contains cryptocurrency wallet address(es); ' ..
      'options are "type:address" pairs, e.g. "monero:xxxxx"',
})

-- Registration walks the ordered list rather than `pairs(wallet_checks)`, so
-- symbol ids stay stable between runs instead of churning the symbol cache
for _, currency in ipairs(lua_crypto_addresses.currencies) do
  local chk = wallet_checks[currency]

  rspamd_config:register_symbol({
    name = chk.symbol,
    parent = crypto_id,
    type = 'virtual',
    score = 0.0,
    one_shot = true,
    group = 'scams',
    description = chk.description,
  })
end

-- The matching `crypto_addresses` selector lives in lua_selectors/extractors.lua
-- so that it is available regardless of whether these rules loaded before the
-- plugin configs that use it. It computes the addresses itself, so consumers
-- never need a dependency on CRYPTO_ADDR_CHECK and keep working even under a
-- settings profile that does not enable it:
--
--   crypto_addresses()                 -> {"1...", "4..."}   bare, for maps/DNS
--   crypto_addresses('monero')         -> {"4..."}
--   crypto_addresses('', 'typed')      -> {"bitcoin:1...", "monero:4..."}
