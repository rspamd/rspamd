--[[
Copyright (c) 2011-2016, Vsevolod Stakhov <vsevolod@highsecure.ru>

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


local reconf = config['regexp']

reconf['HTML_META_REFRESH_URL'] = {
  -- Requires options { check_attachements = true; }
  re = '/<meta\\s+http-equiv="refresh"\\s+content="\\d+\\s*;\\s*url=/{sa_raw_body}i',
  description = "Has HTML Meta refresh URL",
  score = 5.0,
  one_shot = true,
  group = 'HTML'
}

reconf['HAS_DATA_URI'] = {
  -- Requires options { check_attachements = true; }
  re = '/data:[^\\/]+\\/[^; ]+;base64,/{sa_raw_body}i',
  description = "Has Data URI encoding",
  group = 'HTML',
  one_shot = true,
}

reconf['DATA_URI_OBFU'] = {
  -- Requires options { check_attachements = true; }
  re = '/data:text\\/(?:plain|html);base64,/{sa_raw_body}i',
  description = "Uses Data URI encoding to obfuscate plain or HTML in base64",
  group = 'HTML',
  one_shot = true,
  score = 2.0
}

reconf['INTRODUCTION'] = {
  re = '/\\b(?:my name is\\b|(?:i am|this is)\\s+(?:mr|mrs|ms|miss|master|sir|prof(?:essor)?|d(?:octo)?r|rev(?:erend)?)(?:\\.|\\b))/{sa_body}i',
  description = "Sender introduces themselves",
  score = 2.0,
  one_shot = true,
  group = 'scams'
}

-- Message contains a link to a .onion URI (Tor hidden service)
local onion_uri_v2 = '/[a-z0-9]{16}\\.onion?/{url}i'
local onion_uri_v3 = '/[a-z0-9]{56}\\.onion?/{url}i'
reconf['HAS_ONION_URI'] = {
    re = string.format('(%s | %s)', onion_uri_v2, onion_uri_v3),
    description = 'Contains .onion hidden service URI',
    score = 0.0,
    group = 'experimental'
}

local my_victim = [[/(?:victim|prey)/{words}]]
local your_webcam = [[/webcam/{words}]]
local your_onan = [[/(?:mast[ur]{2}bati(?:on|ng)|onanism|solitary)/{words}]]
local password_in_words = [[/^pass(?:(?:word)|(?:phrase))$/i{words}]]
local btc_wallet_address = [[/^[13][1-9a-km-zA-HJ-NP-Z]{25,34}$/]]
local wallet_word = [[/^wallet$/{words}]]
local broken_unicode = [[has_flag(bad_unicode)]]

reconf['LEAKED_PASSWORD_SCAM'] = {
  re = string.format('%s{words} & (%s | %s | %s | %s | %s | %s | lua:check_data_images)',
      btc_wallet_address, password_in_words, wallet_word,
      my_victim, your_webcam, your_onan, broken_unicode),
  description = 'Contains password word and BTC wallet address',
  functions = {
    check_data_images = function(task)
      local tp = task:get_text_parts() or {}

      for _,p in ipairs(tp) do
        if p:is_html() then
          local hc = p:get_html()

          if hc and hc:has_property('data_urls') then
            return true
          end
        end
      end

      return false
    end
  },
  score = 7.0,
  group = 'scams'
}

-- Special routine to validate bitcoin wallets
-- Prepare base58 alphabet
local fun = require "fun"
local off = 0
local base58_dec = fun.tomap(fun.map(
    function(c)
      off = off + 1
      return c,(off - 1)
    end,
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"))

local id = rspamd_config:register_symbol{
  name = 'LEAKED_PASSWORD_SCAM_VALIDATED',
  callback = function(task)
    local rspamd_re = require "rspamd_regexp"
    local hash = require "rspamd_cryptobox_hash"

    if task:has_symbol('LEAKED_PASSWORD_SCAM') then
      -- Perform BTC wallet check (quite expensive)
      local wallet_re = rspamd_re.create_cached(btc_wallet_address)
      local seen_valid = false
      for _,tp in ipairs(task:get_text_parts()) do

        local words = tp:get_words('raw') or {}

        for _,word in ipairs(words) do
          if wallet_re:match(word) then
            -- We have something that looks like a BTC address
            local bytes = {}
            for i=1,25 do bytes[i] = 0 end
            -- Base58 decode loop
            fun.each(function(ch)
              local acc = base58_dec[ch] or 0
              for i=25,1,-1 do
                acc = acc + (58 * bytes[i]);
                bytes[i] = math.fmod(acc, 256);
                acc = math.modf(acc / 256);
              end
            end, fun.tail(word)) -- Tail due to first byte is version
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
              task:insert_result('LEAKED_PASSWORD_SCAM_VALIDATED', 1.0, word)
              seen_valid = true
            end
          end
        end
      end

      if not seen_valid then
        task:insert_result('LEAKED_PASSWORD_SCAM_INVALID', 1.0)
      end
    end
  end,
  score = 0.0,
  group = 'scams'
}

rspamd_config:register_symbol{
  type = 'virtual',
  name = 'LEAKED_PASSWORD_SCAM_INVALID',
  parent = id,
  score = 0.0,
}

rspamd_config:register_dependency('LEAKED_PASSWORD_SCAM_VALIDATED',
    'LEAKED_PASSWORD_SCAM')