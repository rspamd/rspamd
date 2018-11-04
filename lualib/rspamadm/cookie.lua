--[[
Copyright (c) 2018, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

local argparse = require "argparse"


-- Define command line options
local parser = argparse()
    :name "rspamadm cookie"
    :description "Produces cookies or message ids"
    :help_description_margin(30)

parser:mutex(
    parser:option "-k --key"
          :description('Key to load')
          :argname "<32hex>",
    parser:flag "-K --new-key"
          :description('Generates a new key')
)

parser:option "-d --domain"
      :description('Use specified domain and generate full message id')
      :argname "<domain>"
parser:flag "-D --decrypt"
      :description('Decrypt cookie instead of encrypting one')
parser:flag "-t --timestamp"
      :description('Show cookie timestamp (valid for decrypting only)')
parser:argument "cookie":args "?"
      :description('Use specified cookie')

local function gen_cookie(args, key)
  local cr = require "rspamd_cryptobox"

  if not args.cookie then return end

  local function encrypt()
    if #args.cookie > 31 then
      print('cookie too long (>31 characters), cannot encrypt')
      os.exit(1)
    end

    local enc_cookie = cr.encrypt_cookie(key, args.cookie)
    if args.domain then
      print(string.format('<%s@%s>', enc_cookie, args.domain))
    else
      print(enc_cookie)
    end
  end

  local function decrypt()
    local extracted_cookie = args.cookie:match('^%<?([^@]+)@.*$')
    if not extracted_cookie then
      -- Assume full message id as a cookie
      extracted_cookie = args.cookie
    end

    local dec_cookie,ts = cr.decrypt_cookie(key, extracted_cookie)

    if dec_cookie then
      if args.timestamp then
        print(string.format('%s %s', dec_cookie, ts))
      else
        print(dec_cookie)
      end
    else
      print('cannot decrypt cookie')
      os.exit(1)
    end
    end

  if args.decrypt then
    decrypt()
  else
    encrypt()
  end
end

local function handler(args)
  local res = parser:parse(args)

  if not (res.key or res['new_key']) then
    parser:error('--key or --new-key must be specified')
  end

  if res.key then
    local pattern = {'^'}
    for i=1,32 do pattern[i + 1] = '[a-zA-Z0-9]' end
    pattern[34] = '$'

    if not res.key:match(table.concat(pattern, '')) then
      parser:error('invalid key: ' .. res.key)
    end

    gen_cookie(res, res.key)
  else
    local util = require "rspamd_util"
    local key = util.random_hex(32)

    print(key)
    gen_cookie(res, res.key)
  end
end

return {
  handler = handler,
  description = parser._description,
  name = 'cookie'
}