--[[
Copyright (c) 2023, Vsevolod Stakhov <vsevolod@rspamd.com>

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
local rspamd_util = require "rspamd_util"
local rspamd_cryptobox = require "rspamd_cryptobox"

local parser = argparse()
    :name 'rspamadm dkim_keygen'
    :description 'Create key pairs for dkim signing'
    :help_description_margin(30)
parser:option '-d --domain'
      :description 'Create a key for a specific domain'
      :default "example.com"
parser:option '-s --selector'
      :description 'Create a key for a specific DKIM selector'
      :default "mail"
parser:option '-k --privkey'
      :description 'Save private key to file instead of printing it to stdout'
parser:option '-b --bits'
      :convert(function(input)
        local n = tonumber(input)
        if not n or n < 512 or n > 4096 then
          return nil
        end
        return n
      end)
      :description 'Generate an RSA key with the specified number of bits (512 to 4096)'
      :default(1024)
parser:option '-t --type'
      :description 'Key type: RSA, ED25519 or ED25119-seed'
      :convert {
        ['rsa'] = 'rsa',
        ['RSA'] = 'rsa',
        ['ed25519'] = 'ed25519',
        ['ED25519'] = 'ed25519',
        ['ed25519-seed'] = 'ed25519-seed',
        ['ED25519-seed'] = 'ed25519-seed',
      }
      :default 'rsa'
parser:option '-o --output'
      :description 'Output public key in the following format: dns, dnskey or plain'
      :convert {
        ['dns'] = 'dns',
        ['plain'] = 'plain',
        ['dnskey'] = 'dnskey',
      }
      :default 'dns'
parser:option '--priv-output'
      :description 'Output private key in the following format: PEM or DER (for RSA)'
      :convert {
        ['pem'] = 'pem',
        ['der'] = 'der',
      }
      :default 'pem'
parser:flag '-f --force'
      :description 'Force overwrite of existing files'

local function split_string(input, max_length)
  max_length = max_length or 253
  local pieces = {}
  local index = 1

  while index <= #input do
    local piece = input:sub(index, index + max_length - 1)
    table.insert(pieces, piece)
    index = index + max_length
  end

  return pieces
end


local function print_public_key_dns(opts, base64_pk)
  local key_type = opts.type == 'rsa' and 'rsa' or 'ed25519'
  if #base64_pk < 255 - 2 then
    io.write(string.format('%s._domainkey IN TXT ( "v=DKIM1; k=%s;" \n\t"p=%s" ) ;\n', opts.selector, key_type, base64_pk))
  else
    -- Split it  by parts
    local parts = split_string(base64_pk)
    io.write(string.format('%s._domainkey IN TXT ( "v=DKIM1; k=%s; "\n', opts.selector, key_type))
    for i,part in ipairs(parts) do
      if i == 1 then
        io.write(string.format('\t"p=%s"\n', part))
      else
        io.write(string.format('\t"%s"\n', part))
      end
    end
    io.write(") ; \n")
  end

end

local function print_public_key(opts, pk)
  local key_type = opts.type == 'rsa' and 'rsa' or 'ed25519'
  local base64_pk = tostring(rspamd_util.encode_base64(pk))
  if opts.output == 'plain' then
    io.write(base64_pk)
    io.write("\n")
  elseif opts.output == 'dns' then
    print_public_key_dns(opts, base64_pk)
  elseif opts.output == 'dnskey' then
    io.write(string.format('v=DKIM1; k=%s; p=%s\n', key_type, base64_pk))
  end
end

local function gen_rsa_key(opts)
  local rsa = require "rspamd_rsa"

  local sk,pk = rsa.keypair(opts.bits or 1024)
  if opts.privkey then
    if opts.force then
      os.remove(opts.privkey)
    end
    sk:save(opts.privkey, opts.priv_output)
  else
    sk:save("-", opts.priv_output)
  end

  print_public_key(opts, tostring(pk))
end

local function gen_eddsa_key(opts)
  local sk,pk = rspamd_cryptobox.gen_dkim_keypair(opts.type)

  if opts.privkey and opts.force then
    os.remove(opts.privkey)
  end
  if not sk:save_in_file(opts.privkey, tonumber('0600', 8)) then
    io.stderr:write('cannot save private key to ' .. (opts.privkey or 'stdout') .. '\n')
    os.exit(1)
  end

  if not opts.privkey then
    io.write("\n")
    io.flush()
  end

  print_public_key(opts, tostring(pk))
end

local function handler(args)
  local opts = parser:parse(args)

  if not opts then os.exit(1) end

  if opts.type == 'rsa' then
    gen_rsa_key(opts)
  else
    gen_eddsa_key(opts)
  end
end

return {
  name = 'dkim_keygen',
  aliases = {'dkimkeygen'},
  handler = handler,
  description = parser._description
}


