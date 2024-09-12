local util = require 'lua_util'
local argparse = require 'argparse'

local parser = argparse()
    :name "rspamadm decrypt header"
    :description "Decrypt given header with given key and nonce"
    :help_description_margin(32)

parser:option "-H --header"
      :description("Encrypted header")
      :argname("<header>")
parser:option "-k --key"
      :description("Key used to encrypt header")
      :argname("<key>")
parser:option "-n --nonce"
      :description("Nonce used to encrypt header")
      :argname("<nonce>")

local function handler(args)
    local opts = parser:parse(args)
    local settings = {
        prefix = 'dec',
        dec_encrypt = true,
        dec_key = opts.key
    }

    local encrypted_header = opts.header
    local nonce = opts.nonce

    local decrypted_header = util.maybe_decrypt_header(encrypted_header, settings, settings.prefix, nonce)
    if decrypted_header ~= nil then
        print(string.format(
                'The decryption was successful. The decrypted header: %s',
                decrypted_header
        ))
    else
        print('The decryption failed. Please check the correctness of the arguments given.')
    end
end

return {
    name = 'decrypt_header',
    aliases = { 'decrypt_header', 'decryptheader' },
    handler = handler,
    description = parser._description
}