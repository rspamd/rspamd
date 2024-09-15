local util = require 'lua_util'
local rspamd_util = require 'rspamd_util'
local argparse = require 'argparse'

local parser = argparse()
    :name "rspamadm encrypt/decrypt text"
    :description "Encrypt/Decrypt given text with given key and nonce"
    :help_description_margin(32)
    :command_target('command')
    :require_command(true)

local decrypt = parser:command 'decrypt'
                      :description 'Decrypt text with given key and nonce'

decrypt:option "-t --text"
      :description("Encrypted text(Base 64)")
      :argname("<text>")
decrypt:option "-k --key"
      :description("Key used to encrypt text")
      :argname("<key>")
decrypt:option "-n --nonce"
      :description("Nonce used to encrypt text(Base 64)")
      :argname("<nonce>")

local encrypt = parser:command 'encrypt'
                      :description 'Encrypt text with given key'

encrypt:option "-t --text"
      :description("Text to encrypt")
      :argname("<text>")
encrypt:option "-k --key"
      :description("Key to encrypt text")
      :argname("<key>")
encrypt:option "-n --nonce"
       :description("Nonce to encrypt text(Base 64)")
       :argname("<nonce>")

local function decryption_handler(args)
    local settings = {
        prefix = 'dec',
        dec_encrypt = true,
        dec_key = args.key
    }

    local decrypted_header = util.maybe_decrypt_header(rspamd_util.decode_base64(args.text), settings, settings.prefix,
            rspamd_util.decode_base64(args.nonce))
    if decrypted_header ~= nil then
        print(string.format(
                'The decryption was successful. The decrypted text: %s',
                decrypted_header
        ))
    else
        print('The decryption failed. Please check the correctness of the arguments given.')
    end
end

local function encryption_handler(args)
    local settings = {
        prefix = 'dec',
        dec_encrypt = true,
        dec_key = args.key,
        dec_nonce = rspamd_util.decode_base64(args.nonce)
    }

    local encrypted_text, nonce = util.maybe_encrypt_header(args.text, settings, settings.prefix)
    if encrypted_text ~= nil then
        print(string.format(
                'The encryption was successful. The encrypted text: %s The nonce: %s',
                rspamd_util.encode_base64(encrypted_text), rspamd_util.encode_base64(nonce)
        ))
    else
        print('The encryption failed. Please check the correctness of the arguments given.')
    end
end

local command_handlers = {
    decrypt = decryption_handler,
    encrypt = encryption_handler,
}

local function handler(args)
    local cmd_opts = parser:parse(args)

    local f = command_handlers[cmd_opts.command]
    if not f then
        parser:error(string.format("command isn't implemented: %s",
                cmd_opts.command))
    end
    f(cmd_opts)
end


return {
    name = 'secretbox',
    aliases = { 'secretbox', 'secret_box' },
    handler = handler,
    description = parser._description
}