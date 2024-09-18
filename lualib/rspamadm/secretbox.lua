local util = require 'lua_util'
local rspamd_util = require 'rspamd_util'
local argparse = require 'argparse'

local parser = argparse()
    :name "secretbox"
    :description "Encrypt/decrypt given text with given key and nonce"
    :help_description_margin(32)
    :command_target('command')
    :require_command(true)

parser:mutex(
    parser:flag '-R --raw'
          :description('Encrypted text(and nonce if it is there) will be given in raw'),
    parser:flag '-H --hex'
          :description('Encrypted text(and nonce if it is there) will be given in hex'),
    parser:flag '-b --base32'
          :description('Encrypted text(and nonce if it is there) will be given in base32'),
    parser:flag '-B --base64'
          :description('Encrypted text(and nonce if it is there) will be given in base64')
)

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
       :default(nil)

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
       :default(nil)

local function set_up_encoding(args, type, text)
    local function fromhex(str)
        return (str:gsub('..', function (cc)
            return string.char(tonumber(cc, 16))
        end))
    end

    local function tohex(str)
        return (str:gsub('.', function (c)
            return string.format('%02X', string.byte(c))
        end))
    end

    local output = text

    if type == 'encode' then
        if args.hex then
            output = tohex(text)
        elseif args.base32 then
            output = rspamd_util.encode_base32(text)
        elseif args.base64 then
            output = rspamd_util.encode_base64(text)
        end
    elseif type == 'decode' then
        if args.hex then
            output = fromhex(text)
        elseif args.base32 then
            output = rspamd_util.decode_base32(text)
        elseif args.base64 then
            output = rspamd_util.decode_base64(text)
        end
    end

    return output
end

local function decryption_handler(args)
    local settings = {
        prefix = 'dec',
        dec_encrypt = true,
        dec_key = args.key
    }

    local decrypted_header = ''
    if(args.nonce ~= nil) then
        local decoded_text = set_up_encoding(args, 'decode', tostring(args.text))
        local decoded_nonce = set_up_encoding(args, 'decode', tostring(args.nonce))

        decrypted_header = util.maybe_decrypt_header(decoded_text, settings, settings.prefix, decoded_nonce)
    else
        local text_with_nonce = set_up_encoding(args, 'decode', tostring(args.text))
        local nonce = string.sub(tostring(text_with_nonce), 1, 24)
        local text = string.sub(tostring(text_with_nonce), 25)

        decrypted_header = util.maybe_decrypt_header(text, settings, settings.prefix, nonce)
    end

    if decrypted_header ~= nil then
        print(decrypted_header)
    else
        print('The decryption failed. Please check the correctness of the arguments given.')
    end
end

local function encryption_handler(args)
    local settings = {
        prefix = 'dec',
        dec_encrypt = true,
        dec_key = args.key,
    }

    if args.nonce ~= nil then
        settings.dec_nonce = set_up_encoding(args, 'decode', tostring(args.nonce))
    end

    local encrypted_text = util.maybe_encrypt_header(args.text, settings, settings.prefix)

    if encrypted_text ~= nil then
        print(set_up_encoding(args, 'encode', tostring(encrypted_text)))
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
    name = 'secret_box',
    aliases = { 'secretbox', 'secret_box' },
    handler = handler,
    description = parser._description
}