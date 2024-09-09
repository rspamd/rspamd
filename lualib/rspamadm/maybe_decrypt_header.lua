local util = require 'lua_util'

return function(_, res)
    local settings = {
        prefix = 'dec',
        dec_encrypt = true,
        dec_key = res['key']
    }

    local encrypted_header = res['encrypted_header']
    local nonce = res['nonce']

    local decrypted_header = util.maybe_decrypt_header(encrypted_header, settings, settings.prefix, nonce)
    if decrypted_header ~= nil then
        print(string.format(
                'Decryption is successful. Decrypted header: %s',
                decrypted_header
        ))
    end
end