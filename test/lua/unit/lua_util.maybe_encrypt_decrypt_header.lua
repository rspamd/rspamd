local util = require 'lua_util'

local settings = {
    prefix = 'prefix',
    prefix_encrypt = true,
    prefix_key = 'key'
}

context("Lua util - maybe encrypt/decrypt header", function()
    test("Encrypt/Decrypt header", function()
        local header = 'X-Spamd-Result'

        local encrypted_header = util.maybe_encrypt_header(header, settings, settings.prefix)
        if encrypted_header == header or encrypted_header == nil then
            assert_true(false, 'Failed to encrypt header')
        end

        local decrypted_header = util.maybe_decrypt_header(encrypted_header, settings, settings.prefix)
        if decrypted_header == encrypted_header or decrypted_header == nil then
            assert_true(false, 'Failed to decrypt header')
        end

        if header ~= decrypted_header then
            assert_true(false, 'Failed to confirm equality of original header and decrypted one')
        else
            assert_true(true, 'Succeed to confirm equality of original header and decrypted header')
        end
    end)
end)