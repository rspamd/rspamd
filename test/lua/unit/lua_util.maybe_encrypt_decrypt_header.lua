local util = require 'lua_util'

context("Lua util - maybe encrypt/decrypt header", function()
    test("Encrypt/Decrypt header with nonce", function()
        local header = 'X-Spamd-Result'
        local settings = {
            prefix = 'prefix',
            prefix_encrypt = true,
            prefix_key = 'key',
            prefix_nonce = 'nonce'
        }

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

    test("Encrypt/Decrypt header without nonce", function()
        local header = 'X-Spamd-Result'
        local settings = {
            prefix = 'prefix',
            prefix_encrypt = true,
            prefix_key = 'key'
        }

        local encrypted_header, nonce = util.maybe_encrypt_header(header, settings, settings.prefix)
        if encrypted_header == header or encrypted_header == nil then
            assert_true(false, 'Failed to encrypt header')
        end

        local decrypted_header = util.maybe_decrypt_header(encrypted_header, settings,
                settings.prefix, nonce)
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