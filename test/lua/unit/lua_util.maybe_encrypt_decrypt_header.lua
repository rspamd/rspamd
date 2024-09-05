local util = require 'lua_util'

context("Lua util - maybe encrypt/decrypt header", function()
    test("Encrypt/Decrypt header with nonce", function()
        local header = tostring('X-Spamd-Result')
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

        if tostring(header) == tostring(decrypted_header) then
            assert_true(true, 'Succeed to confirm equality of original header and decrypted header')
        else
            assert_rspamd_table_eq_sorted({actual = { decrypted_header },
                                           expect = { header }})
        end
    end)

    test("Encrypt/Decrypt header without nonce", function()
        local header = tostring('X-Spamd-Result')
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

        if tostring(header) == tostring(decrypted_header) then
            assert_true(true, 'Succeed to confirm equality of original header and decrypted header')
        else
            assert_rspamd_table_eq_sorted({actual = { decrypted_header },
                                           expect = { header }})
        end
    end)
end)