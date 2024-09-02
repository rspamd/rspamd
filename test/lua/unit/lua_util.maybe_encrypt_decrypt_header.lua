local util = require 'lua_util'

local settings = {
    prefix = 'prefix',
    encrypt = true,
    key = 'key'
}

context("Lua util - maybe encrypt/decrypt header", function()
    test("Encrypt/Decrypt header", function()
        local header = 'X-Spamd-Result'

        local encoded_header = util.maybe_encrypt_header(header, settings, settings.prefix)
        if encoded_header == header then
            assert_true(false, 'Failed to encode header')
        end
        local decoded_header = util.maybe_decrypt_header(encoded_header, settings, settings.prefix)

        if header ~= decoded_header then
            assert_true(false, 'Failed to confirm equality of original header and decoded one')
        else
            assert_true(true, 'Succeed to confirm equality of original header and decoded header')
        end
    end)
end)