local util = require 'lua_util'

local settings = {
    prefix = 'prefix',
    encrypt = true,
    publickey = 'public_key'
}

context("Lua util - maybe encode/decode header", function()
    test("Encode/Decode header", function()
        local header = 'X-Spamd-Result'

        local encoded_header = util.maybe_encode_header(header, settings, settings.prefix)
        local decoded_header = util.maybe_decode_header(encoded_header. settings. settings.prefix)

        if header ~= decoded_header then
            assert_true(false, 'Failed to confirm equality of original header and decoded one')
        else
            assert_true(true, 'Succeed to confirm equality of original header and decoded header')
        end
    end)
end)