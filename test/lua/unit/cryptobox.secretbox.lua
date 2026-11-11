local secretbox = require 'rspamd_cryptobox_secretbox'

context("Cryptobox - secretbox", function()

  local key = 'test key'
  local msg = 'plain text to protect'
  local short_nonce = '\017'
  local padded_nonce = '\017' .. string.rep('\000', 23)

  test('Short nonce is zero-padded to full nonce length', function()
    local box = secretbox.create(key)

    local ct_short = box:encrypt(msg, short_nonce)
    local ct_padded = box:encrypt(msg, padded_nonce)

    assert_equal(tostring(ct_short), tostring(ct_padded))
  end)

  test('Round-trip with short nonce', function()
    local box = secretbox.create(key)

    local ct = box:encrypt(msg, short_nonce)
    local ok, pt = box:decrypt(ct, short_nonce)

    assert_true(ok)
    assert_equal(tostring(pt), msg)
  end)

  test('Encrypt with short nonce, decrypt with padded and vice versa', function()
    local box = secretbox.create(key)

    local ok, pt = box:decrypt(box:encrypt(msg, short_nonce), padded_nonce)
    assert_true(ok)
    assert_equal(tostring(pt), msg)

    ok, pt = box:decrypt(box:encrypt(msg, padded_nonce), short_nonce)
    assert_true(ok)
    assert_equal(tostring(pt), msg)
  end)

  test('Round-trip with full-length nonce', function()
    local box = secretbox.create(key)
    local nonce = string.rep('\001', 24)

    local ct = box:encrypt(msg, nonce)
    local ok, pt = box:decrypt(ct, nonce)

    assert_true(ok)
    assert_equal(tostring(pt), msg)
  end)

  test('Wrong nonce fails authentication', function()
    local box = secretbox.create(key)

    local ct = box:encrypt(msg, short_nonce)
    local ok = box:decrypt(ct, '\018')

    assert_false(ok)
  end)

  test('Generated random nonce round-trips', function()
    local box = secretbox.create(key)

    local ct, nonce = box:encrypt(msg)
    assert_not_nil(nonce)

    local ok, pt = box:decrypt(ct, nonce)
    assert_true(ok)
    assert_equal(tostring(pt), msg)
  end)

end)
