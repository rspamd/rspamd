-- Test rsa signing

context("RSA signature verification test", function()
  local rsa_privkey = require "rspamd_rsa_privkey"
  local rsa_pubkey = require "rspamd_rsa_pubkey"
  local rsa_signature = require "rspamd_rsa_signature"
  local rsa = require "rspamd_rsa"
  local hash = require "rspamd_cryptobox_hash"
  local pubkey = 'testkey.pub'
  local privkey = 'testkey.sec'
  local data = 'test.data'
  local signature = 'test.sig'
  local test_dir = string.gsub(debug.getinfo(1).source, "^@(.+/)[^/]+$", "%1")
  local rsa_key, rsa_sig

  test("RSA sign", function()
    -- Signing test
    rsa_key = rsa_privkey.load_file(string.format('%s/%s', test_dir, privkey))
    assert_not_nil(rsa_key)

    local h = hash.create_specific('sha256')
    local d = io.open(string.format('%s/%s', test_dir, data), "rb"):read "*a"
    h:update(d)
    local sig = rsa.sign_memory(rsa_key, h:bin())
    assert_not_nil(sig)
    sig:save(string.format('%s/%s', test_dir, signature), true)
  end)

  test("RSA verify", function()
    -- Verifying test
    local h = hash.create_specific('sha256')
    local d = io.open(string.format('%s/%s', test_dir, data), "rb"):read "*a"
    h:update(d)
    rsa_key = rsa_pubkey.load(string.format('%s/%s', test_dir, pubkey))
    assert_not_nil(rsa_key)
    rsa_sig = rsa_signature.load(string.format('%s/%s', test_dir, signature))
    assert_not_nil(rsa_sig)
    assert_true(rsa.verify_memory(rsa_key, rsa_sig, h:bin()))
  end)
end)
