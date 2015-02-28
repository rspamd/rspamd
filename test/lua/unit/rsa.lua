-- Test rsa signing

context("RSA signature verification test", function()
  local rsa_privkey = require "rspamd_rsa_privkey"
  local rsa_pubkey = require "rspamd_rsa_pubkey"
  local rsa_signature = require "rspamd_rsa_signature"
  local rsa = require "rspamd_rsa"
  local pubkey = 'testkey.pub'
  local privkey = 'testkey'
  local data = 'test.data'
  local signature = 'test.sig'
  local test_dir = string.gsub(debug.getinfo(1).source, "^@(.+/)[^/]+$", "%1")
  local rsa_key, rsa_sig
  
  test("RSA sign", function()
    -- Signing test
    local rsa_key = rsa_privkey.load(string.format('%s/%s', test_dir, privkey))
    assert_not_nil(rsa_key)
    local rsa_sig = rsa.sign_file(rsa_key, string.format('%s/%s', test_dir, data))
    assert_not_nil(rsa_sig)
    rsa_sig:save(string.format('%s/%s', test_dir, signature), true)
  end)
  
  test("RSA verify", function()
    -- Verifying test
    rsa_key = rsa_pubkey.load(string.format('%s/%s', test_dir, pubkey))
    assert_not_nil(rsa_key)
    rsa_sig = rsa_signature.load(string.format('%s/%s', test_dir, signature))
    assert_not_nil(rsa_sig)
    assert_true(rsa.verify_file(rsa_key, rsa_sig, string.format('%s/%s', test_dir, data)))
  end)
end)
