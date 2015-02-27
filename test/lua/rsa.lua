-- Test rsa signing

local pubkey = 'testkey.pub'
local privkey = 'testkey'
local data = 'test.data'
local signature = 'test.sig'

-- Signing test
local rsa_key = rsa_privkey.load(string.format('%s/%s', test_dir, privkey))

if not rsa_key then
	return -1
end

local rsa_sig = rsa.sign_file(rsa_key, string.format('%s/%s', test_dir, data))

if not rsa_sig then
	return -1
end

rsa_sig:save(string.format('%s/%s', test_dir, signature), true)

-- Verifying test
rsa_key = rsa_pubkey.load(string.format('%s/%s', test_dir, pubkey))

if not rsa_key then
	return -1
end

rsa_sig = rsa_signature.load(string.format('%s/%s', test_dir, signature))

if not rsa_sig then
	return -1
end

if not rsa.verify_file(rsa_key, rsa_sig, string.format('%s/%s', test_dir, data)) then
	return -1
end

