--[[
Copyright (c) 2021, Vsevolod Stakhov <vsevolod@highsecure.ru>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
]]--


--[[[
-- @module lua_aws
-- This module contains Amazon AWS utility functions
--]]

local N = "aws"
local rspamd_logger = require "rspamd_logger"
local lua_util = require "lua_util"
local fun = require "fun"
local rspamd_crypto_hash = require "rspamd_cryptobox_hash"

local exports = {}

-- Returns a canonical representation of today date
local function today_canonical()
  return os.date('!%Y%m%d', os.time())
end

--[[[
-- @function lua_aws.aws_date([date_str])
-- Returns an aws date header corresponding to the specific date
--]]
local function aws_date(date_str)
  if not date_str then
    date_str = today_canonical()
  end

  return date_str .. 'T000000Z'
end

exports.aws_date = aws_date


-- Local cache of the keys to save resources
local cached_keys = {}

local function maybe_get_cached_key(date_str, secret_key, region, service, req_type)
  local bucket = cached_keys[tonumber(date_str)]

  if not bucket then
    return nil
  end

  local elt = bucket[string.format('%s.%s.%s.%s', secret_key, region, service, req_type)]
  if elt then
    return elt
  end
end

local function save_cached_key(date_str, secret_key, region, service, req_type, key)
  local numdate = tonumber(date_str)
  -- expire old buckets
  for k,_ in pairs(cached_keys) do
    if k < numdate then
      cached_keys[k] = nil
    end
  end


  local bucket = cached_keys[tonumber(date_str)]
  local idx = string.format('%s.%s.%s.%s', secret_key, region, service, req_type)

  if not bucket then
    cached_keys[tonumber(date_str)] = {
      idx = key
    }
  else
    bucket[idx] = key
  end
end
--[[[
-- @function lua_aws.aws_signing_key([date_str], secret_key, region, [service='s3'], [req_type='aws4_request'])
-- Returns a signing key for the specific parameters
--]]
local function aws_signing_key(date_str, secret_key, region, service, req_type)
  if not date_str then
    date_str = today_canonical()
  end

  if not service then
    service = 's3'
  end

  if not req_type then
    req_type = 'aws4_request'
  end

  assert(type(secret_key) == 'string')
  assert(type(region) == 'string')

  local maybe_cached = maybe_get_cached_key(date_str, secret_key, region, service, req_type)

  if maybe_cached then
    return maybe_cached
  end

  local hmac1 = rspamd_crypto_hash.create_specific_keyed("AWS4" .. secret_key, "sha256", date_str):bin()
  local hmac2 = rspamd_crypto_hash.create_specific_keyed(hmac1, "sha256", date_str):bin()
  local hmac3 = rspamd_crypto_hash.create_specific_keyed(hmac2, "sha256",region):bin()
  local hmac4 = rspamd_crypto_hash.create_specific_keyed(hmac3, "sha256", service):bin()
  local final_key = rspamd_crypto_hash.create_specific_keyed(hmac4, "sha256", req_type):bin()

  save_cached_key(date_str, secret_key, region, service, req_type, final_key)

  return final_key
end

exports.aws_signing_key = aws_signing_key

--[[[
-- @function lua_aws.aws_canon_request_hash(method, path, headers_to_sign, hex_hash)
-- Returns an Authorization header required for AWS
--]]
local function aws_canon_request_hash(method, uri, headers_to_sign, hex_hash)
  lua_util.debugm(N, 'huis')
  assert(type(method) == 'string')
  assert(type(uri) == 'string')
  assert(type(headers_to_sign) == 'table')

  if not hex_hash then
    hex_hash = headers_to_sign['x-amz-content-sha256']
  end

  assert(type(hex_hash) == 'string')

  local sha_ctx = rspamd_crypto_hash.create_specific('sha256')

  sha_ctx:update(method .. '\n')
  sha_ctx:update(uri .. '\n')
  -- XXX add query string canonicalisation
  sha_ctx:update('\n')
  -- Sort auth headers and canonicalise them as requested
  local hdr_canon = fun.tomap(fun.map(function(k, v)
    return k:lower(), lua_util.str_trim(v)
  end, headers_to_sign))
  local header_names = lua_util.keys(hdr_canon)
  table.sort(header_names)
  for _,hn in ipairs(header_names) do
    local v = hdr_canon[hn]
    lua_util.debugm(N, 'update signature with the header %s, %s',
        hn, v)
    sha_ctx:update(string.format('%s:%s\n', hn, v))
  end
  local hdrs_list = table.concat(header_names, ';')
  lua_util.debugm(N, 'headers list to sign: %s', hdrs_list)
  sha_ctx:update(string.format('\n%s\n%s', hdrs_list, hex_hash))

  return sha_ctx:hex()
end

exports.aws_canon_request_hash = aws_canon_request_hash

-- A simple tests according to AWS docs to check sanity
local test_request_hdrs = {
  ['Host'] = 'examplebucket.s3.amazonaws.com',
  ['x-amz-date'] = '20130524T000000Z',
  ['Range'] = 'bytes=0-9',
  ['x-amz-content-sha256'] = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  ['x-amz-date'] = '20130524T000000Z '
}

assert(aws_canon_request_hash('GET', '/test.txt', test_request_hdrs) ==
    '7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972')

return exports
