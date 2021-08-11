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
--local rspamd_logger = require "rspamd_logger"
local ts = (require "tableshape").types
local lua_util = require "lua_util"
local fun = require "fun"
local rspamd_crypto_hash = require "rspamd_cryptobox_hash"

local exports = {}

-- Returns a canonical representation of today date
local function today_canonical()
  return os.date('!%Y%m%d')
end

--[[[
-- @function lua_aws.aws_date([date_str])
-- Returns an aws date header corresponding to the specific date
--]]
local function aws_date(date_str)
  if not date_str then
    date_str = today_canonical()
  end

  return date_str .. os.date('!T%H%M%SZ')
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
  local hmac2 = rspamd_crypto_hash.create_specific_keyed(hmac1, "sha256",region):bin()
  local hmac3 = rspamd_crypto_hash.create_specific_keyed(hmac2, "sha256", service):bin()
  local final_key = rspamd_crypto_hash.create_specific_keyed(hmac3, "sha256", req_type):bin()

  save_cached_key(date_str, secret_key, region, service, req_type, final_key)

  return final_key
end

exports.aws_signing_key = aws_signing_key

--[[[
-- @function lua_aws.aws_canon_request_hash(method, path, headers_to_sign, hex_hash)
-- Returns a hash + list of headers as required to produce signature afterwards
--]]
local function aws_canon_request_hash(method, uri, headers_to_sign, hex_hash)
  assert(type(method) == 'string')
  assert(type(uri) == 'string')
  assert(type(headers_to_sign) == 'table')

  if not hex_hash then
    hex_hash = headers_to_sign['x-amz-content-sha256']
  end

  assert(type(hex_hash) == 'string')

  local sha_ctx = rspamd_crypto_hash.create_specific('sha256')

  lua_util.debugm(N, 'update signature with the method %s',
      method)
  sha_ctx:update(method .. '\n')
  lua_util.debugm(N, 'update signature with the uri %s',
      uri)
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

  return sha_ctx:hex(),hdrs_list
end

exports.aws_canon_request_hash = aws_canon_request_hash

local aws_authorization_hdr_args_schema = ts.shape{
  date = ts.string + ts['nil'] / today_canonical,
  secret_key = ts.string,
  method = ts.string + ts['nil'] / function() return 'GET' end,
  uri = ts.string,
  region = ts.string,
  service = ts.string + ts['nil'] / function() return 's3' end,
  req_type = ts.string + ts['nil'] / function() return 'aws4_request' end,
  headers = ts.map_of(ts.string, ts.string),
  key_id = ts.string,
}
--[[[
-- @function lua_aws.aws_authorization_hdr(params)
-- Produces an authorization header as required by AWS
-- Parameters schema is the following:
ts.shape{
  date = ts.string + ts['nil'] / today_canonical,
  secret_key = ts.string,
  method = ts.string + ts['nil'] / function() return 'GET' end,
  uri = ts.string,
  region = ts.string,
  service = ts.string + ts['nil'] / function() return 's3' end,
  req_type = ts.string + ts['nil'] / function() return 'aws4_request' end,
  headers = ts.map_of(ts.string, ts.string),
  key_id = ts.string,
}
--
--]]
local function aws_authorization_hdr(tbl, transformed)
  local res,err
  if not transformed then
    res,err = aws_authorization_hdr_args_schema:transform(tbl)
    assert(res, err)
  else
    res = tbl
  end

  local signing_key = aws_signing_key(res.date, res.secret_key, res.region, res.service,
      res.req_type)
  assert(signing_key ~= nil)
  local signed_sha,signed_hdrs = aws_canon_request_hash(res.method, res.uri,
      res.headers)

  if not signed_sha then
    return nil
  end

  local string_to_sign = string.format('AWS4-HMAC-SHA256\n%s\n%s/%s/%s/%s\n%s',
      res.headers['x-amz-date'] or aws_date(),
      res.date, res.region, res.service, res.req_type,
      signed_sha)
  lua_util.debugm(N, "string to sign: %s", string_to_sign)
  local hmac = rspamd_crypto_hash.create_specific_keyed(signing_key, 'sha256', string_to_sign):hex()
  lua_util.debugm(N, "hmac: %s", hmac)
  local auth_hdr = string.format('AWS4-HMAC-SHA256 Credential=%s/%s/%s/%s/%s,'..
      'SignedHeaders=%s,Signature=%s',
      res.key_id, res.date, res.region, res.service, res.req_type,
      signed_hdrs, hmac)

  return auth_hdr
end

exports.aws_authorization_hdr = aws_authorization_hdr



--[[[
-- @function lua_aws.aws_request_enrich(params, content)
-- Produces an authorization header as required by AWS
-- Parameters schema is the following:
ts.shape{
  date = ts.string + ts['nil'] / today_canonical,
  secret_key = ts.string,
  method = ts.string + ts['nil'] / function() return 'GET' end,
  uri = ts.string,
  region = ts.string,
  service = ts.string + ts['nil'] / function() return 's3' end,
  req_type = ts.string + ts['nil'] / function() return 'aws4_request' end,
  headers = ts.map_of(ts.string, ts.string),
  key_id = ts.string,
}
This method returns new/modified in place table of the headers
--
--]]
local function aws_request_enrich(tbl, content)
  local res,err = aws_authorization_hdr_args_schema:transform(tbl)
  assert(res, err)
  local content_sha256 = rspamd_crypto_hash.create_specific('sha256', content):hex()
  local hdrs = res.headers
  hdrs['x-amz-content-sha256'] = content_sha256
  if not hdrs['x-amz-date'] then
    hdrs['x-amz-date'] = aws_date(res.date)
  end
  hdrs['Authorization'] = aws_authorization_hdr(res, true)

  return hdrs
end

exports.aws_request_enrich = aws_request_enrich

-- A simple tests according to AWS docs to check sanity
local test_request_hdrs = {
  ['Host'] = 'examplebucket.s3.amazonaws.com',
  ['x-amz-date'] = '20130524T000000Z',
  ['Range'] = 'bytes=0-9',
  ['x-amz-content-sha256'] = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
}

assert(aws_canon_request_hash('GET', '/test.txt', test_request_hdrs) ==
    '7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972')

assert(aws_authorization_hdr{
  date = '20130524',
  region = 'us-east-1',
  headers = test_request_hdrs,
  uri = '/test.txt',
  key_id = 'AKIAIOSFODNN7EXAMPLE',
  secret_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
} == 'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,' ..
    'SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,' ..
    'Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41')

return exports
