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

return exports
