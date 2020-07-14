--[[
Copyright (c) 2020, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

local ts = require("tableshape").types
local exports = {}
local cr_hash = require 'rspamd_cryptobox_hash'

local blake2b_key = cr_hash.create_specific('blake2'):update('rspamd'):bin()

local function digest_schema()
  return {ts.one_of{'hex', 'base32', 'bleach32', 'rbase32', 'base64'}:is_optional(),
          ts.one_of{'blake2', 'sha256', 'sha1', 'sha512', 'md5'}:is_optional()}
end

exports.digest_schema = digest_schema

local function create_raw_digest(data, args)
  local ht = args[2] or 'blake2'

  local h

  if ht == 'blake2' then
    -- Hack to be compatible with various 'get_digest' methods
    h = cr_hash.create_keyed(blake2b_key):update(data)
  else
    h = cr_hash.create_specific(ht):update(data)
  end

  return h
end

local function encode_digest(h, args)
  local encoding = args[1] or 'hex'

  local s
  if encoding == 'hex' then
    s = h:hex()
  elseif encoding == 'base32' then
    s = h:base32()
  elseif encoding == 'bleach32' then
    s = h:base32('bleach')
  elseif encoding == 'rbase32' then
    s = h:base32('rfc')
  elseif encoding == 'base64' then
    s = h:base64()
  end

  return s
end

local function create_digest(data, args)
  local h = create_raw_digest(data, args)
  return encode_digest(h, args)
end


local function get_cached_or_raw_digest(task, idx, mime_part, args)
  if #args == 0 then
    -- Optimise as we already have this hash in the API
    return mime_part:get_digest()
  end

  local ht = args[2] or 'blake2'
  local cache_key = 'mp_digest_' .. ht .. tostring(idx)

  local cached = task:cache_get(cache_key)

  if cached then
    return encode_digest(cached, args)
  end

  local h = create_raw_digest(mime_part:get_content('raw_parsed'), args)
  task:cache_set(cache_key, h)

  return encode_digest(h, args)
end

exports.create_digest = create_digest
exports.create_raw_digest = create_raw_digest
exports.get_cached_or_raw_digest = get_cached_or_raw_digest
exports.encode_digest = encode_digest

return exports