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

local function digest_schema()
  return {ts.one_of{'hex', 'base32', 'bleach32', 'rbase32', 'base64'}:is_optional(),
          ts.one_of{'blake2', 'sha256', 'sha1', 'sha512', 'md5'}:is_optional()}
end

exports.digest_schema = digest_schema

local function create_digest(data, args)
  local hash = require 'rspamd_cryptobox_hash'
  local encoding = args[1] or 'hex'
  local ht = args[2] or 'blake2'
  local h = hash:create_specific(ht):update(data)
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

exports.create_digest = create_digest

return exports