--[[
Copyright (c) 2019, Vsevolod Stakhov <vsevolod@highsecure.ru>

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
-- @module lua_ffi
-- This module contains ffi interfaces (requires luajit or lua-ffi)
--]]

local ffi

local exports = {}

if type(jit) == 'table' then
  ffi = require "ffi"
  local NULL = ffi.new 'void*'

  exports.is_null = function(o)
    return o ~= NULL
  end
else
  local ret,result_or_err = pcall(require, 'ffi')

  if not ret then
    return {}
  end

  ffi = result_or_err
  -- Lua ffi
  local NULL = ffi.NULL or ffi.C.NULL
  exports.is_null = function(o)
    return o ~= NULL
  end
end

pcall(ffi.load, "rspamd-server", true)
exports.common = require "lua_ffi/common"
exports.dkim = require "lua_ffi/dkim"
exports.spf = require "lua_ffi/spf"
exports.linalg = require "lua_ffi/linalg"

for k,v in pairs(ffi) do
  -- Preserve all stuff to use lua_ffi as ffi itself
  exports[k] = v
end

return exports