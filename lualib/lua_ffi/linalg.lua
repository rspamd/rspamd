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

--[[[
-- @module lua_ffi/linalg
-- This module contains ffi interfaces to linear algebra routines
--]]

local ffi = require 'ffi'

local exports = {}

ffi.cdef[[
  void kad_sgemm_simple(int trans_A, int trans_B, int M, int N, int K, const float *A, const float *B, float *C);
  bool kad_ssyev_simple (int N, float *A, float *output);
]]

local function table_to_ffi(a, m, n)
  local a_conv = ffi.new("float[?]", m * n)
  for i=1,m or #a do
    for j=1,n or #a[1] do
      a_conv[(i - 1) * n + (j - 1)] = a[i][j]
    end
  end
  return a_conv
end

local function ffi_to_table(a, m, n)
  local res = {}

  for i=0,m-1 do
    res[i + 1] = {}
    for j=0,n-1 do
      res[i + 1][j + 1] = a[i * n + j]
    end
  end

  return res
end

exports.sgemm = function(a, m, b, n, k, trans_a, trans_b)
  if type(a) == 'table' then
    -- Need to convert, slow!
    a = table_to_ffi(a, m, k)
  end
  if type(b) == 'table' then
    b = table_to_ffi(b, k, n)
  end
  local res = ffi.new("float[?]", m * n)
  ffi.C.kad_sgemm_simple(trans_a or 0, trans_b or 0, m, n, k, ffi.cast('const float*', a),
      ffi.cast('const float*', b), ffi.cast('float*', res))
  return res
end

exports.eigen = function(a, n)
  if type(a) == 'table' then
    -- Need to convert, slow!
    n = n or #a
    a = table_to_ffi(a, n, n)
  end

  local res = ffi.new("float[?]", n)

  if ffi.C.kad_ssyev_simple(n, ffi.cast('float*', a), res) then
    return res,a
  end

  return nil
end

exports.ffi_to_table = ffi_to_table
exports.table_to_ffi = table_to_ffi

return exports