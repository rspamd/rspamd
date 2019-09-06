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
-- @module lua_magic/patterns
-- This module contains types definitions
--]]

-- This table is indexed by msdos extension for convenience

local types = {
  -- exe
  exe = {
    ct = 'application/x-ms-application',
    type = 'executable',
  },
  -- text
  rtf = {
    ct = "application/rtf",
    type = 'text',
  },
  pdf = {
    ct = 'application/pdf',
    type = 'binary',
  },
  ps = {
    ct = 'application/postscript',
    type = 'binary',
  },
  chm = {
    ct = 'application/chm',
    type = 'binary',
  },
  djvu = {
    ct = 'application/djvu',
    type = 'binary',
  },
  -- archives
  arj = {
    ct = 'application/x-compressed',
    type = 'archive',
  },
  cab = {
    ct = 'application/x-compressed',
    type = 'archive',
  },
  ace = {
    ct = 'application/x-compressed',
    type = 'archive',
  },
  -- images
  psd = {
    ct = 'image/psd',
    type = 'image',
  },
  pcx = {
    ct = 'image/pcx',
    type = 'image',
  },
  pic = {
    ct = 'image/pic',
    type = 'image',
  },
  tiff = {
    ct = 'image/tiff',
    type = 'image',
  },
  ico = {
    ct = 'image/ico',
    type = 'image',
  },
  -- other
  pgp = {
    ct = 'application/encrypted',
    type = 'encrypted'
  }
}

return types