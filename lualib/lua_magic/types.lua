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
  elf = {
    ct = 'application/x-elf-executable',
    type = 'executable',
  },
  lnk = {
    ct = 'application/x-ms-application',
    type = 'executable',
  },
  class = {
    ct = 'application/x-java-applet',
    type = 'executable',
  },
  jar = {
    ct = 'application/java-archive',
    type = 'archive',
  },
  apk = {
    ct = 'application/vnd.android.package-archive',
    type = 'archive',
  },
  bat = {
    ct = 'application/x-bat',
    type = 'executable',
  },
  -- text
  rtf = {
    ct = "application/rtf",
    type = 'binary',
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
    ct = 'application/x-chm',
    type = 'binary',
  },
  djvu = {
    ct = 'application/x-djvu',
    type = 'binary',
  },
  -- archives
  arj = {
    ct = 'application/x-arj',
    type = 'archive',
  },
  cab = {
    ct = 'application/x-cab',
    type = 'archive',
  },
  ace = {
    ct = 'application/x-ace',
    type = 'archive',
  },
  tar = {
    ct = 'application/x-tar',
    type = 'archive',
  },
  bz2 = {
    ct = 'application/x-bzip',
    type = 'archive',
  },
  xz = {
    ct = 'application/x-xz',
    type = 'archive',
  },
  lz4 = {
    ct = 'application/x-lz4',
    type = 'archive',
  },
  zst = {
    ct = 'application/x-zstandard',
    type = 'archive',
  },
  dmg = {
    ct = 'application/x-dmg',
    type = 'archive',
  },
  iso = {
    ct = 'application/x-iso',
    type = 'archive',
  },
  zoo = {
    ct = 'application/x-zoo',
    type = 'archive',
  },
  egg = {
    ct = 'application/x-egg',
    type = 'archive',
  },
  alz = {
    ct = 'application/x-alz',
    type = 'archive',
  },
  xar = {
    ct = 'application/x-xar',
    type = 'archive',
  },
  epub = {
    ct = 'application/x-epub',
    type = 'archive'
  },
  szdd = { -- in fact, their MSDOS extension is like FOO.TX_ or FOO.TX$
    ct = 'application/x-compressed',
    type = 'archive',
  },
  -- images
  psd = {
    ct = 'image/psd',
    type = 'image',
    av_check = false,
  },
  pcx = {
    ct = 'image/pcx',
    type = 'image',
    av_check = false,
  },
  pic = {
    ct = 'image/pic',
    type = 'image',
    av_check = false,
  },
  tiff = {
    ct = 'image/tiff',
    type = 'image',
    av_check = false,
  },
  ico = {
    ct = 'image/ico',
    type = 'image',
    av_check = false,
  },
  swf = {
    ct = 'application/x-shockwave-flash',
    type = 'image',
  },
  -- Ole files
  ole = {
    ct = 'application/octet-stream',
    type = 'office'
  },
  doc = {
    ct = 'application/msword',
    type = 'office'
  },
  xls = {
    ct = 'application/vnd.ms-excel',
    type = 'office'
  },
  ppt = {
    ct = 'application/vnd.ms-powerpoint',
    type = 'office'
  },
  vsd = {
    ct = 'application/vnd.visio',
    type = 'office'
  },
  msi = {
    ct = 'application/x-msi',
    type = 'executable'
  },
  msg = {
    ct = 'application/vnd.ms-outlook',
    type = 'office'
  },
  -- newer office (2007+)
  docx = {
    ct = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    type = 'office'
  },
  xlsx = {
    ct = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    type = 'office'
  },
  pptx = {
    ct = 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    type = 'office'
  },
  -- OpenOffice formats
  odt = {
    ct = 'application/vnd.oasis.opendocument.text',
    type = 'office'
  },
  ods = {
    ct = 'application/vnd.oasis.opendocument.spreadsheet',
    type = 'office'
  },
  odp = {
    ct = 'application/vnd.oasis.opendocument.presentation',
    type = 'office'
  },
  -- https://en.wikipedia.org/wiki/Associated_Signature_Containers
  asice = {
    ct = 'application/vnd.etsi.asic-e+zip',
    type = 'office'
  },
  asics = {
    ct = 'application/vnd.etsi.asic-s+zip',
    type = 'office'
  },
  -- other
  pgp = {
    ct = 'application/encrypted',
    type = 'encrypted'
  },
  uue = {
    ct = 'application/x-uuencoded',
    type = 'binary',
  },
  -- Types that are detected by Rspamd itself
  -- Archives
  zip = {
    ct = 'application/zip',
    type = 'archive',
  },
  rar = {
    ct = 'application/x-rar',
    type = 'archive',
  },
  ['7z'] = {
    ct = 'x-7z-compressed',
    type = 'archive',
  },
  gz = {
    ct = 'application/gzip',
    type = 'archive',
  },
  -- Images
  png = {
    ct = 'image/png',
    type = 'image',
    av_check = false,
  },
  gif = {
    ct = 'image/gif',
    type = 'image',
    av_check = false,
  },
  jpg = {
    ct = 'image/jpeg',
    type = 'image',
    av_check = false,
  },
  bmp = {
    type = 'image',
    ct = 'image/bmp',
    av_check = false,
  },
  dwg = {
    type = 'image',
    ct = 'image/vnd.dwg',
  },
  -- Text
  xml = {
    ct = 'application/xml',
    type = 'text',
    no_text = true,
  },
  txt = {
    type = 'text',
    ct = 'text/plain',
    av_check = false,
  },
  html = {
    type = 'text',
    ct = 'text/html',
    av_check = false,
  },
  csv = {
    type = 'text',
    ct = 'text/csv',
    av_check = false,
    no_text = true,
  },
  ics = {
    type = 'text',
    ct = 'text/calendar',
    av_check = false,
    no_text = true,
  },
  vcf = {
    type = 'text',
    ct = 'text/vcard',
    av_check = false,
    no_text = true,
  },
  eml = {
    type = 'message',
    ct = 'message/rfc822',
    av_check = false,
  },
}

return types