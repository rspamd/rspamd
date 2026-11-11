--[[
Copyright (c) 2022, Vsevolod Stakhov <vsevolod@rspamd.com>

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
-- @module lua_content
-- This module contains content processing logic
--]]


local exports = {}
local N = "lua_content"
local lua_util = require "lua_util"

local content_modules = {
  ical = {
    mime_type = { "text/calendar", "application/calendar" },
    module = require "lua_content/ical",
    extensions = { 'ics' },
    output = "text"
  },
  vcf = {
    mime_type = { "text/vcard", "application/vcard" },
    module = require "lua_content/vcard",
    extensions = { 'vcf' },
    output = "text"
  },
  pdf = {
    mime_type = "application/pdf",
    module = require "lua_content/pdf",
    extensions = { 'pdf' },
    output = "table"
  },
  docx = {
    mime_type = {
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.template",
      "application/vnd.ms-word.document.macroenabled.12",
      "application/vnd.ms-word.template.macroenabled.12",
    },
    module = require "lua_content/docx",
    extensions = { 'docx', 'docm', 'dotx', 'dotm' },
    output = "table",
    process_archive = true,
  },
  xlsx = {
    mime_type = {
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.template",
      "application/vnd.ms-excel.sheet.macroenabled.12",
      "application/vnd.ms-excel.template.macroenabled.12",
      "application/vnd.ms-excel.addin.macroenabled.12",
    },
    module = require "lua_content/xlsx",
    extensions = { 'xlsx', 'xlsm', 'xltx', 'xltm', 'xlam' },
    output = "table",
    process_archive = true,
  },
  pptx = {
    mime_type = {
      "application/vnd.openxmlformats-officedocument.presentationml.presentation",
      "application/vnd.openxmlformats-officedocument.presentationml.slideshow",
      "application/vnd.openxmlformats-officedocument.presentationml.template",
      "application/vnd.ms-powerpoint.presentation.macroenabled.12",
      "application/vnd.ms-powerpoint.slideshow.macroenabled.12",
      "application/vnd.ms-powerpoint.template.macroenabled.12",
    },
    module = require "lua_content/pptx",
    extensions = { 'pptx', 'pptm', 'ppsx', 'ppsm', 'potx', 'potm' },
    output = "table",
    process_archive = true,
  },
  svg = {
    mime_type = { "image/svg+xml", "image/svg" },
    module = require "lua_content/svg",
    extensions = { 'svg', 'svgz' },
    output = "table",
    -- gzip-compressed SVGZ parts are detected as archives
    process_archive = true,
    -- A document that the strict detection does not take for an image is
    -- still opened as one by its name, and the handler tells what is wrong
    by_name = true,
  },
}

local modules_by_mime_type
local modules_by_extension

local function cache_key(part)
  return string.format('lua_content:%s', part:get_id())
end

local function init()
  modules_by_mime_type = {}
  modules_by_extension = {}
  for k, v in pairs(content_modules) do
    if v.mime_type then
      if type(v.mime_type) == 'table' then
        for _, mt in ipairs(v.mime_type) do
          modules_by_mime_type[mt] = { k, v }
        end
      else
        modules_by_mime_type[v.mime_type] = { k, v }
      end

    end
    if v.extensions then
      for _, ext in ipairs(v.extensions) do
        modules_by_extension[ext] = { k, v }
      end
    end
  end
end

-- `keep_text`: the part is text that only looks like some format (e.g. a
-- text/plain part with "%PDF-1.4" in it); its content is read, but kept aside
-- as for archives, so that the part stays text
exports.maybe_process_mime_part = function(part, task, keep_text)
  if not modules_by_mime_type then
    init()
  end

  local ctype, csubtype = part:get_type()
  local mt = string.format("%s/%s", ctype or 'application',
      csubtype or 'octet-stream')
  local pair = modules_by_mime_type[mt]

  if not pair then
    local ext = part:get_detected_ext()

    if ext then
      pair = modules_by_extension[ext]
    end

    if not pair and ext == 'zip' and not keep_text then
      -- The content tells nothing more than "an archive". The application
      -- that opens the file goes by its name, so the name picks the handler,
      -- which then says if the content is what the name claims
      local fname = part:get_filename()
      local fext = fname and fname:match('%.([%w]+)$')

      if fext then
        pair = modules_by_extension[fext:lower()]
      end
    elseif not pair and not ext and not keep_text and not part:is_text() then
      -- The content is not recognised at all
      local fname = part:get_filename()
      local fext = fname and fname:match('%.([%w]+)$')
      local by_ext = fext and modules_by_extension[fext:lower()]

      if by_ext and by_ext[2].by_name then
        pair = by_ext
      end
    end
  end

  if pair then
    if part:is_archive() and not pair[2].process_archive then
      lua_util.debugm(N, task, "skip %s content processor for archive part",
          pair[1])
      return
    end

    lua_util.debugm(N, task, "found known content of type %s: %s",
        mt, pair[1])

    local data = pair[2].module.process(part:get_content(), part, task)

    if data then
      lua_util.debugm(N, task, "extracted content from %s: %s type",
          pair[1], type(data))
      if part:is_archive() or keep_text then
        task:cache_set(cache_key(part), data)
      else
        part:set_specific(data)
      end
    else
      lua_util.debugm(N, task, "failed to extract anything from %s",
          pair[1])
    end
  end

end

exports.get_specific = function(part, task)
  if part:is_specific() then
    return part:get_specific()
  end

  return task:cache_get(cache_key(part))
end

return exports
