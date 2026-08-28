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
    mime_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    module = require "lua_content/docx",
    extensions = { 'docx' },
    output = "table",
    process_archive = true,
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

exports.maybe_process_mime_part = function(part, task)
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
      if part:is_archive() then
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
