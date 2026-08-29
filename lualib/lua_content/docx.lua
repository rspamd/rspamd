--[[
Copyright (c) 2026, Vsevolod Stakhov <vsevolod@rspamd.com>

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

local lua_util = require "lua_util"
local ooxml = require "lua_content/ooxml"
local rspamd_url = require "rspamd_url"
local rspamd_ooxml = require "rspamd_ooxml"

local N = "lua_content"
local exports = {}

local document_content_types = {
  ["application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"] = true,
}

local config = {
  enabled = true,
  max_entries = 10000,
  max_parts = 128,
  max_file_size = 4 * 1024 * 1024,
  max_output = 16 * 1024 * 1024,
  max_ratio = 200,
  max_relationships = 4096,
  max_target_length = 16 * 1024,
  max_text = 2 * 1024 * 1024,
  max_urls = 1024,
  xml = {
    max_input = 4 * 1024 * 1024,
    max_depth = 64,
    max_tokens = 200000,
    max_attributes = 256,
    max_attribute_length = 64 * 1024,
    max_text = 2 * 1024 * 1024,
  },
}

local function configure()
  if not rspamd_config then return end
  local options = rspamd_config:get_all_opt('lua_content')
  if options and options.ooxml then
    config = lua_util.override_defaults(config, options.ooxml)
  end
end

exports.hyperlink_from_instruction = rspamd_ooxml.hyperlink_from_instruction

exports.extract = function(package, requested_options)
  local options = lua_util.override_defaults(config, requested_options or {})
  if not document_content_types[package.main_content_type] then
    return nil, "OOXML package is not a DOCX document"
  end

  local stories = {}
  local part_names = { package.main_part }
  for _, part_name in ipairs(package.story_parts) do
    part_names[#part_names + 1] = part_name
  end

  for _, part_name in ipairs(part_names) do
    local contents = package.parts[part_name]
    if contents then
      local relationships = package.relationships[part_name] or { list = {}, by_id = {} }
      stories[#stories + 1] = {
        content = contents,
        relationships = relationships,
      }
    end
  end

  return rspamd_ooxml.extract_docx(stories, options)
end

local function extract_text_data(specific)
  return specific.text
end

local function process_docx(input, mpart, task)
  if not config.enabled then return nil end

  local package, err = ooxml.open(input, config)
  if not package then
    lua_util.debugm(N, task, 'cannot open DOCX package: %s', err)
    return nil
  end

  local extracted
  extracted, err = exports.extract(package, config)
  if not extracted then
    lua_util.debugm(N, task, 'cannot extract DOCX content: %s', err)
    return nil
  end

  if extracted.text:len() > 0 and task.inject_part then
    task:inject_part('text', extracted.text, mpart)
  end

  for _, value in ipairs(extracted.urls) do
    local url_ok, url = pcall(rspamd_url.create, task:get_mempool(), value, { 'content' })
    if url_ok and url then
      task:inject_url(url, mpart)
    end
  end

  return {
    tag = 'docx',
    extract_text = extract_text_data,
    text = extracted.text,
    urls = extracted.urls,
    main_part = package.main_part,
    story_parts = package.story_parts,
    extracted_bytes = package.extracted_bytes,
    extracted_parts = package.extracted_parts,
  }
end

configure()

exports.process = process_docx
exports.config = config

return exports
