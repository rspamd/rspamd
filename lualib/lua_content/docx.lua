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
local rspamd_util = require "rspamd_util"

local N = "lua_content"
local exports = {}

local document_content_types = {
  ["application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"] = true,
}

local config = {
  enabled = true,
  max_documents = 8,
  processing_timeout = 2.0,
  max_entries = 10000,
  max_parts = 128,
  max_file_size = 4 * 1024 * 1024,
  max_output = 16 * 1024 * 1024,
  max_ratio = 200,
  max_relationships = 4096,
  max_content_types = 4096,
  max_target_length = 16 * 1024,
  max_text = 2 * 1024 * 1024,
  max_urls = 1024,
  xml = {
    max_input = 4 * 1024 * 1024,
    max_depth = 64,
    max_tokens = 200000,
    max_attributes = 256,
    max_attribute_length = 64 * 1024,
    max_namespace_declarations = 1024,
    max_text = 2 * 1024 * 1024,
  },
}

local budget_cache_key = 'lua_content:docx_budget'

local function ensure_state(state)
  state = state or {}
  for _, name in ipairs({
    'documents', 'entries', 'output', 'parts', 'relationships', 'content_types',
    'xml_tokens', 'text', 'urls', 'injected_text', 'injected_urls',
  }) do
    state[name] = state[name] or 0
  end
  return state
end

local function remaining(limit, used)
  return math.max(0, limit - used)
end

local function options_for_state(options, state)
  local result = lua_util.shallowcopy(options)
  result.xml = lua_util.shallowcopy(options.xml or {})
  result.xml.end_timestamp = state.end_timestamp or 0
  return result
end

local function deadline_expired(state)
  return state.end_timestamp and rspamd_util.get_ticks() >= state.end_timestamp
end

local function configure()
  if not rspamd_config then return end
  local options = rspamd_config:get_all_opt('lua_content')
  if options and options.ooxml then
    config = lua_util.override_defaults(config, options.ooxml)
  end
end

exports.hyperlink_from_instruction = rspamd_ooxml.hyperlink_from_instruction

exports.extract = function(package, requested_options, requested_state)
  local options = lua_util.override_defaults(config, requested_options or {})
  local state = ensure_state(requested_state)
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

  local native_options = options_for_state(options, state)
  native_options.max_text = remaining(options.max_text, state.text)
  native_options.max_urls = remaining(options.max_urls, state.urls)
  native_options.xml.max_tokens = remaining(options.xml.max_tokens, state.xml_tokens)

  local extracted, err, tokens = rspamd_ooxml.extract_docx(stories, native_options)
  state.xml_tokens = state.xml_tokens + (tokens or 0)
  if not extracted then return nil, err end

  state.text = state.text + extracted.text:len()
  state.urls = state.urls + #extracted.urls
  return extracted
end

local function extract_text_data(specific)
  return specific.text
end

local function process_docx(input, mpart, task)
  if not config.enabled then return nil end

  local state = task:cache_get(budget_cache_key)
  if type(state) ~= 'table' then
    state = ensure_state()
    if config.processing_timeout > 0 then
      state.end_timestamp = rspamd_util.get_ticks() + config.processing_timeout
    end
    task:cache_set(budget_cache_key, state)
  else
    ensure_state(state)
  end

  if state.documents >= config.max_documents then
    lua_util.debugm(N, task, 'cannot process DOCX: document limit exceeded')
    return nil
  end
  state.documents = state.documents + 1
  if deadline_expired(state) then
    lua_util.debugm(N, task, 'cannot process DOCX: processing timeout')
    return nil
  end

  local options = options_for_state(config, state)

  local package, err = ooxml.open(input, options, state)
  if not package then
    lua_util.debugm(N, task, 'cannot open DOCX package: %s', err)
    return nil
  end

  local extracted
  extracted, err = exports.extract(package, options, state)
  if not extracted then
    lua_util.debugm(N, task, 'cannot extract DOCX content: %s', err)
    return nil
  end

  local text_len = extracted.text:len()
  if text_len > 0 and task.inject_part then
    if deadline_expired(state) then
      lua_util.debugm(N, task, 'cannot inject DOCX text: processing timeout')
      return nil
    end
    if text_len > remaining(config.max_text, state.injected_text) then
      lua_util.debugm(N, task, 'cannot inject DOCX text: task text limit exceeded')
      return nil
    end
    task:inject_part('text', extracted.text, mpart)
    state.injected_text = state.injected_text + text_len
  end

  for i, value in ipairs(extracted.urls) do
    if i % 32 == 1 and deadline_expired(state) then
      lua_util.debugm(N, task, 'stop injecting DOCX URLs: processing timeout')
      break
    end
    if state.injected_urls >= config.max_urls then break end
    local url_ok, url = pcall(rspamd_url.create, task:get_mempool(), value, { 'content' })
    if url_ok and url then
      task:inject_url(url, mpart)
      state.injected_urls = state.injected_urls + 1
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
