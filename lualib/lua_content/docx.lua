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
local xml = require "lua_content/xml_tokenizer"

local N = "lua_content"
local exports = {}

local word_namespaces = {
  ["http://schemas.openxmlformats.org/wordprocessingml/2006/main"] = true,
  ["http://purl.oclc.org/ooxml/wordprocessingml/main"] = true,
}

local drawing_namespaces = {
  ["http://schemas.openxmlformats.org/drawingml/2006/main"] = true,
  ["http://purl.oclc.org/ooxml/drawingml/main"] = true,
}

local relationship_namespaces = {
  ["http://schemas.openxmlformats.org/officeDocument/2006/relationships"] = true,
  ["http://purl.oclc.org/ooxml/officeDocument/relationships"] = true,
}

local hyperlink_relationships = {
  ["http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink"] = true,
  ["http://purl.oclc.org/ooxml/officeDocument/relationships/hyperlink"] = true,
}

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

local function get_attr(attributes, namespace_set, name)
  for _, attribute in ipairs(attributes) do
    if attribute.name == name and
        ((namespace_set and namespace_set[attribute.namespace]) or
          (not namespace_set and not attribute.namespace)) then
      return attribute.value
    end
  end
  return nil
end

local function hyperlink_from_instruction(instruction)
  local upper = instruction:upper()
  local start = upper:find('HYPERLINK', 1, true)
  if not start then return nil end

  local before = start > 1 and instruction:sub(start - 1, start - 1) or ''
  local after_pos = start + 9
  local after = instruction:sub(after_pos, after_pos)
  if before:match('[%w_]') or after:match('[%w_]') then return nil end

  local rest = instruction:sub(after_pos):match('^%s*(.-)%s*$')
  if rest == '' or rest:sub(1, 1) == '\\' then return nil end

  local quote = rest:sub(1, 1)
  local target
  if quote == '"' or quote == "'" then
    local close = rest:find(quote, 2, true)
    if close then target = rest:sub(2, close - 1) end
  else
    target = rest:match('^([^%s]+)')
  end

  if target then
    target = target:gsub('\\(.)', '%1')
  end
  return target ~= '' and target or nil
end

exports.hyperlink_from_instruction = hyperlink_from_instruction

local function extract_part(contents, relationships, options, result)
  local chunks = result.chunks
  local depth = 0
  local excluded_depth
  local text_depth
  local instruction_depth
  local fields = {}
  local parse_error

  local function add_text(value)
    if parse_error or value == '' then return end
    result.text_bytes = result.text_bytes + #value
    if result.text_bytes > options.max_text then
      parse_error = "DOCX text limit exceeded"
      return
    end
    chunks[#chunks + 1] = value
  end

  local function add_url(value)
    if not value or value == '' or result.url_seen[value] then return end
    if #result.urls >= options.max_urls then
      parse_error = "DOCX URL limit exceeded"
      return
    end
    result.url_seen[value] = true
    result.urls[#result.urls + 1] = value
  end

  local function finish_field(field)
    if field and not field.parsed then
      add_url(hyperlink_from_instruction(table.concat(field.instruction)))
      field.parsed = true
    end
  end

  local ok, err = xml.parse(contents, {
    start_element = function(namespace, name, attributes)
      depth = depth + 1
      if parse_error then return end

      if word_namespaces[namespace] then
        if (name == 'del' or name == 'moveFrom') and not excluded_depth then
          excluded_depth = depth
        elseif name == 't' and not excluded_depth then
          text_depth = depth
        elseif name == 'tab' and not excluded_depth then
          add_text('\t')
        elseif (name == 'br' or name == 'cr') and not excluded_depth then
          add_text('\n')
        elseif name == 'hyperlink' then
          local id = get_attr(attributes, relationship_namespaces, 'id')
          local relationship = id and relationships.by_id[id] or nil
          if relationship and relationship.external and
              hyperlink_relationships[relationship.type] then
            add_url(relationship.target)
          end
        elseif name == 'fldSimple' then
          add_url(hyperlink_from_instruction(get_attr(attributes, word_namespaces, 'instr') or ''))
        elseif name == 'fldChar' then
          local field_type = get_attr(attributes, word_namespaces, 'fldCharType')
          if field_type == 'begin' then
            fields[#fields + 1] = { instruction = {} }
          elseif field_type == 'separate' then
            finish_field(fields[#fields])
          elseif field_type == 'end' then
            finish_field(fields[#fields])
            fields[#fields] = nil
          end
        elseif name == 'instrText' and fields[#fields] then
          instruction_depth = depth
        end
      elseif drawing_namespaces[namespace] and name == 't' and not excluded_depth then
        text_depth = depth
      end
    end,
    end_element = function(namespace, name)
      if not parse_error then
        if word_namespaces[namespace] and name == 'p' and not excluded_depth then
          add_text('\n')
        end
      end

      if text_depth == depth then text_depth = nil end
      if instruction_depth == depth then instruction_depth = nil end
      if excluded_depth == depth then excluded_depth = nil end
      depth = depth - 1
    end,
    text = function(value)
      if parse_error then return end
      if instruction_depth and fields[#fields] then
        fields[#fields].instruction[#fields[#fields].instruction + 1] = value
      elseif text_depth and not excluded_depth then
        add_text(value)
      end
    end,
  }, options.xml)

  if not ok then return nil, err end
  if parse_error then return nil, parse_error end

  return true
end

exports.extract = function(package, requested_options)
  local options = lua_util.override_defaults(config, requested_options or {})
  if not document_content_types[package.main_content_type] then
    return nil, "OOXML package is not a DOCX document"
  end

  local result = {
    chunks = {},
    text_bytes = 0,
    urls = {},
    url_seen = {},
  }
  local part_names = { package.main_part }
  for _, part_name in ipairs(package.story_parts) do
    part_names[#part_names + 1] = part_name
  end

  for _, part_name in ipairs(part_names) do
    local contents = package.parts[part_name]
    if contents then
      local relationships = package.relationships[part_name] or { list = {}, by_id = {} }
      local ok, err = extract_part(contents, relationships, options, result)
      if not ok then return nil, err end
      if result.chunks[#result.chunks] ~= '\n' then
        if result.text_bytes >= options.max_text then
          return nil, "DOCX text limit exceeded"
        end
        result.chunks[#result.chunks + 1] = '\n'
        result.text_bytes = result.text_bytes + 1
      end
    end
  end

  local text = table.concat(result.chunks):gsub('\n\n\n+', '\n\n')
  return {
    text = text,
    urls = result.urls,
  }
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

  if extracted.text ~= '' and task.inject_part then
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
