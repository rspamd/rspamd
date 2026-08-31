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

-- Minimal, bounded Open Packaging Conventions reader used by OOXML content
-- processors. Only XML parts named by package relationships are extracted.

local archive = require "archive"
local rspamd_ooxml = require "rspamd_ooxml"

local exports = {}

local office_document_relationships = {
  ["http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"] = true,
  ["http://purl.oclc.org/ooxml/officeDocument/relationships/officeDocument"] = true,
}

local story_relationships = {}
for _, base in ipairs({
  "http://schemas.openxmlformats.org/officeDocument/2006/relationships/",
  "http://purl.oclc.org/ooxml/officeDocument/relationships/",
}) do
  for _, name in ipairs({ 'header', 'footer', 'footnotes', 'endnotes' }) do
    story_relationships[base .. name] = true
  end
end

local default_options = {
  max_entries = 10000,
  max_parts = 128,
  max_file_size = 4 * 1024 * 1024,
  max_output = 16 * 1024 * 1024,
  max_ratio = 200,
  max_relationships = 4096,
  max_content_types = 4096,
  max_target_length = 16 * 1024,
  xml = {
    max_tokens = 200000,
  },
}

local function merge_options(options)
  local result = {}
  for name, value in pairs(default_options) do
    result[name] = value
  end
  for name, value in pairs(options or {}) do
    result[name] = value
  end
  return result
end

-- Resolve an internal relationship target against its source part. The result
-- is the exact ZIP member spelling to request from libarchive.
exports.resolve_part_name = rspamd_ooxml.resolve_part_name

local function relationship_part_name(source_part)
  if source_part == '' then
    return '_rels/.rels'
  end

  local directory, filename = source_part:match('^(.-)([^/]+)$')
  return string.format('%s_rels/%s.rels', directory, filename)
end

exports.relationship_part_name = relationship_part_name

local parse_content_types = rspamd_ooxml.parse_content_types

local function content_type_for(content_types, part_name)
  local override = content_types.overrides[part_name]
  if override then return override end

  local extension = part_name:match('%.([^./]+)$')
  return extension and content_types.defaults[extension:lower()] or nil
end

local parse_relationships = rspamd_ooxml.parse_relationships

local function ensure_state(state)
  state = state or {}
  for _, name in ipairs({
    'entries', 'output', 'parts', 'relationships', 'content_types', 'xml_tokens',
  }) do
    state[name] = state[name] or 0
  end
  return state
end

local function remaining(limit, used)
  return math.max(0, limit - used)
end

local function parser_options(options, state)
  local xml = {}
  for name, value in pairs(options.xml or {}) do
    xml[name] = value
  end
  xml.max_tokens = remaining(xml.max_tokens or 200000, state.xml_tokens)

  return {
    max_relationships = remaining(options.max_relationships, state.relationships),
    max_content_types = remaining(options.max_content_types, state.content_types),
    max_target_length = options.max_target_length,
    xml = xml,
  }
end

local function parse_content_types_bounded(content, options, state)
  local result, err, tokens = parse_content_types(content, parser_options(options, state))
  state.xml_tokens = state.xml_tokens + (tokens or 0)
  if not result then return nil, err end

  local count = 0
  for _ in pairs(result.defaults) do count = count + 1 end
  for _ in pairs(result.overrides) do count = count + 1 end
  state.content_types = state.content_types + count
  return result
end

local function parse_relationships_bounded(content, source_part, options, state)
  local result, err, tokens = parse_relationships(content, source_part,
      parser_options(options, state))
  state.xml_tokens = state.xml_tokens + (tokens or 0)
  if not result then return nil, err end

  state.relationships = state.relationships + #result.list
  return result
end

local function content_length(content)
  if type(content) == 'string' then return #content end
  return content:len()
end

local function extract_selected(data, names, options, state)
  if #names == 0 then return {} end
  local remaining_parts = remaining(options.max_parts, state.parts)
  if #names > remaining_parts then
    return nil, "OOXML selected part limit exceeded"
  end

  local remaining_output = remaining(options.max_output, state.output)
  if remaining_output == 0 then
    return nil, "OOXML output limit exceeded"
  end
  local remaining_entries = remaining(options.max_entries, state.entries)
  if remaining_entries == 0 then
    return nil, "OOXML archive entry limit exceeded"
  end

  local ok, files, truncated, entries_seen = pcall(archive.unpack, data, 'zip', nil, {
    files = names,
    max_entries = remaining_entries,
    max_files = remaining_parts,
    max_file_size = options.max_file_size,
    max_output = remaining_output,
    max_ratio = options.max_ratio,
    end_timestamp = options.xml and options.xml.end_timestamp,
  })
  if not ok then
    return nil, string.format("cannot unpack OOXML package: %s", files)
  end
  state.entries = state.entries + (entries_seen or 0)

  local result = {}
  for _, file in ipairs(files) do
    state.output = state.output + content_length(file.content)
    state.parts = state.parts + 1
    if result[file.name] then
      return nil, string.format("duplicate OOXML part: %s", file.name)
    end
    result[file.name] = file.content
  end

  if truncated then
    return nil, "OOXML archive extraction limit exceeded"
  end

  return result
end

local function add_unique(array, seen, value)
  if not seen[value] then
    array[#array + 1] = value
    seen[value] = true
  end
end

exports.open = function(data, requested_options, requested_state)
  local options = merge_options(requested_options)
  local state = ensure_state(requested_state)
  local initial = {
    entries = state.entries,
    output = state.output,
    parts = state.parts,
    relationships = state.relationships,
    content_types = state.content_types,
    xml_tokens = state.xml_tokens,
  }

  local bootstrap, err = extract_selected(data, {
    '[Content_Types].xml',
    '_rels/.rels',
  }, options, state)
  if not bootstrap then return nil, err end
  if not bootstrap['[Content_Types].xml'] or not bootstrap['_rels/.rels'] then
    return nil, "missing OOXML package metadata"
  end

  local content_types
  content_types, err = parse_content_types_bounded(
      bootstrap['[Content_Types].xml'], options, state)
  if not content_types then return nil, err end

  local package_relationships
  package_relationships, err = parse_relationships_bounded(
      bootstrap['_rels/.rels'], '', options, state)
  if not package_relationships then return nil, err end

  local main_part
  for _, relationship in ipairs(package_relationships.list) do
    if office_document_relationships[relationship.type] and not relationship.external then
      if main_part then
        return nil, "multiple OOXML office document relationships"
      end
      main_part = relationship.part_name
    end
  end
  if not main_part then
    return nil, "missing OOXML office document relationship"
  end

  local main_relationship_part = relationship_part_name(main_part)
  local main_files
  main_files, err = extract_selected(data, {
    main_part,
    main_relationship_part,
  }, options, state)
  if not main_files then return nil, err end
  if not main_files[main_part] then
    return nil, "missing OOXML main document part"
  end

  local relationships = {}
  if main_files[main_relationship_part] then
    relationships, err = parse_relationships_bounded(
        main_files[main_relationship_part], main_part, options, state)
    if not relationships then return nil, err end
  else
    relationships = { list = {}, by_id = {} }
  end

  local story_names = {}
  local selected_names = {}
  local story_seen = {}
  local selected_seen = {}
  for _, relationship in ipairs(relationships.list) do
    if not relationship.external and story_relationships[relationship.type] then
      add_unique(story_names, story_seen, relationship.part_name)
      add_unique(selected_names, selected_seen, relationship.part_name)
      add_unique(selected_names, selected_seen, relationship_part_name(relationship.part_name))
    end
  end

  local story_files
  story_files, err = extract_selected(data, selected_names, options, state)
  if not story_files then return nil, err end

  local parts = {
    [main_part] = main_files[main_part],
  }
  local part_relationships = {
    [main_part] = relationships,
  }
  for _, story_name in ipairs(story_names) do
    if story_files[story_name] then
      parts[story_name] = story_files[story_name]
      local rels_name = relationship_part_name(story_name)
      if story_files[rels_name] then
        local parsed_story_relationships
        parsed_story_relationships, err = parse_relationships_bounded(
            story_files[rels_name], story_name, options, state)
        if not parsed_story_relationships then return nil, err end
        part_relationships[story_name] = parsed_story_relationships
      else
        part_relationships[story_name] = { list = {}, by_id = {} }
      end
    end
  end

  return {
    main_part = main_part,
    story_parts = story_names,
    parts = parts,
    relationships = part_relationships,
    content_types = content_types,
    main_content_type = content_type_for(content_types, main_part),
    extracted_bytes = state.output - initial.output,
    extracted_parts = state.parts - initial.parts,
    archive_entries = state.entries - initial.entries,
    relationship_count = state.relationships - initial.relationships,
    content_type_count = state.content_types - initial.content_types,
    xml_tokens = state.xml_tokens - initial.xml_tokens,
  }
end

return exports
