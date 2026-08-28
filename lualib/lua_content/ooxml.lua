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
local xml = require "lua_content/xml_tokenizer"

local exports = {}

local content_types_namespaces = {
  ["http://schemas.openxmlformats.org/package/2006/content-types"] = true,
  ["http://purl.oclc.org/ooxml/package/content-types"] = true,
}

local relationships_namespaces = {
  ["http://schemas.openxmlformats.org/package/2006/relationships"] = true,
  ["http://purl.oclc.org/ooxml/package/relationships"] = true,
}

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
  max_target_length = 16 * 1024,
  xml = {},
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

local function get_attr(attributes, name)
  for _, attribute in ipairs(attributes) do
    if not attribute.namespace and attribute.name == name then
      return attribute.value
    end
  end
  return nil
end

local function percent_decode(value)
  local pos = 1
  while true do
    local percent = value:find('%', pos, true)
    if not percent then break end
    local hex = value:sub(percent + 1, percent + 2)
    if #hex ~= 2 or not hex:match('^%x%x$') then
      return nil
    end
    pos = percent + 3
  end

  return (value:gsub('%%(%x%x)', function(hex)
    return string.char(tonumber(hex, 16))
  end))
end

local function validate_segment(segment)
  if segment == '' then
    return nil, "empty path segment"
  end

  local decoded = percent_decode(segment)
  if not decoded then
    return nil, "invalid percent escape"
  end
  if decoded:find('[%z\1-\31\\/]') then
    return nil, "encoded path separator or control character"
  end
  if decoded == '.' or decoded == '..' then
    return nil, "encoded dot path segment"
  end

  return true
end


-- Resolve an internal relationship target against its source part. The result
-- is the exact ZIP member spelling to request from libarchive.
exports.resolve_part_name = function(source_part, target)
  if type(target) ~= 'string' or target == '' then
    return nil, "empty relationship target"
  end
  if target:find('[%z\1-\31\\]') then
    return nil, "control character or backslash in relationship target"
  end
  if target:sub(1, 1) == '/' or target:sub(1, 2) == '//' or
      target:match('^[%a][%w+.-]*:') then
    return nil, "absolute internal relationship target"
  end

  local path = target:match('^([^#]*)')
  if path == '' or path:find('?', 1, true) or path:find('//', 1, true) or
      path:sub(-1) == '/' then
    return nil, "invalid internal relationship target"
  end

  local components = {}
  if source_part and source_part ~= '' then
    for segment in source_part:gmatch('[^/]+') do
      components[#components + 1] = segment
    end
    components[#components] = nil
  end

  for segment in path:gmatch('[^/]+') do
    if segment == '..' then
      if #components == 0 then
        return nil, "relationship target escapes package root"
      end
      components[#components] = nil
    elseif segment ~= '.' then
      local ok, err = validate_segment(segment)
      if not ok then
        return nil, err
      end
      components[#components + 1] = segment
    end
  end

  if #components == 0 then
    return nil, "relationship target does not name a part"
  end

  return table.concat(components, '/')
end

local function relationship_part_name(source_part)
  if source_part == '' then
    return '_rels/.rels'
  end

  local directory, filename = source_part:match('^(.-)([^/]+)$')
  return string.format('%s_rels/%s.rels', directory, filename)
end

exports.relationship_part_name = relationship_part_name

local function parse_content_types(contents, options)
  local result = {
    defaults = {},
    overrides = {},
  }
  local depth = 0
  local parse_error
  local root_seen = false

  local ok, err = xml.parse(contents, {
    start_element = function(namespace, name, attributes)
      depth = depth + 1
      if parse_error then return end

      if depth == 1 then
        if name ~= 'Types' or not content_types_namespaces[namespace] then
          parse_error = "invalid OOXML content types root"
        else
          root_seen = true
        end
      elseif depth == 2 and content_types_namespaces[namespace] then
        if name == 'Default' then
          local extension = get_attr(attributes, 'Extension')
          local content_type = get_attr(attributes, 'ContentType')
          if not extension or extension == '' or not content_type or content_type == '' then
            parse_error = "invalid OOXML default content type"
          elseif result.defaults[extension:lower()] then
            parse_error = "duplicate OOXML default content type"
          else
            result.defaults[extension:lower()] = content_type
          end
        elseif name == 'Override' then
          local part_name = get_attr(attributes, 'PartName')
          local content_type = get_attr(attributes, 'ContentType')
          if not part_name or part_name:sub(1, 1) ~= '/' or
              not content_type or content_type == '' then
            parse_error = "invalid OOXML content type override"
          else
            local normalized, normalize_error = exports.resolve_part_name('', part_name:sub(2))
            if not normalized then
              parse_error = string.format("invalid OOXML part name: %s", normalize_error)
            elseif result.overrides[normalized] then
              parse_error = "duplicate OOXML content type override"
            else
              result.overrides[normalized] = content_type
            end
          end
        end
      end
    end,
    end_element = function()
      depth = depth - 1
    end,
  }, options.xml)

  if not ok then
    return nil, err
  end
  if parse_error then
    return nil, parse_error
  end
  if not root_seen then
    return nil, "missing OOXML content types root"
  end

  return result
end

local function content_type_for(content_types, part_name)
  local override = content_types.overrides[part_name]
  if override then return override end

  local extension = part_name:match('%.([^./]+)$')
  return extension and content_types.defaults[extension:lower()] or nil
end

local function parse_relationships(contents, source_part, options)
  local result = {
    list = {},
    by_id = {},
  }
  local depth = 0
  local parse_error
  local root_seen = false

  local ok, err = xml.parse(contents, {
    start_element = function(namespace, name, attributes)
      depth = depth + 1
      if parse_error then return end

      if depth == 1 then
        if name ~= 'Relationships' or not relationships_namespaces[namespace] then
          parse_error = "invalid OOXML relationships root"
        else
          root_seen = true
        end
      elseif depth == 2 and name == 'Relationship' and relationships_namespaces[namespace] then
        local id = get_attr(attributes, 'Id')
        local relation_type = get_attr(attributes, 'Type')
        local target = get_attr(attributes, 'Target')
        local target_mode = get_attr(attributes, 'TargetMode')

        if not id or id == '' or not relation_type or relation_type == '' or
            not target or target == '' then
          parse_error = "invalid OOXML relationship"
          return
        end
        if #target > options.max_target_length then
          parse_error = "OOXML relationship target limit exceeded"
          return
        end
        if target:find('[%z\1-\31]') then
          parse_error = "control character in OOXML relationship target"
          return
        end
        if result.by_id[id] then
          parse_error = "duplicate OOXML relationship id"
          return
        end
        if #result.list >= options.max_relationships then
          parse_error = "OOXML relationship limit exceeded"
          return
        end

        if target_mode and target_mode:lower() ~= 'external' and
            target_mode:lower() ~= 'internal' then
          parse_error = "invalid OOXML relationship target mode"
          return
        end

        local relationship = {
          id = id,
          type = relation_type,
          target = target,
          external = target_mode and target_mode:lower() == 'external' or false,
        }
        if not relationship.external then
          relationship.part_name, parse_error = exports.resolve_part_name(source_part, target)
          if not relationship.part_name then return end
        end

        result.list[#result.list + 1] = relationship
        result.by_id[id] = relationship
      end
    end,
    end_element = function()
      depth = depth - 1
    end,
  }, options.xml)

  if not ok then
    return nil, err
  end
  if parse_error then
    return nil, parse_error
  end
  if not root_seen then
    return nil, "missing OOXML relationships root"
  end

  return result
end

local function content_length(content)
  if type(content) == 'string' then return #content end
  return content:len()
end

local function extract_selected(data, names, options, state)
  if #names == 0 then return {} end
  if state.parts + #names > options.max_parts then
    return nil, "OOXML selected part limit exceeded"
  end

  local remaining = options.max_output - state.output
  if remaining <= 0 then
    return nil, "OOXML output limit exceeded"
  end

  local ok, files, truncated = pcall(archive.unpack, data, 'zip', nil, {
    files = names,
    max_entries = options.max_entries,
    max_files = options.max_parts,
    max_file_size = options.max_file_size,
    max_output = remaining,
    max_ratio = options.max_ratio,
  })
  if not ok then
    return nil, string.format("cannot unpack OOXML package: %s", files)
  end
  if truncated then
    return nil, "OOXML archive extraction limit exceeded"
  end

  local result = {}
  for _, file in ipairs(files) do
    if result[file.name] then
      return nil, string.format("duplicate OOXML part: %s", file.name)
    end
    result[file.name] = file.content
    state.output = state.output + content_length(file.content)
    state.parts = state.parts + 1
  end

  return result
end

local function add_unique(array, seen, value)
  if not seen[value] then
    array[#array + 1] = value
    seen[value] = true
  end
end

exports.open = function(data, requested_options)
  local options = merge_options(requested_options)
  local state = { output = 0, parts = 0 }

  local bootstrap, err = extract_selected(data, {
    '[Content_Types].xml',
    '_rels/.rels',
  }, options, state)
  if not bootstrap then return nil, err end
  if not bootstrap['[Content_Types].xml'] or not bootstrap['_rels/.rels'] then
    return nil, "missing OOXML package metadata"
  end

  local content_types
  content_types, err = parse_content_types(bootstrap['[Content_Types].xml'], options)
  if not content_types then return nil, err end

  local package_relationships
  package_relationships, err = parse_relationships(bootstrap['_rels/.rels'], '', options)
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
    relationships, err = parse_relationships(main_files[main_relationship_part], main_part, options)
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
        parsed_story_relationships, err = parse_relationships(story_files[rels_name], story_name, options)
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
    extracted_bytes = state.output,
    extracted_parts = state.parts,
  }
end

return exports
