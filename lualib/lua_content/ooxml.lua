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

-- Minimal, bounded Open Packaging Conventions reader plus the shared
-- processing pipeline for OOXML office documents (DOCX, XLSX, PPTX).
-- Only XML parts named by package relationships are extracted from the
-- archive, following a per-format story map that is at most two levels deep.

local archive = require "archive"
local lua_util = require "lua_util"
local rspamd_ooxml = require "rspamd_ooxml"
local rspamd_url = require "rspamd_url"
local rspamd_util = require "rspamd_util"

local N = "lua_content"
local exports = {}

local relationship_bases = {
  "http://schemas.openxmlformats.org/officeDocument/2006/relationships/",
  "http://purl.oclc.org/ooxml/officeDocument/relationships/",
}
local microsoft_relationship_base = "http://schemas.microsoft.com/office/2006/relationships/"

local function expand_relationships(spec)
  local result = {}
  for name, story in pairs(spec) do
    for _, base in ipairs(relationship_bases) do
      result[base .. name] = story
    end
  end
  return result
end

local office_document_relationships = expand_relationships({ officeDocument = true })
local hyperlink_relationships = expand_relationships({ hyperlink = true })

-- A story entry with a `kind` has its content parsed natively; an entry
-- without one is fetched for its relationships only (settings, external links).
local word_story = { kind = 'word' }

local formats = {
  docx = {
    tag = 'docx',
    main_kind = 'word',
    default_story_kind = 'word',
    content_types = {
      ["application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"] = true,
      ["application/vnd.openxmlformats-officedocument.wordprocessingml.template.main+xml"] = true,
      ["application/vnd.ms-word.document.macroenabled.main+xml"] = true,
      ["application/vnd.ms-word.template.macroenabledtemplate.main+xml"] = true,
    },
    stories = expand_relationships({
      header = word_story,
      footer = word_story,
      footnotes = word_story,
      endnotes = word_story,
      settings = {},
    }),
  },
  xlsx = {
    tag = 'xlsx',
    main_kind = 'workbook',
    content_types = {
      ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"] = true,
      ["application/vnd.openxmlformats-officedocument.spreadsheetml.template.main+xml"] = true,
      ["application/vnd.ms-excel.sheet.macroenabled.main+xml"] = true,
      ["application/vnd.ms-excel.template.macroenabled.main+xml"] = true,
      ["application/vnd.ms-excel.addin.macroenabled.main+xml"] = true,
    },
    stories = expand_relationships({
      sharedStrings = { kind = 'shared_strings' },
      worksheet = {
        kind = 'worksheet',
        nested = expand_relationships({ drawing = { kind = 'drawing' } }),
      },
      externalLink = {},
    }),
  },
  pptx = {
    tag = 'pptx',
    content_types = {
      ["application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"] = true,
      ["application/vnd.openxmlformats-officedocument.presentationml.slideshow.main+xml"] = true,
      ["application/vnd.openxmlformats-officedocument.presentationml.template.main+xml"] = true,
      ["application/vnd.ms-powerpoint.presentation.macroenabled.main+xml"] = true,
      ["application/vnd.ms-powerpoint.slideshow.macroenabled.main+xml"] = true,
      ["application/vnd.ms-powerpoint.template.macroenabled.main+xml"] = true,
    },
    stories = expand_relationships({
      slide = {
        kind = 'slide',
        nested = expand_relationships({ notesSlide = { kind = 'slide' } }),
      },
    }),
  },
}
formats.xlsx.stories[microsoft_relationship_base .. 'xlMacrosheet'] = { kind = 'worksheet' }

local formats_by_content_type = {}
for _, format in pairs(formats) do
  for content_type in pairs(format.content_types) do
    formats_by_content_type[content_type] = format
  end
end

local function format_for_content_type(content_type)
  if type(content_type) ~= 'string' then return nil end
  return formats_by_content_type[content_type:lower()]
end

exports.formats = formats

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
  max_external_targets = 16,
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

local budget_cache_key = 'lua_content:ooxml_budget'

local function configure()
  if not rspamd_config then return end
  local options = rspamd_config:get_all_opt('lua_content')
  if options and options.ooxml then
    config = lua_util.override_defaults(config, options.ooxml)
  end
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

local empty_relationships = { list = {}, by_id = {} }

exports.open = function(data, requested_options, requested_state)
  local options = lua_util.override_defaults(config, requested_options or {})
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

  local main_content_type = content_type_for(content_types, main_part)
  local format = format_for_content_type(main_content_type)
  if not format then
    return nil, string.format("unsupported OOXML document type: %s",
        main_content_type or 'unknown')
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

  local relationships = empty_relationships
  if main_files[main_relationship_part] then
    relationships, err = parse_relationships_bounded(
        main_files[main_relationship_part], main_part, options, state)
    if not relationships then return nil, err end
  end

  local parts = {
    [main_part] = main_files[main_part],
  }
  local part_relationships = {
    [main_part] = relationships,
  }
  local kinds = {}
  if format.main_kind then
    kinds[main_part] = format.main_kind
  end
  local seen = { [main_part] = true }
  local truncated = false

  -- Pick the parts a relationship list points at, within the part budget.
  -- Every story costs its relationships part plus, when parsed, the part itself.
  local function select_stories(parent_relationships, selectors, selection)
    for _, relationship in ipairs(parent_relationships.list) do
      if not relationship.external then
        local story = selectors[relationship.type]
        if story and not seen[relationship.part_name] then
          local needed = story.kind and 2 or 1
          if #selection.names + needed > remaining(options.max_parts, state.parts) then
            truncated = true
            break
          end
          seen[relationship.part_name] = true
          local entry = { name = relationship.part_name, story = story, children = {} }
          selection.entries[#selection.entries + 1] = entry
          if story.kind then
            selection.names[#selection.names + 1] = relationship.part_name
          end
          selection.names[#selection.names + 1] = relationship_part_name(relationship.part_name)
          if selection.parent then
            selection.parent.children[#selection.parent.children + 1] = entry
          end
        end
      end
    end
  end

  local function load_stories(selection)
    local files
    files, err = extract_selected(data, selection.names, options, state)
    if not files then return nil, err end
    for _, entry in ipairs(selection.entries) do
      local rels_name = relationship_part_name(entry.name)
      entry.relationships = empty_relationships
      if files[rels_name] then
        entry.relationships, err = parse_relationships_bounded(files[rels_name], entry.name,
            options, state)
        if not entry.relationships then return nil, err end
      end
      part_relationships[entry.name] = entry.relationships
      if entry.story.kind and files[entry.name] then
        parts[entry.name] = files[entry.name]
        kinds[entry.name] = entry.story.kind
        entry.loaded = true
      end
    end
    return true
  end

  local level1 = { entries = {}, names = {} }
  select_stories(relationships, format.stories, level1)
  local ok
  ok, err = load_stories(level1)
  if not ok then return nil, err end

  local level2 = { entries = {}, names = {} }
  for _, entry in ipairs(level1.entries) do
    if entry.story.nested then
      level2.parent = entry
      select_stories(entry.relationships, entry.story.nested, level2)
    end
  end
  level2.parent = nil
  ok, err = load_stories(level2)
  if not ok then return nil, err end

  local story_names = {}
  for _, entry in ipairs(level1.entries) do
    if entry.loaded then
      story_names[#story_names + 1] = entry.name
    end
    for _, child in ipairs(entry.children) do
      if child.loaded then
        story_names[#story_names + 1] = child.name
      end
    end
  end

  return {
    format = format.tag,
    main_part = main_part,
    story_parts = story_names,
    parts = parts,
    kinds = kinds,
    relationships = part_relationships,
    content_types = content_types,
    main_content_type = main_content_type,
    truncated = truncated or nil,
    extracted_bytes = state.output - initial.output,
    extracted_parts = state.parts - initial.parts,
    archive_entries = state.entries - initial.entries,
    relationship_count = state.relationships - initial.relationships,
    content_type_count = state.content_types - initial.content_types,
    xml_tokens = state.xml_tokens - initial.xml_tokens,
  }
end

local function relationship_short_type(relationship_type)
  return relationship_type:match('([^/]+)$') or relationship_type
end

-- Summarise the risk-relevant relationships of an opened package: embedded
-- macros, OLE objects and every non-hyperlink external target.
exports.summarize_relationships = function(package, requested_options)
  local options = lua_util.override_defaults(config, requested_options or {})
  local summary = {
    macros = {},
    ole_objects = 0,
    external_targets = {},
  }
  local macros_seen = {}
  local function add_macro(kind)
    if not macros_seen[kind] then
      macros_seen[kind] = true
      summary.macros[#summary.macros + 1] = kind
    end
  end

  local part_names = lua_util.keys(package.relationships or {})
  table.sort(part_names)
  for _, part_name in ipairs(part_names) do
    local relationships = package.relationships[part_name]
    for _, relationship in ipairs(relationships.list or {}) do
      local short = relationship_short_type(relationship.type)
      if short == 'vbaProject' then
        add_macro('vba')
      elseif short == 'xlMacrosheet' or short == 'xlIntlMacrosheet' then
        add_macro('xlm')
      elseif short == 'oleObject' or short == 'package' then
        summary.ole_objects = summary.ole_objects + 1
      end

      if relationship.external and not hyperlink_relationships[relationship.type] then
        if short == 'attachedTemplate' then
          summary.remote_template = summary.remote_template or relationship.target
        elseif #summary.external_targets < options.max_external_targets then
          summary.external_targets[#summary.external_targets + 1] = {
            type = short,
            target = relationship.target,
            part = part_name,
          }
        end
      end
    end
  end

  return summary
end

-- Extract text and URLs from an opened package. `expected_format` lets a
-- format specific module refuse packages of another type.
exports.extract = function(package, requested_options, requested_state, expected_format)
  local options = lua_util.override_defaults(config, requested_options or {})
  local state = ensure_state(requested_state)
  local format = package.format and formats[package.format]
      or format_for_content_type(package.main_content_type)
  if not format then
    return nil, "unsupported OOXML document type"
  end
  if expected_format and format.tag ~= expected_format then
    return nil, string.format("OOXML package is not a %s document", expected_format:upper())
  end

  local stories = {}
  local kinds = package.kinds or {}
  local function add_story(part_name, default_kind)
    local kind = kinds[part_name] or default_kind
    local contents = package.parts[part_name]
    if kind and contents then
      stories[#stories + 1] = {
        content = contents,
        kind = kind,
        relationships = package.relationships[part_name] or empty_relationships,
      }
    end
  end

  add_story(package.main_part, format.main_kind)
  for _, part_name in ipairs(package.story_parts or {}) do
    add_story(part_name, format.default_story_kind)
  end

  local native_options = options_for_state(options, state)
  native_options.max_text = remaining(options.max_text, state.text)
  native_options.max_urls = remaining(options.max_urls, state.urls)
  native_options.xml.max_tokens = remaining(options.xml.max_tokens, state.xml_tokens)

  local extracted, err, tokens = rspamd_ooxml.extract(stories, native_options)
  state.xml_tokens = state.xml_tokens + (tokens or 0)
  if not extracted then return nil, err end

  state.text = state.text + extracted.text:len()
  state.urls = state.urls + #extracted.urls
  extracted.format = format.tag
  return extracted
end

local function extract_text_data(specific)
  return specific.text
end

local function suspicious_result(tag, reason, package)
  local result = {
    tag = tag,
    suspicious = true,
    reason = reason,
  }
  if package then
    result.relationships = exports.summarize_relationships(package)
  end
  return result
end

-- Process one attachment as an OOXML document. `hint` names the format the
-- MIME type or extension claimed; the package content decides the real one.
exports.process_document = function(input, mpart, task, hint)
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
    lua_util.debugm(N, task, 'cannot process %s: document limit exceeded', hint)
    return suspicious_result(hint, 'document_limit')
  end
  state.documents = state.documents + 1
  if deadline_expired(state) then
    lua_util.debugm(N, task, 'cannot process %s: processing timeout', hint)
    return suspicious_result(hint, 'timeout')
  end

  local options = options_for_state(config, state)

  local package, err = exports.open(input, options, state)
  if not package then
    lua_util.debugm(N, task, 'cannot open %s package: %s', hint, err)
    return suspicious_result(hint, 'package')
  end
  local tag = package.format

  local extracted
  extracted, err = exports.extract(package, options, state)
  if not extracted then
    lua_util.debugm(N, task, 'cannot extract %s content: %s', tag, err)
    return suspicious_result(tag, 'content', package)
  end

  local text_len = extracted.text:len()
  if text_len > 0 and task.inject_part then
    if deadline_expired(state) then
      lua_util.debugm(N, task, 'cannot inject %s text: processing timeout', tag)
      return suspicious_result(tag, 'timeout', package)
    end
    if text_len > remaining(config.max_text, state.injected_text) then
      lua_util.debugm(N, task, 'cannot inject %s text: task text limit exceeded', tag)
      return suspicious_result(tag, 'text_limit', package)
    end
    task:inject_part('text', extracted.text, mpart)
    state.injected_text = state.injected_text + text_len
  end

  for i, value in ipairs(extracted.urls) do
    if i % 32 == 1 and deadline_expired(state) then
      lua_util.debugm(N, task, 'stop injecting %s URLs: processing timeout', tag)
      break
    end
    if state.injected_urls >= config.max_urls then break end
    local url_ok, url = pcall(rspamd_url.create, task:get_mempool(), value, { 'content' })
    if url_ok and url then
      task:inject_url(url, mpart)
      state.injected_urls = state.injected_urls + 1
    end
  end

  local result = {
    tag = tag,
    extract_text = extract_text_data,
    text = extracted.text,
    urls = extracted.urls,
    relationships = exports.summarize_relationships(package, options),
    main_part = package.main_part,
    story_parts = package.story_parts,
    truncated = package.truncated,
    extracted_bytes = package.extracted_bytes,
    extracted_parts = package.extracted_parts,
  }
  if hint ~= tag then
    result.declared_format = hint
  end
  if tag == 'xlsx' then
    result.sheets = extracted.sheets
    result.hidden_sheets = extracted.hidden_sheets
    result.very_hidden_sheets = extracted.very_hidden_sheets
    result.auto_exec_names = extracted.auto_exec_names
  end

  return result
end

configure()

exports.config = config

return exports
