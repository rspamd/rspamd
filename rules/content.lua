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

local lua_content = require "lua_content"

local function process_pdf_specific(task, part, specific)
  local suspicious_factor = 0
  if specific.encrypted then
    task:insert_result('PDF_ENCRYPTED', 1.0, part:get_filename() or 'unknown')
    suspicious_factor = suspicious_factor + 0.1
    if specific.openaction then
      suspicious_factor = suspicious_factor + 0.5
    end
  end

  if specific.scripts then
    task:insert_result('PDF_JAVASCRIPT', 1.0, part:get_filename() or 'unknown')
    suspicious_factor = suspicious_factor + 0.1
  end

  if specific.suspicious then
    suspicious_factor = suspicious_factor + specific.suspicious
  end

  if suspicious_factor > 0.5 then
    if suspicious_factor > 1.0 then
      suspicious_factor = 1.0
    end
    task:insert_result('PDF_SUSPICIOUS', suspicious_factor, part:get_filename() or 'unknown')
  end

  if specific.long_trailer then
    task:insert_result('PDF_LONG_TRAILER', 1.0, string.format('%s:%d',
        part:get_filename() or 'unknown', specific.long_trailer))
  end
  if specific.many_objects then
    task:insert_result('PDF_MANY_OBJECTS', 1.0, string.format('%s:%d',
        part:get_filename() or 'unknown', specific.many_objects))
  end
  if specific.timeout_processing then
    task:insert_result('PDF_TIMEOUT', 1.0, string.format('%s:%.3f',
        part:get_filename() or 'unknown', specific.timeout_processing))
  end
end

local ooxml_prefixes = {
  docx = 'DOCX',
  xlsx = 'XLSX',
  pptx = 'PPTX',
}
local max_external_data_options = 8
local max_target_option_length = 128

local function trim_target(target)
  if #target > max_target_option_length then
    return target:sub(1, max_target_option_length) .. '...'
  end
  return target
end

local function process_ooxml_relationships(task, filename, specific)
  local relationships = specific.relationships
  if not relationships then return end

  local macros = {}
  for _, kind in ipairs(relationships.macros or {}) do
    macros[#macros + 1] = kind
  end
  for _, name in ipairs(specific.auto_exec_names or {}) do
    macros[#macros + 1] = name
  end
  if #macros > 0 then
    task:insert_result('OOXML_MACROS', 1.0,
        string.format('%s:%s', filename, table.concat(macros, ',')))
  end

  if (relationships.ole_objects or 0) > 0 then
    task:insert_result('OOXML_OLE_OBJECT', 1.0,
        string.format('%s:%d', filename, relationships.ole_objects))
  end

  if relationships.remote_template then
    task:insert_result('OOXML_REMOTE_TEMPLATE', 1.0,
        string.format('%s:%s', filename, trim_target(relationships.remote_template)))
  end

  local external_targets = relationships.external_targets or {}
  for i, target in ipairs(external_targets) do
    if i > max_external_data_options then break end
    task:insert_result('OOXML_EXTERNAL_DATA', 1.0,
        string.format('%s:%s=%s', filename, target.type, trim_target(target.target)))
  end
end

local function process_ooxml_specific(task, part, specific)
  local filename = part:get_filename() or 'unknown'
  local prefix = ooxml_prefixes[specific.tag]

  process_ooxml_relationships(task, filename, specific)

  if specific.suspicious then
    task:insert_result(prefix .. '_SUSPICIOUS', 1.0,
        string.format('%s:%s', filename, specific.reason or 'unknown'))
    return
  end

  task:insert_result(prefix .. '_CONTENT', 1.0, filename)
  if specific.urls and #specific.urls > 0 then
    task:insert_result(prefix .. '_EXTERNAL_LINKS', 1.0,
        string.format('%s:%s', filename, #specific.urls))
  end
end

local tags_processors = {
  pdf = process_pdf_specific,
  docx = process_ooxml_specific,
  xlsx = process_ooxml_specific,
  pptx = process_ooxml_specific,
}

local function process_specific_cb(task)
  local parts = task:get_parts() or {}

  for _, p in ipairs(parts) do
    local data = lua_content.get_specific(p, task)

    if data and type(data) == 'table' and data.tag then
      if tags_processors[data.tag] then
        tags_processors[data.tag](task, p, data)
      end
    end
  end
end

local id = rspamd_config:register_symbol {
  type = 'callback',
  name = 'SPECIFIC_CONTENT_CHECK',
  callback = process_specific_cb
}

rspamd_config:register_symbol {
  type = 'virtual',
  name = 'PDF_ENCRYPTED',
  parent = id,
  groups = { "content", "pdf" },
}

for tag, prefix in pairs(ooxml_prefixes) do
  for _, suffix in ipairs({ 'CONTENT', 'EXTERNAL_LINKS', 'SUSPICIOUS' }) do
    rspamd_config:register_symbol {
      type = 'virtual',
      name = prefix .. '_' .. suffix,
      parent = id,
      groups = { "content", tag },
    }
  end
end

for _, name in ipairs({
  'OOXML_MACROS', 'OOXML_OLE_OBJECT', 'OOXML_REMOTE_TEMPLATE', 'OOXML_EXTERNAL_DATA',
}) do
  rspamd_config:register_symbol {
    type = 'virtual',
    name = name,
    parent = id,
    groups = { "content", "ooxml" },
  }
end
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'PDF_JAVASCRIPT',
  parent = id,
  groups = { "content", "pdf" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'PDF_SUSPICIOUS',
  parent = id,
  groups = { "content", "pdf" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'PDF_LONG_TRAILER',
  parent = id,
  groups = { "content", "pdf" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'PDF_MANY_OBJECTS',
  parent = id,
  groups = { "content", "pdf" },
}
rspamd_config:register_symbol {
  type = 'virtual',
  name = 'PDF_TIMEOUT',
  parent = id,
  groups = { "content", "pdf" },
}
