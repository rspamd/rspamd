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

-- SVG content processor. SVG attachments are XML documents that mail
-- clients and browsers render with a scripting engine, which makes them the
-- container of choice for HTML smuggling and credential phishing. The native
-- extractor pulls out visible text, hyperlinks and remote resources, and
-- counts the scripting / embedding constructs a legitimate picture never
-- needs. Decoded data: payloads (HTML, nested SVG) are fed back into the
-- task so the regular HTML and URL rules see them, and are kept in the part
-- specific (`payloads`: type, content, truncated) so other scanners can treat
-- them as derived targets without going through the task.

local lua_util = require "lua_util"
local rspamd_svg = require "rspamd_svg"
local rspamd_url = require "rspamd_url"
local rspamd_util = require "rspamd_util"

local N = "lua_content"
local exports = {}

local config = {
  enabled = true,
  max_documents = 8,
  processing_timeout = 1.0,
  max_size = 4 * 1024 * 1024,
  max_text = 1024 * 1024,
  max_urls = 512,
  max_payloads = 4,
  max_payload_size = 256 * 1024,
  max_resources = 32,
  inject_payloads = true,
  xml = {
    max_input = 4 * 1024 * 1024,
    max_depth = 128,
    max_tokens = 200000,
    max_attributes = 256,
    max_attribute_length = 4 * 1024 * 1024,
    max_namespace_declarations = 1024,
    max_text = 1024 * 1024,
  },
}

local budget_cache_key = 'lua_content:svg_budget'
local max_nesting = 1

local function configure()
  if not rspamd_config then return end
  local options = rspamd_config:get_all_opt('lua_content')
  if options and options.svg then
    config = lua_util.override_defaults(config, options.svg)
  end
end

local function ensure_state(state)
  state = state or {}
  for _, name in ipairs({ 'documents', 'injected_text', 'injected_urls', 'injected_payloads' }) do
    state[name] = state[name] or 0
  end
  return state
end

local function remaining(limit, used)
  return math.max(0, limit - used)
end

local function deadline_expired(state)
  return state.end_timestamp and rspamd_util.get_ticks() >= state.end_timestamp
end

local function options_for_state(options, state)
  local result = lua_util.shallowcopy(options)
  result.xml = lua_util.shallowcopy(options.xml or {})
  result.xml.end_timestamp = state.end_timestamp or 0
  return result
end

local function content_length(content)
  if type(content) == 'string' then return #content end
  return content:len()
end

local function head_bytes(content, count)
  if content_length(content) < count then return '' end
  if type(content) == 'string' then return content:sub(1, count) end
  return tostring(content:span(1, count))
end

local function is_gzip(content)
  return head_bytes(content, 2) == '\31\139'
end

local function classify_error(err)
  if err:find('DTD', 1, true) then return 'dtd' end
  if err:find('timeout', 1, true) then return 'timeout' end
  if err:find('not an SVG', 1, true) then return 'root' end
  if err:find('limit', 1, true) then return 'limit' end
  if err:find('UTF-8', 1, true) or err:find('convert', 1, true) then return 'encoding' end
  return 'xml'
end

local function suspicious_result(reason, err)
  return {
    tag = 'svg',
    suspicious = true,
    reason = reason,
    error = err,
  }
end

local function extract_text_data(specific)
  return specific.text
end

-- Direct native extraction with the module configuration; used by tests
exports.extract = function(input, requested_options)
  local options = lua_util.override_defaults(config, requested_options or {})
  return rspamd_svg.extract(input, options)
end

local counters = {
  'scripts', 'external_scripts', 'event_handlers', 'javascript_urls', 'foreign_objects',
  'data_uris', 'hyperlinks', 'forms', 'password_inputs', 'meta_refresh',
  'embedded_documents', 'css_urls', 'elements',
}

local function copy_extracted(extracted)
  local result = {
    tag = 'svg',
    extract_text = extract_text_data,
    text = extracted.text,
    urls = extracted.urls,
    resources = extracted.resources,
    data_uri_types = extracted.data_uri_types,
    script_indicators = extracted.script_indicators,
    payloads = extracted.payloads or {},
    doctype = extracted.doctype,
    width = extracted.width,
    height = extracted.height,
    view_box = extracted.view_box,
    nested_documents = 0,
  }
  for _, name in ipairs(counters) do
    result[name] = extracted[name] or 0
  end
  return result
end

-- Fold the indicators of a nested SVG (data:image/svg+xml payload) into the
-- outer document, so the rules see the whole picture.
local function merge_nested(result, nested)
  result.nested_documents = result.nested_documents + 1
  if nested.suspicious then
    result.nested_suspicious = nested.reason
    return
  end
  for _, name in ipairs(counters) do
    result[name] = result[name] + (nested[name] or 0)
  end
  for _, indicator in ipairs(nested.script_indicators or {}) do
    result.script_indicators[#result.script_indicators + 1] = indicator
  end
  for _, uri_type in ipairs(nested.data_uri_types or {}) do
    result.data_uri_types[#result.data_uri_types + 1] = uri_type
  end
  for _, url in ipairs(nested.urls or {}) do
    result.urls[#result.urls + 1] = url
  end
  for _, payload in ipairs(nested.payloads or {}) do
    result.payloads[#result.payloads + 1] = payload
  end
end

local function process_svg(input, mpart, task, nesting)
  nesting = nesting or 0
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
    lua_util.debugm(N, task, 'cannot process SVG: document limit exceeded')
    return suspicious_result('document_limit')
  end
  state.documents = state.documents + 1
  if deadline_expired(state) then
    lua_util.debugm(N, task, 'cannot process SVG: processing timeout')
    return suspicious_result('timeout')
  end

  local content = input
  if is_gzip(content) then
    local ok, decompressed = pcall(rspamd_util.gzip_decompress, content, config.max_size)
    if not ok or not decompressed then
      lua_util.debugm(N, task, 'cannot decompress SVGZ: %s', decompressed)
      return suspicious_result('gzip')
    end
    content = decompressed
  end
  if content_length(content) > config.max_size then
    lua_util.debugm(N, task, 'cannot process SVG: size limit exceeded')
    return suspicious_result('size')
  end

  local options = options_for_state(config, state)
  options.max_text = remaining(config.max_text, state.injected_text)
  options.max_urls = remaining(config.max_urls, state.injected_urls)
  local extracted, err = rspamd_svg.extract(content, options)
  if not extracted then
    lua_util.debugm(N, task, 'cannot extract SVG content: %s', err)
    return suspicious_result(classify_error(err), err)
  end

  local result = copy_extracted(extracted)

  local text_len = extracted.text:len()
  if text_len > 0 and task.inject_part then
    if deadline_expired(state) then
      lua_util.debugm(N, task, 'cannot inject SVG text: processing timeout')
      return suspicious_result('timeout')
    end
    task:inject_part('text', extracted.text, mpart)
    state.injected_text = state.injected_text + text_len
  end

  for i, value in ipairs(extracted.urls) do
    if i % 32 == 1 and deadline_expired(state) then
      lua_util.debugm(N, task, 'stop injecting SVG URLs: processing timeout')
      break
    end
    if state.injected_urls >= config.max_urls then break end
    local url_ok, url = pcall(rspamd_url.create, task:get_mempool(), value, { 'content' })
    if url_ok and url then
      task:inject_url(url, mpart)
      state.injected_urls = state.injected_urls + 1
    end
  end

  for _, payload in ipairs(extracted.payloads or {}) do
    if state.injected_payloads >= config.max_payloads or deadline_expired(state) then
      break
    end
    state.injected_payloads = state.injected_payloads + 1
    if payload.type == 'image/svg+xml' then
      if nesting < max_nesting then
        merge_nested(result, process_svg(payload.content, mpart, task, nesting + 1))
      end
    elseif config.inject_payloads and task.inject_part then
      -- text/html or application/xhtml+xml: let the HTML parser and rules see it
      task:inject_part('html', payload.content, mpart)
    end
  end

  return result
end

exports.process = function(input, mpart, task)
  return process_svg(input, mpart, task, 0)
end

configure()

exports.config = config

return exports
