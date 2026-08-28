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

-- A deliberately small XML tokenizer for bounded OOXML parts. It does not
-- implement DTDs or general entities and never resolves external resources.

local rspamd_util = require "rspamd_util"

local exports = {}

local xml_namespace = "http://www.w3.org/XML/1998/namespace"
local xmlns_namespace = "http://www.w3.org/2000/xmlns/"

local default_limits = {
  max_input = 8 * 1024 * 1024,
  max_depth = 64,
  max_tokens = 200000,
  max_attributes = 256,
  max_attribute_length = 64 * 1024,
  max_text = 2 * 1024 * 1024,
}

local function is_space(byte)
  return byte == 0x20 or byte == 0x09 or byte == 0x0a or byte == 0x0d
end

local function is_name_start(byte)
  return byte == 0x3a or byte == 0x5f or
      (byte >= 0x41 and byte <= 0x5a) or
      (byte >= 0x61 and byte <= 0x7a)
end

local function is_name_char(byte)
  return is_name_start(byte) or byte == 0x2d or byte == 0x2e or
      (byte >= 0x30 and byte <= 0x39)
end

local function parse_name(input, pos)
  local start = pos
  local byte = input:byte(pos)

  if not byte or not is_name_start(byte) then
    return nil, pos
  end

  pos = pos + 1
  while is_name_char(input:byte(pos) or -1) do
    pos = pos + 1
  end

  return input:sub(start, pos - 1), pos
end

local function split_qname(qname)
  local colon = qname:find(':', 1, true)

  if not colon then
    return nil, qname
  end

  if colon == 1 or colon == #qname or qname:find(':', colon + 1, true) then
    return nil, nil
  end

  return qname:sub(1, colon - 1), qname:sub(colon + 1)
end

local function valid_xml_codepoint(cp)
  return cp == 0x09 or cp == 0x0a or cp == 0x0d or
      (cp >= 0x20 and cp <= 0xd7ff) or
      (cp >= 0xe000 and cp <= 0xfffd) or
      (cp >= 0x10000 and cp <= 0x10ffff)
end

local function codepoint_to_utf8(cp)
  if not valid_xml_codepoint(cp) then
    return nil
  end

  if cp <= 0x7f then
    return string.char(cp)
  elseif cp <= 0x7ff then
    return string.char(0xc0 + math.floor(cp / 0x40),
        0x80 + (cp % 0x40))
  elseif cp <= 0xffff then
    return string.char(0xe0 + math.floor(cp / 0x1000),
        0x80 + (math.floor(cp / 0x40) % 0x40),
        0x80 + (cp % 0x40))
  end

  return string.char(0xf0 + math.floor(cp / 0x40000),
      0x80 + (math.floor(cp / 0x1000) % 0x40),
      0x80 + (math.floor(cp / 0x40) % 0x40),
      0x80 + (cp % 0x40))
end

local predefined_entities = {
  amp = '&',
  apos = "'",
  gt = '>',
  lt = '<',
  quot = '"',
}

local function decode_entities(value)
  if not value:find('&', 1, true) then
    return value
  end

  local out = {}
  local pos = 1

  while pos <= #value do
    local amp = value:find('&', pos, true)
    if not amp then
      out[#out + 1] = value:sub(pos)
      break
    end

    if amp > pos then
      out[#out + 1] = value:sub(pos, amp - 1)
    end

    local semi = value:find(';', amp + 1, true)
    if not semi or semi - amp > 16 then
      return nil, "unterminated or oversized entity"
    end

    local entity = value:sub(amp + 1, semi - 1)
    local decoded = predefined_entities[entity]

    if not decoded and entity:sub(1, 1) == '#' then
      local cp
      if entity:sub(2, 2):lower() == 'x' then
        cp = tonumber(entity:sub(3), 16)
      else
        cp = tonumber(entity:sub(2), 10)
      end
      decoded = cp and codepoint_to_utf8(cp) or nil
    end

    if not decoded then
      return nil, string.format("unsupported XML entity &%s;", entity)
    end

    out[#out + 1] = decoded
    pos = semi + 1
  end

  return table.concat(out)
end

local function prepare_input(input)
  if input == nil then
    return nil, "missing XML input"
  end

  local value = type(input) == 'string' and input or tostring(input)

  if value:sub(1, 2) == "\255\254" then
    local converted = rspamd_util.to_utf8(value:sub(3), 'UTF-16LE')
    if not converted then
      return nil, "cannot convert UTF-16LE XML"
    end
    value = tostring(converted)
  elseif value:sub(1, 2) == "\254\255" then
    local converted = rspamd_util.to_utf8(value:sub(3), 'UTF-16BE')
    if not converted then
      return nil, "cannot convert UTF-16BE XML"
    end
    value = tostring(converted)
  elseif value:sub(1, 3) == "\239\187\191" then
    value = value:sub(4)
  end

  if rspamd_util.is_valid_utf8 and not rspamd_util.is_valid_utf8(value) then
    return nil, "XML input is not valid UTF-8"
  end
  if value:find('[%z\1-\8\11\12\14-\31]') then
    return nil, "XML input contains an invalid control character"
  end

  return value
end

local function restore_namespaces(namespaces, changes)
  for i = #changes, 1, -1 do
    local change = changes[i]
    if change.had_value then
      namespaces[change.prefix] = change.old_value
    else
      namespaces[change.prefix] = nil
    end
  end
end

local function fail(message, pos)
  return false, string.format("%s at byte %s", message, pos)
end

exports.parse = function(raw_input, handlers, options)
  handlers = handlers or {}
  options = options or {}

  local limits = {}
  for name, value in pairs(default_limits) do
    limits[name] = options[name] or value
  end

  local input, input_error = prepare_input(raw_input)
  if not input then
    return false, input_error
  end
  if #input > limits.max_input then
    return fail("XML input limit exceeded", 1)
  end

  local get_ticks = rspamd_util.get_ticks or os.clock
  local end_timestamp = options.end_timestamp
  if not end_timestamp and options.timeout then
    end_timestamp = get_ticks() + options.timeout
  end

  local namespaces = {
    xml = xml_namespace,
    xmlns = xmlns_namespace,
  }
  local stack = {}
  local pos = 1
  local tokens = 0
  local text_bytes = 0

  local function add_token(at)
    tokens = tokens + 1
    if tokens > limits.max_tokens then
      return fail("XML token limit exceeded", at)
    end
    if end_timestamp and tokens % 256 == 0 and get_ticks() >= end_timestamp then
      return fail("XML processing timeout", at)
    end
    return true
  end

  local function emit_text(value, at, decode)
    if value == '' then
      return true
    end

    if decode then
      local decoded, err = decode_entities(value)
      if not decoded then
        return fail(err, at)
      end
      value = decoded
    end

    text_bytes = text_bytes + #value
    if text_bytes > limits.max_text then
      return fail("XML text limit exceeded", at)
    end

    local ok, err = add_token(at)
    if not ok then
      return ok, err
    end
    if handlers.text then
      handlers.text(value)
    end
    return true
  end

  while pos <= #input do
    if input:sub(pos, pos) ~= '<' then
      local next_tag = input:find('<', pos, true) or (#input + 1)
      local ok, err = emit_text(input:sub(pos, next_tag - 1), pos, true)
      if not ok then
        return ok, err
      end
      pos = next_tag
    elseif input:sub(pos, pos + 3) == '<!--' then
      local close = input:find('-->', pos + 4, true)
      if not close then
        return fail("unterminated XML comment", pos)
      end
      local ok, err = add_token(pos)
      if not ok then
        return ok, err
      end
      pos = close + 3
    elseif input:sub(pos, pos + 8) == '<![CDATA[' then
      local close = input:find(']]>', pos + 9, true)
      if not close then
        return fail("unterminated CDATA section", pos)
      end
      local ok, err = emit_text(input:sub(pos + 9, close - 1), pos, false)
      if not ok then
        return ok, err
      end
      pos = close + 3
    elseif input:sub(pos, pos + 1) == '<?' then
      local close = input:find('?>', pos + 2, true)
      if not close then
        return fail("unterminated processing instruction", pos)
      end
      local ok, err = add_token(pos)
      if not ok then
        return ok, err
      end
      pos = close + 2
    elseif input:sub(pos, pos + 8):lower() == '<!doctype' then
      return fail("XML DTD declarations are not supported", pos)
    elseif input:sub(pos, pos + 1) == '<!' then
      return fail("unsupported XML declaration", pos)
    elseif input:sub(pos, pos + 1) == '</' then
      local qname, after_name = parse_name(input, pos + 2)
      if not qname then
        return fail("invalid XML end element", pos)
      end

      local cursor = after_name
      while is_space(input:byte(cursor) or -1) do
        cursor = cursor + 1
      end
      if input:sub(cursor, cursor) ~= '>' then
        return fail("invalid XML end element", cursor)
      end

      local element = stack[#stack]
      if not element or element.qname ~= qname then
        return fail("mismatched XML end element", pos)
      end

      local ok, err = add_token(pos)
      if not ok then
        return ok, err
      end
      if handlers.end_element then
        handlers.end_element(element.namespace, element.name)
      end
      stack[#stack] = nil
      restore_namespaces(namespaces, element.namespace_changes)
      pos = cursor + 1
    else
      local qname, cursor = parse_name(input, pos + 1)
      if not qname then
        return fail("invalid XML start element", pos)
      end

      local raw_attributes = {}
      local attribute_names = {}
      local self_closing = false
      local closed = false

      while cursor <= #input do
        while is_space(input:byte(cursor) or -1) do
          cursor = cursor + 1
        end

        local current = input:sub(cursor, cursor)
        if current == '>' then
          cursor = cursor + 1
          closed = true
          break
        elseif current == '/' and input:sub(cursor + 1, cursor + 1) == '>' then
          cursor = cursor + 2
          self_closing = true
          closed = true
          break
        end

        local attribute_qname
        attribute_qname, cursor = parse_name(input, cursor)
        if not attribute_qname then
          return fail("invalid XML attribute name", cursor)
        end
        if attribute_names[attribute_qname] then
          return fail("duplicate XML attribute", cursor)
        end
        attribute_names[attribute_qname] = true

        while is_space(input:byte(cursor) or -1) do
          cursor = cursor + 1
        end
        if input:sub(cursor, cursor) ~= '=' then
          return fail("missing XML attribute value", cursor)
        end
        cursor = cursor + 1
        while is_space(input:byte(cursor) or -1) do
          cursor = cursor + 1
        end

        local quote = input:sub(cursor, cursor)
        if quote ~= '"' and quote ~= "'" then
          return fail("unquoted XML attribute value", cursor)
        end
        local value_start = cursor + 1
        local value_end = input:find(quote, value_start, true)
        if not value_end then
          return fail("unterminated XML attribute value", cursor)
        end
        if value_end - value_start > limits.max_attribute_length then
          return fail("XML attribute length limit exceeded", cursor)
        end

        local raw_value = input:sub(value_start, value_end - 1)
        if raw_value:find('<', 1, true) then
          return fail("unescaped less-than sign in XML attribute", value_start)
        end
        local value, decode_error = decode_entities(raw_value)
        if not value then
          return fail(decode_error, value_start)
        end

        raw_attributes[#raw_attributes + 1] = {
          qname = attribute_qname,
          value = value,
        }
        if #raw_attributes > limits.max_attributes then
          return fail("XML attribute limit exceeded", cursor)
        end
        cursor = value_end + 1
      end

      if not closed then
        return fail("unterminated XML start element", pos)
      end

      local namespace_changes = {}
      for _, attribute in ipairs(raw_attributes) do
        local prefix
        if attribute.qname == 'xmlns' then
          prefix = ''
        elseif attribute.qname:sub(1, 6) == 'xmlns:' then
          prefix = attribute.qname:sub(7)
        end

        if prefix then
          if prefix == 'xmlns' or
              (prefix == 'xml' and attribute.value ~= xml_namespace) or
              (prefix ~= 'xml' and attribute.value == xml_namespace) or
              attribute.value == xmlns_namespace then
            return fail("invalid XML namespace declaration", pos)
          end

          namespace_changes[#namespace_changes + 1] = {
            prefix = prefix,
            old_value = namespaces[prefix],
            had_value = namespaces[prefix] ~= nil,
          }
          namespaces[prefix] = attribute.value ~= '' and attribute.value or nil
        end
      end

      local prefix, name = split_qname(qname)
      if not name then
        restore_namespaces(namespaces, namespace_changes)
        return fail("invalid qualified XML element name", pos)
      end
      local namespace = namespaces[prefix or '']
      if prefix and not namespace then
        restore_namespaces(namespaces, namespace_changes)
        return fail("unbound XML element prefix", pos)
      end

      local attributes = {}
      for _, attribute in ipairs(raw_attributes) do
        if attribute.qname ~= 'xmlns' and attribute.qname:sub(1, 6) ~= 'xmlns:' then
          local attribute_prefix, attribute_name = split_qname(attribute.qname)
          if not attribute_name then
            restore_namespaces(namespaces, namespace_changes)
            return fail("invalid qualified XML attribute name", pos)
          end
          local attribute_namespace = attribute_prefix and namespaces[attribute_prefix] or nil
          if attribute_prefix and not attribute_namespace then
            restore_namespaces(namespaces, namespace_changes)
            return fail("unbound XML attribute prefix", pos)
          end
          attributes[#attributes + 1] = {
            namespace = attribute_namespace,
            name = attribute_name,
            qname = attribute.qname,
            value = attribute.value,
          }
        end
      end

      if #stack + 1 > limits.max_depth then
        restore_namespaces(namespaces, namespace_changes)
        return fail("XML depth limit exceeded", pos)
      end

      local ok, err = add_token(pos)
      if not ok then
        restore_namespaces(namespaces, namespace_changes)
        return ok, err
      end
      if handlers.start_element then
        handlers.start_element(namespace, name, attributes)
      end

      if self_closing then
        local end_ok, end_err = add_token(pos)
        if not end_ok then
          restore_namespaces(namespaces, namespace_changes)
          return end_ok, end_err
        end
        if handlers.end_element then
          handlers.end_element(namespace, name)
        end
        restore_namespaces(namespaces, namespace_changes)
      else
        stack[#stack + 1] = {
          qname = qname,
          namespace = namespace,
          name = name,
          namespace_changes = namespace_changes,
        }
      end

      pos = cursor
    end
  end

  if #stack > 0 then
    return fail("unclosed XML element", #input + 1)
  end

  return true
end

return exports
