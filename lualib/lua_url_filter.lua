--[[
Copyright (c) 2025, Vsevolod Stakhov <vsevolod@rspamd.com>

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
-- @module lua_url_filter
-- This module provides fast URL filtering during parsing phase.
-- Called from C code to decide whether to create URL object or reject text.
--]]

local exports = {}

-- Filter result constants
exports.ACCEPT = 0
exports.SUSPICIOUS = 1
exports.REJECT = 2

-- Default settings (work without configuration)
local settings = {
  enabled = true,
  builtin_filters = {
    oversized_user = {
      enabled = true,
      max_length = 512  -- Absolute limit for user field
    },
    basic_unicode = {
      enabled = true,
      reject_invalid_utf8 = true
    },
    garbage_pattern = {
      enabled = true,
      max_at_signs = 20  -- Obvious garbage threshold
    }
  },
  custom_filters = {}
}

-- Built-in filter: Check for extremely long user fields
local function filter_oversized_user(url_text, url_obj, flags, cfg)
  if not url_obj then
    return exports.ACCEPT
  end

  local user = url_obj:get_user()
  if not user then
    return exports.ACCEPT
  end

  local user_len = #user
  if user_len > cfg.max_length then
    -- This is obviously garbage, reject
    return exports.REJECT
  end

  return exports.ACCEPT
end

-- Built-in filter: Check for invalid UTF-8
local function filter_basic_unicode(url_text, url_obj, flags, cfg)
  if not cfg.reject_invalid_utf8 then
    return exports.ACCEPT
  end

  local ok, rspamd_util = pcall(require, "rspamd_util")
  if ok and rspamd_util.is_valid_utf8 then
    if not rspamd_util.is_valid_utf8(url_text) then
      -- Invalid UTF-8, reject
      return exports.REJECT
    end
  end

  return exports.ACCEPT
end

-- Built-in filter: Check for obvious garbage patterns
local function filter_garbage_pattern(url_text, url_obj, flags, cfg)
  -- Count @ signs
  local _, at_count = url_text:gsub("@", "")
  if at_count > cfg.max_at_signs then
    -- Way too many @ signs, this is garbage
    return exports.REJECT
  end

  return exports.ACCEPT
end

-- Main entry point (called from C)
function exports.filter_url(url_text, url_obj, flags)
  if not settings.enabled then
    return exports.ACCEPT
  end

  local result = exports.ACCEPT

  -- Run built-in filters
  if settings.builtin_filters.oversized_user and
     settings.builtin_filters.oversized_user.enabled then
    local r = filter_oversized_user(url_text, url_obj, flags,
                                     settings.builtin_filters.oversized_user)
    if r == exports.REJECT then
      return r
    end
  end

  if settings.builtin_filters.basic_unicode and
     settings.builtin_filters.basic_unicode.enabled then
    local r = filter_basic_unicode(url_text, url_obj, flags,
                                   settings.builtin_filters.basic_unicode)
    if r == exports.REJECT then
      return r
    end
  end

  if settings.builtin_filters.garbage_pattern and
     settings.builtin_filters.garbage_pattern.enabled then
    local r = filter_garbage_pattern(url_text, url_obj, flags,
                                     settings.builtin_filters.garbage_pattern)
    if r == exports.REJECT then
      return r
    end
  end

  -- Run custom filters (if any)
  for name, filter_func in pairs(settings.custom_filters) do
    local ok, r = pcall(filter_func, url_text, url_obj, flags)
    if not ok then
      -- Log error but don't fail
      local rspamd_logger = require "rspamd_logger"
      rspamd_logger.errx("Error in custom URL filter %s: %s", name, r)
    else
      if r == "reject" then
        return exports.REJECT
      elseif r == "suspicious" then
        result = exports.SUSPICIOUS
      end
    end
  end

  return result
end

-- Initialize from configuration
function exports.init(cfg)
  local lua_util = require "lua_util"
  local opts = cfg:get_all_opt('url_filter')
  if opts then
    settings = lua_util.override_defaults(settings, opts)
  end

  local rspamd_logger = require "rspamd_logger"
  rspamd_logger.infox(cfg, "URL filter initialized (enabled=%s)", settings.enabled)
end

-- Allow runtime registration of custom filters
function exports.register_custom_filter(name, func)
  if type(func) ~= 'function' then
    local rspamd_logger = require "rspamd_logger"
    rspamd_logger.errx("Cannot register custom filter %s: not a function", name)
    return false
  end

  settings.custom_filters[name] = func
  local rspamd_logger = require "rspamd_logger"
  rspamd_logger.infox("Registered custom URL filter: %s", name)
  return true
end

return exports
