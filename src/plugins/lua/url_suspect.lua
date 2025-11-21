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
-- @module url_suspect
-- This module performs deep introspection of suspicious URLs.
-- Works with existing URL flags, no new flags needed.
-- Provides multiple specific symbols for different URL issues.
--]]

if confighelp then
  return
end

local N = "url_suspect"
local rspamd_logger = require "rspamd_logger"
local lua_util = require "lua_util"
local rspamd_url = require "rspamd_url"
local rspamd_util = require "rspamd_util"
local bit = require "bit"

-- Symbol names (fixed, not configurable)
local symbols = {
  -- User/password symbols
  user_password = "URL_USER_PASSWORD",
  user_long = "URL_USER_LONG",
  user_very_long = "URL_USER_VERY_LONG",
  -- Numeric IP symbols
  numeric_ip = "URL_NUMERIC_IP",
  numeric_ip_user = "URL_NUMERIC_IP_USER",
  numeric_private = "URL_NUMERIC_PRIVATE_IP",
  -- TLD symbols
  no_tld = "URL_NO_TLD",
  suspicious_tld = "URL_SUSPICIOUS_TLD",
  -- Unicode symbols
  bad_unicode = "URL_BAD_UNICODE",
  homograph = "URL_HOMOGRAPH_ATTACK",
  rtl_override = "URL_RTL_OVERRIDE",
  zero_width = "URL_ZERO_WIDTH_SPACES",
  -- Structure symbols
  multiple_at = "URL_MULTIPLE_AT_SIGNS",
  backslash = "URL_BACKSLASH_PATH",
  excessive_dots = "URL_EXCESSIVE_DOTS",
  very_long = "URL_VERY_LONG"
}

-- Default settings (work without any maps)
local settings = {
  enabled = true,
  process_flags = { 'has_user', 'numeric', 'obscured', 'zw_spaces', 'no_tld' },
  -- DoS protection
  max_urls = 10000,
  checks = {
    user_password = {
      enabled = true,
      length_thresholds = {
        suspicious = 64,
        long = 128,
        very_long = 256
      }
    },
    numeric_ip = {
      enabled = true,
      allow_private_ranges = true
    },
    tld = {
      enabled = true,
      builtin_suspicious = { ".tk", ".ml", ".ga", ".cf", ".gq" }
    },
    unicode = {
      enabled = true,
      check_validity = true,
      check_homographs = true,
      check_rtl_override = true,
      check_zero_width = true
    },
    structure = {
      enabled = true,
      check_multiple_at = true,
      max_at_signs = 2,
      check_backslash = true,
      check_excessive_dots = true,
      max_host_dots = 6,
      check_length = true,
      max_url_length = 2048
    }
  },
  use_whitelist = false,
  custom_checks = {}
}

-- Optional maps (only loaded if enabled)
local maps = {
  whitelist = nil,
  user_patterns = nil,
  user_blacklist = nil,
  suspicious_ips = nil,
  suspicious_tlds = nil,
  suspicious_ports = nil
}



-- Check implementations
local checks = {}

-- Check: User/password in URL
function checks.user_password_analysis(task, url, cfg)
  local findings = {}
  local url_flags_tab = rspamd_url.flags
  local flags = url:get_flags_num()

  -- Check if user field present
  if bit.band(flags, url_flags_tab.has_user) == 0 then
    return findings
  end

  local user = url:get_user()
  if not user then
    return findings
  end

  local user_len = #user

  lua_util.debugm(N, task, "Checking user field length: %d chars", user_len)

  -- Length-based detection (get host only when needed for options)
  if user_len > cfg.length_thresholds.very_long then
    table.insert(findings, {
      symbol = symbols.user_very_long,
      options = { string.format("%d", user_len) }
    })
  elseif user_len > cfg.length_thresholds.long then
    table.insert(findings, {
      symbol = symbols.user_long,
      options = { string.format("%d", user_len) }
    })
  else
    -- Get host only for these cases where we need it in options
    local host = url:get_host()
    if user_len > cfg.length_thresholds.suspicious then
      table.insert(findings, {
        symbol = symbols.user_password,
        options = { host or "unknown" }
      })
    else
      -- Normal length user
      table.insert(findings, {
        symbol = symbols.user_password,
        options = { host or "unknown" }
      })
    end
  end

  -- Optional: check pattern map if configured
  if maps.user_patterns then
    local match = maps.user_patterns:get_key(user)
    if match then
      lua_util.debugm(N, task, "User field matches suspicious pattern")
      -- Could add additional symbol or increase score
    end
  end

  -- Optional: check blacklist if configured
  if maps.user_blacklist then
    if maps.user_blacklist:get_key(user) then
      lua_util.debugm(N, task, "User field is blacklisted")
      -- Could add additional symbol or increase score
    end
  end

  return findings
end

-- Check: Numeric IP as hostname
function checks.numeric_ip_analysis(task, url, cfg)
  local findings = {}
  local url_flags_tab = rspamd_url.flags
  local flags = url:get_flags_num()

  if bit.band(flags, url_flags_tab.numeric) == 0 then
    return findings
  end

  local host = url:get_host()
  if not host then
    return findings
  end

  -- Parse IP address using rspamd_ip for proper checks
  local rspamd_ip = require "rspamd_ip"
  local ip = rspamd_ip.from_string(host)

  if not ip or not ip:is_valid() then
    return findings
  end

  -- Check if private IP using rspamd_ip API
  local is_private = ip:is_local()

  if is_private and cfg.allow_private_ranges then
    table.insert(findings, {
      symbol = symbols.numeric_private,
      options = { host }
    })
  else
    -- Check if user present (more suspicious)
    if bit.band(flags, url_flags_tab.has_user) ~= 0 then
      table.insert(findings, {
        symbol = symbols.numeric_ip_user,
        options = { host }
      })
    else
      table.insert(findings, {
        symbol = symbols.numeric_ip,
        options = { host }
      })
    end
  end

  -- Optional: check IP range map if configured (radix maps work with rspamd_ip)
  if maps.suspicious_ips then
    if maps.suspicious_ips:get_key(ip) then
      lua_util.debugm(N, task, "IP is in suspicious range")
      -- Could add additional penalty
    end
  end

  return findings
end

-- Check: TLD validation
function checks.tld_analysis(task, url, cfg)
  local findings = {}
  local url_flags_tab = rspamd_url.flags
  local flags = url:get_flags_num()
  local host = url:get_host()

  if not host then
    return findings
  end

  -- Check for missing TLD
  if bit.band(flags, url_flags_tab.no_tld) ~= 0 then
    -- Skip if it's a numeric IP (handled separately)
    if bit.band(flags, url_flags_tab.numeric) == 0 then
      lua_util.debugm(N, task, "URL has no TLD: %s", host)
      table.insert(findings, {
        symbol = symbols.no_tld,
        options = { host }
      })
    end
    return findings
  end

  local tld = url:get_tld()
  if not tld then
    return findings
  end

  -- Check built-in suspicious TLDs (5 TLDs, O(n) is fine)
  for _, suspicious_tld in ipairs(cfg.builtin_suspicious) do
    if tld == suspicious_tld or tld:sub(-#suspicious_tld) == suspicious_tld then
      lua_util.debugm(N, task, "URL uses suspicious TLD: %s", tld)
      table.insert(findings, {
        symbol = symbols.suspicious_tld,
        options = { tld }
      })
      break
    end
  end

  -- Optional: check TLD map if configured
  if maps.suspicious_tlds then
    if maps.suspicious_tlds:get_key(tld) then
      lua_util.debugm(N, task, "URL TLD in suspicious map: %s", tld)
      -- Already handled by built-in check, or could add extra penalty
    end
  end

  return findings
end

-- Check: Unicode anomalies
function checks.unicode_analysis(task, url, cfg)
  local findings = {}
  local url_flags_tab = rspamd_url.flags
  local flags = url:get_flags_num()

  -- Check zero-width spaces (flag check only, no string needed)
  if cfg.check_zero_width and bit.band(flags, url_flags_tab.zw_spaces) ~= 0 then
    lua_util.debugm(N, task, "URL contains zero-width spaces")
    table.insert(findings, {
      symbol = symbols.zero_width,
      options = { "zw" }
    })
  end

  -- Get host for homograph/options (host is short, acceptable to intern)
  local host
  if cfg.check_homographs or cfg.check_validity or cfg.check_rtl_override then
    host = url:get_host()
  end

  -- Check homographs on host (much smaller than full URL)
  if cfg.check_homographs and host then
    if rspamd_util.is_utf_spoofed(host) then
      lua_util.debugm(N, task, "URL uses homograph attack: %s", host)
      table.insert(findings, {
        symbol = symbols.homograph,
        options = { host }
      })
    end
  end

  -- Only get full URL text if needed, use rspamd_text to avoid copying
  if cfg.check_validity or cfg.check_rtl_override then
    local url_text = url:get_text(true) -- true = return rspamd_text, not string

    -- Check validity on opaque text
    if cfg.check_validity and url_text and not rspamd_util.is_valid_utf8(url_text) then
      lua_util.debugm(N, task, "URL has invalid UTF-8")
      table.insert(findings, {
        symbol = symbols.bad_unicode,
        options = { host or "unknown" }
      })
    end

    -- Check RTL override (U+202E) using text:find on opaque object
    if cfg.check_rtl_override and url_text then
      local rtl_pos = url_text:find("\226\128\174")
      if rtl_pos then
        lua_util.debugm(N, task, "URL contains RTL override")
        table.insert(findings, {
          symbol = symbols.rtl_override,
          options = { host or "unknown" }
        })
      end
    end
  end

  return findings
end

-- Check: URL structure anomalies
function checks.structure_analysis(task, url, cfg)
  local findings = {}
  local url_flags_tab = rspamd_url.flags
  local flags = url:get_flags_num()

  -- Get host only if needed
  local host
  if cfg.check_excessive_dots or cfg.check_backslash then
    host = url:get_host()
  end

  -- Check excessive dots in hostname (work on host, not full URL)
  if cfg.check_excessive_dots and host then
    local _, dot_count = host:gsub("%.", "")
    if dot_count > cfg.max_host_dots then
      lua_util.debugm(N, task, "URL hostname has %d dots", dot_count)
      table.insert(findings, {
        symbol = symbols.excessive_dots,
        options = { string.format("%d", dot_count) }
      })
    end
  end

  -- Check backslashes using existing obscured flag
  if cfg.check_backslash and bit.band(flags, url_flags_tab.obscured) ~= 0 then
    lua_util.debugm(N, task, "URL contains backslashes")
    table.insert(findings, {
      symbol = symbols.backslash,
      options = { host or "obscured" }
    })
  end

  -- Only get full URL text if length/@ checks are enabled (expensive for long URLs)
  if cfg.check_multiple_at or cfg.check_length then
    local url_text = url:get_text()

    -- Check URL length first (cheapest check, just #)
    if cfg.check_length and #url_text > cfg.max_url_length then
      lua_util.debugm(N, task, "URL is very long: %d chars", #url_text)
      table.insert(findings, {
        symbol = symbols.very_long,
        options = { string.format("%d", #url_text) }
      })
    end

    -- Check multiple @ signs (requires gsub scan)
    if cfg.check_multiple_at then
      local _, at_count = url_text:gsub("@", "")
      if at_count > cfg.max_at_signs then
        lua_util.debugm(N, task, "URL has %d @ signs", at_count)
        table.insert(findings, {
          symbol = symbols.multiple_at,
          options = { string.format("%d", at_count) }
        })
      end
    end
  end

  return findings
end

-- Main analysis function
local function analyze_url(task, url, cfg)
  local all_findings = {}

  -- Optional: check whitelist first
  if cfg.use_whitelist and maps.whitelist then
    local host = url:get_host()
    if host and maps.whitelist:get_key(host) then
      lua_util.debugm(N, task, "URL host is whitelisted: %s", host)
      return all_findings
    end
  end

  -- Run all enabled checks (using built-in logic, no maps required)
  if cfg.checks.user_password and cfg.checks.user_password.enabled then
    local findings = checks.user_password_analysis(task, url, cfg.checks.user_password)
    for _, f in ipairs(findings) do
      table.insert(all_findings, f)
    end
  end

  if cfg.checks.numeric_ip and cfg.checks.numeric_ip.enabled then
    local findings = checks.numeric_ip_analysis(task, url, cfg.checks.numeric_ip)
    for _, f in ipairs(findings) do
      table.insert(all_findings, f)
    end
  end

  if cfg.checks.tld and cfg.checks.tld.enabled then
    local findings = checks.tld_analysis(task, url, cfg.checks.tld)
    for _, f in ipairs(findings) do
      table.insert(all_findings, f)
    end
  end

  if cfg.checks.unicode and cfg.checks.unicode.enabled then
    local findings = checks.unicode_analysis(task, url, cfg.checks.unicode)
    for _, f in ipairs(findings) do
      table.insert(all_findings, f)
    end
  end

  if cfg.checks.structure and cfg.checks.structure.enabled then
    local findings = checks.structure_analysis(task, url, cfg.checks.structure)
    for _, f in ipairs(findings) do
      table.insert(all_findings, f)
    end
  end

  -- Run custom checks (advanced users)
  for name, check_func in pairs(cfg.custom_checks) do
    local ok, findings = pcall(check_func, task, url, cfg)
    if ok and findings then
      if type(findings) == 'table' and findings.symbol then
        table.insert(all_findings, findings)
      end
    else
      rspamd_logger.errx(task, "Error in custom check %s: %s", name, findings)
    end
  end

  return all_findings
end

-- Main callback
local function url_suspect_callback(task)
  local suspect_urls

  -- Determine if we need to check all URLs or just flagged ones
  -- TLD and structure checks don't have corresponding URL flags, so need all URLs
  local need_all_urls = (
      (settings.checks.tld and settings.checks.tld.enabled) or
          (settings.checks.structure and settings.checks.structure.enabled and
              (settings.checks.structure.check_multiple_at or
                  settings.checks.structure.check_excessive_dots or
                  settings.checks.structure.check_length))
  )

  if need_all_urls then
    -- Get all URLs (more expensive, but necessary for TLD/structure checks)
    suspect_urls = task:get_urls(true) -- true = include emails
    lua_util.debugm(N, task, "Processing all %s URLs (TLD/structure checks enabled)",
        suspect_urls and #suspect_urls or 0)
  else
    -- Get only URLs with suspicious flags (faster)
    suspect_urls = task:get_urls_filtered(settings.process_flags)
    lua_util.debugm(N, task, "Processing %s flagged URLs",
        suspect_urls and #suspect_urls or 0)
  end

  if not suspect_urls or #suspect_urls == 0 then
    return false
  end

  -- DoS protection: limit number of URLs to process
  local urls_to_check = #suspect_urls
  if urls_to_check > settings.max_urls then
    rspamd_logger.warnx(task, 'Too many URLs (%d), processing only first %d',
        urls_to_check, settings.max_urls)
    urls_to_check = settings.max_urls
  end

  for i = 1, urls_to_check do
    local url_findings = analyze_url(task, suspect_urls[i], settings)

    for _, finding in ipairs(url_findings) do
      task:insert_result(finding.symbol, 1.0, finding.options or {})
    end
  end

  return false
end

-- Initialize maps (only if configured)
local function init_maps(cfg)
  local lua_maps = require "lua_maps"

  -- Load maps if they are configured (not nil)
  if cfg.whitelist_map then
    maps.whitelist = lua_maps.map_add_from_ucl(
        cfg.whitelist_map, 'set', 'url_suspect_whitelist')
  end

  if cfg.checks.user_password.pattern_map then
    maps.user_patterns = lua_maps.map_add_from_ucl(
        cfg.checks.user_password.pattern_map, 'regexp', 'url_suspect_user_patterns')
  end

  if cfg.checks.user_password.blacklist_map then
    maps.user_blacklist = lua_maps.map_add_from_ucl(
        cfg.checks.user_password.blacklist_map, 'set', 'url_suspect_user_blacklist')
  end

  if cfg.checks.numeric_ip.range_map then
    maps.suspicious_ips = lua_maps.map_add_from_ucl(
        cfg.checks.numeric_ip.range_map, 'radix', 'url_suspect_ip_ranges')
  end

  if cfg.checks.tld.tld_map then
    maps.suspicious_tlds = lua_maps.map_add_from_ucl(
        cfg.checks.tld.tld_map, 'set', 'url_suspect_tlds')
  end

  if cfg.checks.structure.port_map then
    maps.suspicious_ports = lua_maps.map_add_from_ucl(
        cfg.checks.structure.port_map, 'set', 'url_suspect_ports')
  end
end

-- Plugin registration
local opts = rspamd_config:get_all_opt(N)
if opts then
  settings = lua_util.override_defaults(settings, opts)
end

if settings.enabled then
  init_maps(settings)

  local id = rspamd_config:register_symbol({
    name = 'URL_SUSPECT_CHECK',
    type = 'callback',
    callback = url_suspect_callback,
    priority = 10,
    group = 'url',
    flags = 'empty,nice'
  })

  -- Register all symbol names as virtual
  for _, symbol_name in pairs(symbols) do
    rspamd_config:register_symbol({
      name = symbol_name,
      type = 'virtual',
      parent = id,
      group = 'url'
    })
  end
end
