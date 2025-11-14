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

-- Default settings (work without any maps)
local settings = {
  enabled = true,
  process_flags = { 'has_user', 'numeric', 'obscured', 'zw_spaces', 'no_tld' },
  checks = {
    user_password = {
      enabled = true,
      length_thresholds = {
        suspicious = 64,
        long = 128,
        very_long = 256
      },

    },
    numeric_ip = {
      enabled = true,
      base_score = 1.5,
      with_user_score = 4.0,
      allow_private_ranges = true,
      private_score = 0.5
    },
    tld = {
      enabled = true,
      builtin_suspicious = { ".tk", ".ml", ".ga", ".cf", ".gq" },
      builtin_score = 3.0,
      missing_tld_score = 2.0
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
  symbols = {
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
  },
  use_whitelist = false,
  custom_checks = {},
  compat_mode = true
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
  local host = url:get_host()

  lua_util.debugm(N, task, "Checking user field length: %d chars", user_len)

  -- Length-based scoring (built-in, no map needed)
  if user_len > cfg.length_thresholds.very_long then
    table.insert(findings, {
      symbol = settings.symbols.user_very_long,
      score = 5.0,
      options = { string.format("%d", user_len) }
    })
  elseif user_len > cfg.length_thresholds.long then
    table.insert(findings, {
      symbol = settings.symbols.user_long,
      score = 3.0,
      options = { string.format("%d", user_len) }
    })
  elseif user_len > cfg.length_thresholds.suspicious then
    table.insert(findings, {
      symbol = settings.symbols.user_password,
      score = 2.0,
      options = { host or "unknown" }
    })
  else
    -- Normal length user
    table.insert(findings, {
      symbol = settings.symbols.user_password,
      score = 2.0,
      options = { host or "unknown" }
    })
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

  lua_util.debugm(N, task, "Checking numeric IP: %s", host)

  -- Check if private IP
  local is_private = host:match("^10%.") or
      host:match("^192%.168%.") or
      host:match("^172%.1[6-9]%.") or
      host:match("^172%.2[0-9]%.") or
      host:match("^172%.3[0-1]%.")

  if is_private and cfg.allow_private_ranges then
    table.insert(findings, {
      symbol = settings.symbols.numeric_private,
      score = cfg.private_score,
      options = { host }
    })
  else
    -- Check if user present (more suspicious)
    if bit.band(flags, url_flags_tab.has_user) ~= 0 then
      table.insert(findings, {
        symbol = settings.symbols.numeric_ip_user,
        score = cfg.with_user_score,
        options = { host }
      })
    else
      table.insert(findings, {
        symbol = settings.symbols.numeric_ip,
        score = cfg.base_score,
        options = { host }
      })
    end
  end

  -- Optional: check IP range map if configured
  if maps.suspicious_ips then
    if maps.suspicious_ips:get_key(host) then
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
        symbol = settings.symbols.no_tld,
        score = cfg.missing_tld_score,
        options = { host }
      })
    end
    return findings
  end

  local tld = url:get_tld()
  if not tld then
    return findings
  end

  -- Check built-in suspicious TLDs (no map needed)
  for _, suspicious_tld in ipairs(cfg.builtin_suspicious) do
    if tld == suspicious_tld or tld:sub(-#suspicious_tld) == suspicious_tld then
      lua_util.debugm(N, task, "URL uses suspicious TLD: %s", tld)
      table.insert(findings, {
        symbol = settings.symbols.suspicious_tld,
        score = cfg.builtin_score,
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

  local url_text = url:get_text()
  local host = url:get_host()

  -- Check validity
  if cfg.check_validity and not rspamd_util.is_valid_utf8(url_text) then
    lua_util.debugm(N, task, "URL has invalid UTF-8")
    table.insert(findings, {
      symbol = settings.symbols.bad_unicode,
      score = 3.0,
      options = { host or "unknown" }
    })
  end

  -- Check zero-width spaces (existing flag)
  if cfg.check_zero_width and bit.band(flags, url_flags_tab.zw_spaces) ~= 0 then
    lua_util.debugm(N, task, "URL contains zero-width spaces")
    table.insert(findings, {
      symbol = settings.symbols.zero_width,
      score = 7.0,
      options = { host or "unknown" }
    })
  end

  -- Check homographs
  if cfg.check_homographs and host then
    if rspamd_util.is_utf_spoofed(host) then
      lua_util.debugm(N, task, "URL uses homograph attack: %s", host)
      table.insert(findings, {
        symbol = settings.symbols.homograph,
        score = 5.0,
        options = { host }
      })
    end
  end

  -- Check RTL override (U+202E)
  if cfg.check_rtl_override and url_text:find("\226\128\174") then
    lua_util.debugm(N, task, "URL contains RTL override")
    table.insert(findings, {
      symbol = settings.symbols.rtl_override,
      score = 6.0,
      options = { host or "unknown" }
    })
  end

  return findings
end

-- Check: URL structure anomalies
function checks.structure_analysis(task, url, cfg)
  local findings = {}
  local url_text = url:get_text()
  local host = url:get_host()

  -- Check multiple @ signs
  if cfg.check_multiple_at then
    local _, at_count = url_text:gsub("@", "")
    if at_count > cfg.max_at_signs then
      lua_util.debugm(N, task, "URL has %d @ signs", at_count)
      table.insert(findings, {
        symbol = settings.symbols.multiple_at,
        score = 3.0,
        options = { string.format("%d", at_count) }
      })
    end
  end

  -- Check backslashes (existing flag indicates obscured)
  if cfg.check_backslash then
    local url_flags_tab = rspamd_url.flags
    local flags = url:get_flags_num()
    if bit.band(flags, url_flags_tab.obscured) ~= 0 and url_text:find("\\") then
      lua_util.debugm(N, task, "URL contains backslashes")
      table.insert(findings, {
        symbol = settings.symbols.backslash,
        score = 2.0,
        options = { host or "unknown" }
      })
    end
  end

  -- Check excessive dots in hostname
  if cfg.check_excessive_dots and host then
    local _, dot_count = host:gsub("%.", "")
    if dot_count > cfg.max_host_dots then
      lua_util.debugm(N, task, "URL hostname has %d dots", dot_count)
      table.insert(findings, {
        symbol = settings.symbols.excessive_dots,
        score = 2.0,
        options = { string.format("%d", dot_count) }
      })
    end
  end

  -- Check URL length
  if cfg.check_length and #url_text > cfg.max_url_length then
    lua_util.debugm(N, task, "URL is very long: %d chars", #url_text)
    table.insert(findings, {
      symbol = settings.symbols.very_long,
      score = 1.5,
      options = { string.format("%d", #url_text) }
    })
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
  -- Get URLs with suspicious flags (using existing flags)
  local suspect_urls = task:get_urls_filtered(settings.process_flags)

  if not suspect_urls or #suspect_urls == 0 then
    return false
  end

  lua_util.debugm(N, task, "Processing %s URLs with suspicious flags", #suspect_urls)

  local total_findings = 0

  for _, url in ipairs(suspect_urls) do
    local url_findings = analyze_url(task, url, settings)

    for _, finding in ipairs(url_findings) do
      task:insert_result(finding.symbol, finding.score, finding.options or {})
      total_findings = total_findings + 1
    end
  end

  -- Backward compatibility: R_SUSPICIOUS_URL
  if settings.compat_mode and total_findings > 0 then
    -- Check if we inserted any symbols
    local has_findings = false
    for _, symbol_name in pairs(settings.symbols) do
      if task:has_symbol(symbol_name) then
        has_findings = true
        break
      end
    end

    if has_findings then
      task:insert_result('R_SUSPICIOUS_URL', 5.0)
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
  for _, symbol_name in pairs(settings.symbols) do
    rspamd_config:register_symbol({
      name = symbol_name,
      type = 'virtual',
      parent = id,
      group = 'url'
    })
  end

  -- Backward compat symbol
  if settings.compat_mode then
    rspamd_config:register_symbol({
      name = 'R_SUSPICIOUS_URL',
      type = 'virtual',
      parent = id,
      score = 5.0,
      group = 'url',
      description = 'Suspicious URL (legacy symbol)'
    })
  end
end
