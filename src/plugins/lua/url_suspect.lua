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
  very_long = "URL_VERY_LONG",
  -- Obfuscated text symbol
  obfuscated_text = "URL_OBFUSCATED_TEXT"
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
      enabled = true
      -- suspicious_tlds_map loaded from config (default: $CONFDIR/maps.d/suspicious_tlds.inc)
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
    },
    obfuscated_text = {
      enabled = true,
      -- DoS protection limits
      max_matches_per_message = 50,
      max_extracted_urls = 20,
      min_match_length = 8,
      max_match_length = 1024,
      -- Context window for extraction
      context_before = 64,
      context_after = 256,
      max_normalize_length = 512,
      -- Pattern toggles
      patterns_enabled = {
        spaced_protocol = true,
        hxxp = true,
        bracket_dots = true,
        word_dots = true,
        html_entities = true
      }
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
    very_long = "URL_VERY_LONG",
    -- Obfuscated text symbol
    obfuscated_text = "URL_OBFUSCATED_TEXT"
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
  suspicious_ports = nil,
  -- Obfuscated text pattern control
  obfuscated_patterns = nil
}

-- Obfuscated text helpers
local function normalize_obfuscated_text(text, max_len)
  max_len = max_len or 512

  -- Hard limit to prevent DoS
  if #text > max_len then
    text = text:sub(1, max_len)
  end

  -- 1. Remove zero-width characters (U+200B, U+200C, U+200D, BOM, soft hyphen)
  text = text:gsub("[\226\128\139\226\128\140\226\128\141\239\187\191\194\173]", "")

  -- 2. HTML entity decode (using C binding for comprehensive entity support)
  local decoded = rspamd_util.decode_html_entities(text)
  if decoded then
    text = tostring(decoded)
  end

  -- 3. Normalize spaced protocol: h t t p s : / / -> https://
  text = text:gsub("[hH]%s+[tT]%s+[tT]%s+[pP]%s*[sS]?%s*:%s*/%s*/", "https://")
  text = text:gsub("[hH]%s+[tT]%s+[tT]%s+[pP]%s*:%s*/%s*/", "http://")

  -- 4. hxxp -> http (case insensitive)
  text = text:gsub("[hH][xX][xX][pP][sS]?", "http")

  -- 5. Deobfuscate dots: [.] (.) {.} -> .
  text = text:gsub("[%[%(%{]%s*%.%s*[%]%)%}]", ".")

  -- 6. Word "dot" or "DOT" -> .
  text = text:gsub("%s+[dD][oO][tT]%s+", ".")

  -- 7. Collapse multiple spaces and slashes
  text = text:gsub("%s+", " ")
  text = text:gsub("/+", "/")

  -- 8. Special unicode dots -> ASCII dot
  text = text:gsub("\226\128\164", ".")  -- U+2024 ONE DOT LEADER
  text = text:gsub("\226\128\167", ".")  -- U+2027 HYPHENATION POINT
  text = text:gsub("\194\183", ".")      -- U+00B7 MIDDLE DOT

  return lua_util.str_trim(text)
end

local function extract_url_from_normalized(text)
  if not text or #text == 0 then
    return nil, nil
  end

  -- Pattern 1: URL with explicit protocol
  local url_with_proto = text:match("https?://[%w%.%-_~:/?#@!$&'()*+,;=%%]+")
  if url_with_proto then
    -- Validate: must have at least a dot in the host part
    local host_part = url_with_proto:match("https?://([^/]+)")
    if host_part and host_part:find("%.") then
      return url_with_proto, "explicit_protocol"
    end
  end

  -- Pattern 2: Naked domain (more strict to avoid false positives)
  -- Must start with word boundary, have valid structure
  local naked = text:match("[%w][%w%-]+%.[%a][%w%-%.]+")
  if naked then
    -- Validate: must have valid TLD (at least 2 chars)
    local tld = naked:match("%.([%a][%w%-]*)$")
    if tld and #tld >= 2 and #tld <= 10 then
      -- Additional check: must not be too many dots (likely random text)
      local _, dot_count = naked:gsub("%.", "")
      if dot_count <= 4 then
        return "http://" .. naked, "naked_domain"
      end
    end
  end

  return nil, nil
end

local function extract_context_window(text, start_pos, end_pos, cfg)
  local window_start = math.max(1, start_pos - cfg.context_before)
  local window_end = math.min(#text, end_pos + cfg.context_after)
  local window_len = window_end - window_start

  -- Apply hard limit
  if window_len > cfg.max_normalize_length then
    window_end = window_start + cfg.max_normalize_length
  end

  return text:sub(window_start, window_end)
end

-- Check implementations
local checks = {}

-- Check: User/password in URL
function checks.user_password_analysis(task, url, cfg)
  local findings = {}
  local flags = url:get_flags()

  -- Check if user field present
  if not flags.has_user then
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
  local flags = url:get_flags()

  if not flags.numeric then
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
    if flags.has_user then
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
  local flags = url:get_flags()
  local host = url:get_host()

  if not host then
    return findings
  end

  -- Check for missing TLD
  if flags.no_tld then
    -- Skip if it's a numeric IP (handled separately)
    if not flags.numeric then
      lua_util.debugm(N, task, "URL has no TLD: %s", host)
      table.insert(findings, {
        symbol = symbols.no_tld,
        options = { host }
      })
    end
    return findings
  end

  local esld = url:get_tld()
  if not esld then
    return findings
  end

  local tld = esld:match("^[^%.]+%.(.+)$") or esld
  lua_util.debugm(N, task, "URL eSLD: %s, TLD: %s", esld, tld)

  -- Check suspicious TLDs map
  if maps.suspicious_tlds then
    -- Check both with and without leading dot for flexibility
    local tld_with_dot = '.' .. tld
    local tld_without_dot = tld
    lua_util.debugm(N, task, "Checking TLDs: with_dot=%s, without_dot=%s", tld_with_dot, tld_without_dot)
    if maps.suspicious_tlds:get_key(tld_with_dot) or maps.suspicious_tlds:get_key(tld_without_dot) then
      lua_util.debugm(N, task, "URL uses suspicious TLD: %s", tld)
      table.insert(findings, {
        symbol = symbols.suspicious_tld,
        options = { tld }
      })
    end
  end

  return findings
end

-- Check: Unicode anomalies
function checks.unicode_analysis(task, url, cfg)
  local findings = {}
  local flags = url:get_flags()

  -- Check zero-width spaces (flag check only, no string needed)
  if cfg.check_zero_width and flags.zw_spaces then
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
    local url_text = url:get_text()
    -- We check if we *really* have backslashes here as obscured flag is ambiguous
    if url_text and url_text:find('\\', 1, true) then
      lua_util.debugm(N, task, "URL contains backslashes")
      table.insert(findings, {
        symbol = symbols.backslash,
        options = { host or "obscured" }
      })
    end
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

  if cfg.checks.tld.suspicious_tlds_map then
    maps.suspicious_tlds = lua_maps.rspamd_map_add_from_ucl(
        cfg.checks.tld.suspicious_tlds_map, 'set', 'url_suspect_suspicious_tlds')
    if not maps.suspicious_tlds then
      rspamd_logger.warnx(rspamd_config, 'failed to load suspicious_tlds_map, TLD check will be disabled')
    end
  end

  if cfg.checks.structure.port_map then
    maps.suspicious_ports = lua_maps.map_add_from_ucl(
        cfg.checks.structure.port_map, 'set', 'url_suspect_ports')
  end

  -- Load obfuscated pattern control map if configured
  if cfg.checks.obfuscated_text and cfg.checks.obfuscated_text.pattern_map then
    maps.obfuscated_patterns = lua_maps.map_add_from_ucl(
        cfg.checks.obfuscated_text.pattern_map, 'set', 'url_suspect_obfuscated_patterns')
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

  -- Register all symbol names as virtual (except obfuscated_text which is handled separately)
  for key, symbol_name in pairs(symbols) do
    if key ~= 'obfuscated_text' then
      rspamd_config:register_symbol({
        name = symbol_name,
        type = 'virtual',
        parent = id,
        group = 'url'
      })
    end
  end
end

-- Obfuscated URL detection in message text
-- Uses rspamd_trie (Hyperscan when available) for fast multi-pattern matching
if settings.enabled and settings.checks.obfuscated_text and settings.checks.obfuscated_text.enabled then
  local obf_cfg = settings.checks.obfuscated_text
  local rspamd_trie = require "rspamd_trie"

  -- Helper: check if pattern is enabled
  local function is_pattern_enabled(pattern_name)
    if maps.obfuscated_patterns then
      return maps.obfuscated_patterns:get_key(pattern_name)
    end
    return obf_cfg.patterns_enabled[pattern_name]
  end

  -- Build pattern list with metadata
  local pattern_list = {}   -- array of pattern strings for trie
  local pattern_meta = {}   -- metadata for each pattern (indexed by pattern position)

  if is_pattern_enabled('spaced_protocol') then
    table.insert(pattern_list, [=[[hH]\s+[tT]\s+[tT]\s+[pP]\s*[sS]?\s*[:\/]]=])
    pattern_meta[#pattern_list] = { name = 'spaced_protocol' }
  end

  if is_pattern_enabled('hxxp') then
    table.insert(pattern_list, [=[[hH][xX][xX][pP][sS]?:\/\/]=])
    pattern_meta[#pattern_list] = { name = 'hxxp' }
  end

  if is_pattern_enabled('bracket_dots') then
    table.insert(pattern_list, [=[[\[\(\{]\s*\.\s*[\]\)\}]]=])
    pattern_meta[#pattern_list] = { name = 'bracket_dots' }
  end

  if is_pattern_enabled('word_dots') then
    table.insert(pattern_list, [=[\w+\s+[dD][oO][tT]\s+\w+]=])
    pattern_meta[#pattern_list] = { name = 'word_dot' }
  end

  if is_pattern_enabled('html_entities') then
    table.insert(pattern_list, [=[&#\d{2,3};[^&]{0,20}&#\d{2,3};]=])
    pattern_meta[#pattern_list] = { name = 'html_entity' }
  end

  if #pattern_list == 0 then
    rspamd_logger.infox(rspamd_config, 'No obfuscated text patterns enabled, skipping registration')
  else
    -- Create trie with regex support
    -- flags: re (regex mode) + icase (case insensitive)
    local trie_flags = rspamd_trie.flags.re + rspamd_trie.flags.icase
    local obf_trie = rspamd_trie.create(pattern_list, trie_flags)

    if not obf_trie then
      rspamd_logger.errx(rspamd_config, 'Failed to create obfuscated URL trie')
    else
      local has_hs = rspamd_trie.has_hyperscan()
      rspamd_logger.infox(rspamd_config, 'Created obfuscated URL trie with %d patterns (hyperscan: %s)',
          #pattern_list, has_hs)

      -- Prefilter callback for obfuscated URL detection
      local function obfuscated_text_prefilter(task)
        local text_parts = task:get_text_parts()
        if not text_parts or #text_parts == 0 then
          return false
        end

        -- DoS protection counters
        local match_count = 0
        local extracted_count = 0

        -- Process a match
        local function process_match(txt, start_pos, end_pos, pattern_idx)
          match_count = match_count + 1
          if match_count > obf_cfg.max_matches_per_message then
            return 1  -- stop matching
          end

          if extracted_count >= obf_cfg.max_extracted_urls then
            return 1  -- stop matching
          end

          local meta = pattern_meta[pattern_idx]
          local obf_type = meta and meta.name or 'unknown'

          -- Extract context window
          local window = extract_context_window(txt, start_pos, end_pos, obf_cfg)
          if #window < obf_cfg.min_match_length then
            return 0  -- continue matching
          end

          lua_util.debugm(N, task, 'Processing %s match at %d-%d', obf_type, start_pos, end_pos)

          -- Normalize and extract URL
          local normalized = normalize_obfuscated_text(window, obf_cfg.max_normalize_length)
          if not normalized or #normalized < obf_cfg.min_match_length then
            return 0
          end

          local extracted_url = extract_url_from_normalized(normalized)
          if not extracted_url then
            return 0
          end

          lua_util.debugm(N, task, 'Extracted URL: %s (type: %s)', extracted_url, obf_type)

          -- Create and inject URL with obscured flag
          local url_obj = rspamd_url.create(task:get_mempool(), extracted_url, {'obscured'})
          if not url_obj then
            return 0
          end

          task:inject_url(url_obj)
          extracted_count = extracted_count + 1

          local snippet = window:sub(1, 50):gsub("%s+", " ")
          task:insert_result(symbols.obfuscated_text, 1.0, {
            string.format("type=%s", obf_type),
            string.format("url=%s", extracted_url:sub(1, 50)),
            string.format("orig=%s", snippet)
          })
          lua_util.debugm(N, task, 'Injected obfuscated URL: %s', extracted_url)

          return 0  -- continue matching
        end

        -- Search each text part using trie
        for _, part in ipairs(text_parts) do
          local content = part:get_content()
          if content and #content > 0 then
            local txt = tostring(content)

            -- Use trie:match with callback and report_start=true for positions
            obf_trie:match(txt, function(pattern_idx, match_pos)
              local start_pos, end_pos
              if type(match_pos) == 'table' then
                start_pos, end_pos = match_pos[1], match_pos[2]
              else
                -- Only end position provided
                end_pos = match_pos
                start_pos = math.max(1, end_pos - obf_cfg.max_match_length)
              end

              return process_match(txt, start_pos, end_pos, pattern_idx)
            end, true)  -- report_start = true
          end
        end

        return false
      end

      -- Register as prefilter for early URL injection
      local prefilter_id = rspamd_config:register_symbol({
        name = symbols.obfuscated_text,
        type = 'prefilter',
        callback = obfuscated_text_prefilter,
        group = 'url',
        score = 5.0,
        description = 'Obfuscated URL found in message text'
      })

      rspamd_logger.infox(rspamd_config, 'Registered obfuscated URL prefilter (id=%s, hyperscan=%s)',
          prefilter_id, has_hs)
    end
  end
end
