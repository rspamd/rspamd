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

local T = require "lua_shape.core"
local lua_maps = require "lua_maps"
local lua_util = require "lua_util"
local PluginSchema = require "lua_shape.plugin_schema"

-- Common RBL plugin definitions

local check_types = {
  from = {
    connfilter = true,
  },
  received = {},
  helo = {
    connfilter = true,
  },
  urls = {},
  content_urls = {},
  numeric_urls = {},
  emails = {},
  images = {},
  replyto = {},
  dkim = {},
  rdns = {
    connfilter = true,
  },
  selector = {
    require_argument = true,
  },
}

local default_options = {
  ['default_enabled'] = true,
  ['default_ipv4'] = true,
  ['default_ipv6'] = true,
  ['default_unknown'] = false,
  ['default_dkim_domainonly'] = true,
  ['default_emails_domainonly'] = false,
  ['default_exclude_users'] = false,
  ['default_exclude_local'] = true,
  ['default_no_ip'] = false,
  ['default_dkim_match_from'] = false,
  ['default_selector_flatten'] = true,
}

local return_codes_schema = T.table({}, {
  open = true,
  key = T.transform(T.string(), string.upper),
  extra = T.one_of({
    T.array(T.string()),
    -- Transform string to array
    T.transform(T.string(), function(val)
      return { val }
    end)
  })
}):doc({ summary = "Map of symbol names to IP patterns" })

local return_bits_schema = T.table({}, {
  open = true,
  key = T.transform(T.string(), string.upper),
  extra = T.one_of({
    T.array(T.one_of({
      T.number(),
      T.transform(T.string(), tonumber)
    })),
    -- Transform string or number to array
    T.one_of({
      T.transform(T.string(), function(val)
        return { tonumber(val) }
      end),
      T.transform(T.number(), function(val)
        return { val }
      end)
    })
  })
}):doc({ summary = "Map of symbol names to bit numbers" })

local rule_schema_tbl = {
  content_urls = T.boolean():optional()
      :doc({ summary = "Check URLs found in message body content" }),
  disable_monitoring = T.boolean():optional()
      :doc({ summary = "Disable automatic monitoring/health checks for this RBL" }),
  disabled = T.boolean():optional()
      :doc({ summary = "Completely disable this RBL rule" }),
  dkim = T.boolean():optional()
      :doc({ summary = "Check DKIM signature domains against this RBL" }),
  dkim_domainonly = T.boolean():optional()
      :doc({ summary = "Use only the domain part of DKIM signatures for lookups" }),
  dkim_match_from = T.boolean():optional()
      :doc({ summary = "Only check DKIM domains that match the From header domain" }),
  emails = T.boolean():optional()
      :doc({ summary = "Check email addresses found in message against this RBL" }),
  emails_delimiter = T.string():optional()
      :doc({ summary = "Delimiter to use when constructing email-based RBL queries" }),
  emails_domainonly = T.boolean():optional()
      :doc({ summary = "Use only the domain part of email addresses for lookups" }),
  enabled = T.boolean():optional()
      :doc({ summary = "Enable this RBL rule" }),
  exclude_local = T.boolean():optional()
      :doc({ summary = "Skip RBL checks for locally originated messages" }),
  exclude_users = T.boolean():optional()
      :doc({ summary = "Skip RBL checks for authenticated users" }),
  from = T.boolean():optional()
      :doc({ summary = "Check the sending IP address (from SMTP envelope) against this RBL" }),
  hash = T.enum({ "sha1", "sha256", "sha384", "sha512", "md5", "blake2" }):optional()
      :doc({ summary = "Hash algorithm to use for RBL queries (for hash-based RBLs)" }),
  hash_format = T.enum({ "hex", "base32", "base64" }):optional()
      :doc({ summary = "Encoding format for hashed RBL queries" }),
  hash_len = T.one_of({ T.integer(), T.transform(T.string(), tonumber) }):optional()
      :doc({ summary = "Truncate hash to this many characters" }),
  helo = T.boolean():optional()
      :doc({ summary = "Check the HELO/EHLO hostname against this RBL" }),
  ignore_default = T.boolean():optional()
      :doc({ summary = "Ignore default settings for this rule (alias for ignore_defaults)" }),
  ignore_defaults = T.boolean():optional()
      :doc({ summary = "Ignore default settings for this rule" }),
  ignore_url_whitelist = T.boolean():optional()
      :doc({ summary = "Do not apply URL whitelist to this RBL" }),
  ignore_whitelist = T.boolean():optional()
      :doc({ summary = "Do not apply global whitelist to this RBL" }),
  ignore_whitelists = T.boolean():optional()
      :doc({ summary = "Do not apply any whitelists to this RBL" }),
  images = T.boolean():optional()
      :doc({ summary = "Check URLs of embedded images against this RBL" }),
  ipv4 = T.boolean():optional()
      :doc({ summary = "Enable lookups for IPv4 addresses" }),
  ipv6 = T.boolean():optional()
      :doc({ summary = "Enable lookups for IPv6 addresses" }),
  is_whitelist = T.boolean():optional()
      :doc({ summary = "Treat this RBL as a whitelist (positive result means whitelisted)" }),
  local_exclude_ip_map = T.string():optional()
      :doc({ summary = "Path to map file containing IPs to exclude from this RBL check" }),
  monitored_address = T.string():optional()
      :doc({ summary = "Specific address to use for RBL health monitoring queries" }),
  no_ip = T.boolean():optional()
      :doc({ summary = "Disable IP-based lookups for this RBL" }),
  process_script = T.string():optional()
      :doc({ summary = "Lua script to process/transform RBL query results" }),
  random_monitored = T.boolean():optional()
      :doc({ summary = "Use random addresses for RBL health monitoring" }),
  rbl = T.string()
      :doc({ summary = "The RBL zone/domain to query (required)" }),
  rdns = T.boolean():optional()
      :doc({ summary = "Check reverse DNS (PTR) hostname of sender IP against this RBL" }),
  received = T.boolean():optional()
      :doc({ summary = "Check IP addresses from Received headers against this RBL" }),
  received_flags = T.array(T.string()):optional()
      :doc({ summary = "Only check Received headers with these flags set" }),
  received_max_pos = T.number():optional()
      :doc({ summary = "Maximum position in Received header chain to check (1 = first hop)" }),
  received_min_pos = T.number():optional()
      :doc({ summary = "Minimum position in Received header chain to check" }),
  received_nflags = T.array(T.string()):optional()
      :doc({ summary = "Only check Received headers without these flags set" }),
  replyto = T.boolean():optional()
      :doc({ summary = "Check Reply-To header domain against this RBL" }),
  requests_limit = T.one_of({ T.integer(), T.transform(T.string(), tonumber) }):optional()
      :doc({ summary = "Maximum number of RBL requests per message for this rule" }),
  require_symbols = T.one_of({
    T.array(T.string()),
    T.transform(T.string(), function(s)
      return { s }
    end)
  }):optional()
      :doc({ summary = "Only perform RBL check if these symbols are present" }),
  resolve_ip = T.boolean():optional()
      :doc({ summary = "Resolve hostnames to IPs before RBL lookup" }),
  return_bits = return_bits_schema:optional()
      :doc({ summary = "Map symbol names to bit positions in RBL response" }),
  return_codes = return_codes_schema:optional()
      :doc({ summary = "Map symbol names to specific RBL return codes/IPs" }),
  returnbits = return_bits_schema:optional()
      :doc({ summary = "Alias for return_bits" }),
  returncodes = return_codes_schema:optional()
      :doc({ summary = "Alias for return_codes" }),
  returncodes_matcher = T.enum({ "equality", "glob", "luapattern", "radix", "regexp" }):optional()
      :doc({ summary = "Method to match return codes: equality, glob, luapattern, radix, or regexp" }),
  selector = T.one_of({ { name = "string", schema = T.string() }, { name = "table", schema = T.table({}, { open = true }) } }):optional()
      :doc({ summary = "Selector expression to extract custom data for RBL lookup" }),
  selector_flatten = T.boolean():optional()
      :doc({ summary = "Flatten selector results into individual lookups" }),
  symbol = T.string():optional()
      :doc({ summary = "Symbol name to register for this RBL rule" }),
  symbols_prefixes = T.table({}, { open = true, extra = T.string() }):optional()
      :doc({ summary = "Prefix mappings for generated symbol names" }),
  unknown = T.boolean():optional()
      :doc({ summary = "Check IPs with unknown/missing PTR records" }),
  url_compose_map = lua_maps.map_schema:optional()
      :doc({ summary = "Map to compose/rewrite URLs before RBL lookup" }),
  url_full_hostname = T.boolean():optional()
      :doc({ summary = "Use full hostname (not just registered domain) for URL lookups" }),
  url_whitelist = lua_maps.map_schema:optional()
      :doc({ summary = "Map of URLs to exclude from this RBL check" }),
  urls = T.boolean():optional()
      :doc({ summary = "Check URLs found in message against this RBL" }),
  whitelist = lua_maps.map_schema:optional()
      :doc({ summary = "Map of IPs/domains to exclude from this RBL check" }),
  whitelist_exception = T.one_of({
    T.array(T.string()),
    T.transform(T.string(), function(s)
      return { s }
    end)
  }):optional()
      :doc({ summary = "Symbols that bypass the whitelist" }),
  checks = T.array(T.enum(lua_util.keys(check_types))):optional()
      :doc({ summary = "List of check types to enable: from, received, helo, urls, emails, dkim, rdns, etc." }),
  exclude_checks = T.array(T.enum(lua_util.keys(check_types))):optional()
      :doc({ summary = "List of check types to explicitly disable" }),
}

local function convert_checks(rule, name)
  local rspamd_logger = require "rspamd_logger"
  if rule.checks then
    local all_connfilter = true
    local exclude_checks = lua_util.list_to_hash(rule.exclude_checks or {})
    for _, check in ipairs(rule.checks) do
      if not exclude_checks[check] then
        local check_type = check_types[check]
        if check_type.require_argument then
          if not rule[check] then
            rspamd_logger.errx(rspamd_config, 'rbl rule %s has check %s which requires an argument',
                name, check)
            return nil
          end
        end

        if not check_type.connfilter then
          all_connfilter = false
        end

        if not check_type then
          rspamd_logger.errx(rspamd_config, 'rbl rule %s has invalid check type: %s',
              name, check)
          return nil
        end

        rule[check] = true
      else
        rspamd_logger.infox(rspamd_config, 'disable check %s in %s: excluded explicitly',
            check, name)
      end
    end
    rule.connfilter = all_connfilter
  end

  -- Now check if we have any check enabled at all
  local check_found = false
  for k, _ in pairs(check_types) do
    if type(rule[k]) ~= 'nil' then
      check_found = true
      break
    end
  end

  if not check_found then
    -- Enable implicit `from` check to allow upgrade
    rspamd_logger.warnx(rspamd_config, 'rbl rule %s has no check enabled, enable default `from` check',
        name)
    rule.from = true
  end

  if rule.returncodes and not rule.returncodes_matcher then
    for _, v in pairs(rule.returncodes) do
      for _, e in ipairs(v) do
        if e:find('[%%%[]') then
          rspamd_logger.warn(rspamd_config, 'implicitly enabling luapattern returncodes_matcher for rule %s', name)
          rule.returncodes_matcher = 'luapattern'
          break
        end
      end
      if rule.returncodes_matcher then
        break
      end
    end
  end

  return rule
end


-- Add default boolean flags to the schema
for def_k, _ in pairs(default_options) do
  rule_schema_tbl[def_k:sub(#('default_') + 1)] = T.boolean():optional()
end

local rule_schema = T.table(rule_schema_tbl):doc({ summary = "RBL rule configuration schema" })

local plugin_schema = T.table({
  enabled = T.boolean():optional()
      :doc({ summary = "Enable or disable the RBL module" }),
  disable_monitoring = T.boolean():optional()
      :doc({ summary = "Disable health monitoring for all RBLs" }),
  local_exclude_ip_map = lua_maps.map_schema:optional()
      :doc({ summary = "Global map of IPs to exclude from all RBL checks" }),
  default_enabled = T.boolean():optional()
      :doc({ summary = "Default value for enabled option in rules" }),
  default_ipv4 = T.boolean():optional()
      :doc({ summary = "Default value for ipv4 option in rules" }),
  default_ipv6 = T.boolean():optional()
      :doc({ summary = "Default value for ipv6 option in rules" }),
  default_unknown = T.boolean():optional()
      :doc({ summary = "Default value for unknown option in rules" }),
  default_dkim_domainonly = T.boolean():optional()
      :doc({ summary = "Default value for dkim_domainonly option in rules" }),
  default_emails_domainonly = T.boolean():optional()
      :doc({ summary = "Default value for emails_domainonly option in rules" }),
  default_exclude_users = T.boolean():optional()
      :doc({ summary = "Default value for exclude_users option in rules" }),
  default_exclude_local = T.boolean():optional()
      :doc({ summary = "Default value for exclude_local option in rules" }),
  default_no_ip = T.boolean():optional()
      :doc({ summary = "Default value for no_ip option in rules" }),
  default_dkim_match_from = T.boolean():optional()
      :doc({ summary = "Default value for dkim_match_from option in rules" }),
  default_selector_flatten = T.boolean():optional()
      :doc({ summary = "Default value for selector_flatten option in rules" }),
  default_received_flags = T.array(T.string()):optional()
      :doc({ summary = "Default received flags for all rules" }),
  default_received_nflags = T.array(T.string()):optional()
      :doc({ summary = "Default received negative flags for all rules" }),
}, {
  open = true,
  extra = rule_schema:optional()
      :doc({ summary = "RBL rule definition keyed by rule name" }),
}):doc({ summary = "RBL module configuration" })

PluginSchema.register("plugins.rbl.rule", rule_schema)
PluginSchema.register("plugins.rbl", plugin_schema)

return {
  check_types = check_types,
  rule_schema = rule_schema,
  default_options = default_options,
  convert_checks = convert_checks,
}
