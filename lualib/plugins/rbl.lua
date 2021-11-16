--[[
Copyright (c) 2020, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

local ts = require("tableshape").types
local lua_maps = require "lua_maps"
local lua_util = require "lua_util"

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
    emails = {},
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
  ['default_exclude_private_ips'] = true,
  ['default_exclude_users'] = false,
  ['default_exclude_local'] = true,
  ['default_no_ip'] = false,
  ['default_dkim_match_from'] = false,
  ['default_selector_flatten'] = true,
}

local return_codes_schema = ts.map_of(
    ts.string / string.upper, -- Symbol name
    (
        ts.array_of(ts.string) +
            (ts.string / function(s)
              return { s }
            end) -- List of IP patterns
    )
)
local return_bits_schema = ts.map_of(
    ts.string / string.upper, -- Symbol name
    (
        ts.array_of(ts.number + ts.string / tonumber) +
            (ts.string / function(s)
              return { tonumber(s) }
            end) +
            (ts.number / function(s)
              return { s }
            end)
    )
)

local rule_schema_tbl = {
  content_urls = ts.boolean:is_optional(),
  disable_monitoring = ts.boolean:is_optional(),
  disabled = ts.boolean:is_optional(),
  dkim = ts.boolean:is_optional(),
  dkim_domainonly = ts.boolean:is_optional(),
  dkim_match_from = ts.boolean:is_optional(),
  emails = ts.boolean:is_optional(),
  emails_delimiter = ts.string:is_optional(),
  emails_domainonly = ts.boolean:is_optional(),
  enabled = ts.boolean:is_optional(),
  exclude_local = ts.boolean:is_optional(),
  exclude_private_ips = ts.boolean:is_optional(),
  exclude_users = ts.boolean:is_optional(),
  from = ts.boolean:is_optional(),
  hash = ts.one_of{"sha1", "sha256", "sha384", "sha512", "md5", "blake2"}:is_optional(),
  hash_format = ts.one_of{"hex", "base32", "base64"}:is_optional(),
  hash_len = (ts.integer + ts.string / tonumber):is_optional(),
  helo = ts.boolean:is_optional(),
  ignore_default = ts.boolean:is_optional(), -- alias
  ignore_defaults = ts.boolean:is_optional(),
  ignore_whitelist = ts.boolean:is_optional(),
  ignore_whitelists = ts.boolean:is_optional(), -- alias
  images = ts.boolean:is_optional(),
  ipv4 = ts.boolean:is_optional(),
  ipv6 = ts.boolean:is_optional(),
  is_whitelist = ts.boolean:is_optional(),
  local_exclude_ip_map = ts.string:is_optional(),
  monitored_address = ts.string:is_optional(),
  no_ip = ts.boolean:is_optional(),
  process_script = ts.string:is_optional(),
  rbl = ts.string,
  rdns = ts.boolean:is_optional(),
  received = ts.boolean:is_optional(),
  received_flags = ts.array_of(ts.string):is_optional(),
  received_max_pos = ts.number:is_optional(),
  received_min_pos = ts.number:is_optional(),
  received_nflags = ts.array_of(ts.string):is_optional(),
  replyto = ts.boolean:is_optional(),
  requests_limit = (ts.integer + ts.string / tonumber):is_optional(),
  require_symbols = (
      ts.array_of(ts.string) + (ts.string / function(s) return {s} end)
  ):is_optional(),
  resolve_ip = ts.boolean:is_optional(),
  return_bits = return_bits_schema:is_optional(),
  return_codes = return_codes_schema:is_optional(),
  returnbits = return_bits_schema:is_optional(),
  returncodes = return_codes_schema:is_optional(),
  selector = ts.one_of{ts.string, ts.table}:is_optional(),
  selector_flatten = ts.boolean:is_optional(),
  symbol = ts.string:is_optional(),
  symbols_prefixes = ts.map_of(ts.string, ts.string):is_optional(),
  unknown = ts.boolean:is_optional(),
  url_compose_map = lua_maps.map_schema:is_optional(),
  url_full_hostname = ts.boolean:is_optional(),
  urls = ts.boolean:is_optional(),
  whitelist = lua_maps.map_schema:is_optional(),
  whitelist_exception = (
      ts.array_of(ts.string) + (ts.string / function(s) return {s} end)
  ):is_optional(),
  checks = ts.array_of(ts.one_of(lua_util.keys(check_types))):is_optional(),
  exclude_checks = ts.array_of(ts.one_of(lua_util.keys(check_types))):is_optional(),
}

local function convert_checks(rule)
  local rspamd_logger = require "rspamd_logger"
  if rule.checks then
    local all_connfilter = true
    local exclude_checks = lua_util.list_to_hash(rule.exclude_checks or {})
    for _,check in ipairs(rule.checks) do
      if not exclude_checks[check] then
        local check_type = check_types[check]
        if check_type.require_argument then
          if not rule[check] then
            rspamd_logger.errx(rspamd_config, 'rbl rule %s has check %s which requires an argument',
                    rule.symbol, check)
            return nil
          end
        end

        rule[check] = check_type

        if not check_type.connfilter then
          all_connfilter = false
        end

        if not check_type then
          rspamd_logger.errx(rspamd_config, 'rbl rule %s has invalid check type: %s',
                  rule.symbol, check)
          return nil
        end
      else
        rspamd_logger.infox(rspamd_config, 'disable check %s in %s: excluded explicitly',
                check, rule.symbol)
      end
    end
    rule.connfilter = all_connfilter
  end

  -- Now check if we have any check enabled at all
  local check_found = false
  for k,_ in pairs(check_types) do
    if type(rule[k]) ~= 'nil' then
      check_found = true
      break
    end
  end

  if not check_found then
    -- Enable implicit `from` check to allow upgrade
    rspamd_logger.warnx(rspamd_config, 'rbl rule %s has no check enabled, enable default `from` check',
        rule.symbol)
    rule.from = true
  end

  return rule
end


-- Add default boolean flags to the schema
for def_k,_ in pairs(default_options) do
  rule_schema_tbl[def_k:sub(#('default_') + 1)] = ts.boolean:is_optional()
end

return {
  check_types = check_types,
  rule_schema = ts.shape(rule_schema_tbl),
  default_options = default_options,
  convert_checks = convert_checks,
}