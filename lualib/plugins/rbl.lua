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
  key = T.transform(T.string(), function(val)
    if type(val) == "string" then
      return string.upper(val)
    end
    return val
  end),
  extra = T.one_of({
    T.array(T.string()),
    -- Transform string to array, inner schema validates the result
    T.transform(T.array(T.string()), function(val)
      if type(val) == "string" then
        return { val }
      end
      return val
    end)
  })
}):doc({ summary = "Map of symbol names to IP patterns" })

local return_bits_schema = T.table({}, {
  open = true,
  key = T.transform(T.string(), function(val)
    if type(val) == "string" then
      return string.upper(val)
    end
    return val
  end),
  extra = T.one_of({
    T.array(T.one_of({
      T.number(),
      T.transform(T.number(), function(val)
        if type(val) == "string" then
          return tonumber(val)
        end
        return val
      end)
    })),
    -- Transform string or number to array, inner schema validates the result
    T.transform(T.array(T.number()), function(val)
      if type(val) == "string" then
        return { tonumber(val) }
      elseif type(val) == "number" then
        return { val }
      end
      return val
    end)
  })
}):doc({ summary = "Map of symbol names to bit numbers" })

local rule_schema_tbl = {
  content_urls = T.boolean():optional(),
  disable_monitoring = T.boolean():optional(),
  disabled = T.boolean():optional(),
  dkim = T.boolean():optional(),
  dkim_domainonly = T.boolean():optional(),
  dkim_match_from = T.boolean():optional(),
  emails = T.boolean():optional(),
  emails_delimiter = T.string():optional(),
  emails_domainonly = T.boolean():optional(),
  enabled = T.boolean():optional(),
  exclude_local = T.boolean():optional(),
  exclude_users = T.boolean():optional(),
  from = T.boolean():optional(),
  hash = T.enum({ "sha1", "sha256", "sha384", "sha512", "md5", "blake2" }):optional(),
  hash_format = T.enum({ "hex", "base32", "base64" }):optional(),
  hash_len = T.one_of({ T.integer(), T.transform(T.string(), tonumber) }):optional(),
  helo = T.boolean():optional(),
  ignore_default = T.boolean():optional(),
  ignore_defaults = T.boolean():optional(),
  ignore_url_whitelist = T.boolean():optional(),
  ignore_whitelist = T.boolean():optional(),
  ignore_whitelists = T.boolean():optional(),
  images = T.boolean():optional(),
  ipv4 = T.boolean():optional(),
  ipv6 = T.boolean():optional(),
  is_whitelist = T.boolean():optional(),
  local_exclude_ip_map = T.string():optional(),
  monitored_address = T.string():optional(),
  no_ip = T.boolean():optional(),
  process_script = T.string():optional(),
  random_monitored = T.boolean():optional(),
  rbl = T.string(),
  rdns = T.boolean():optional(),
  received = T.boolean():optional(),
  received_flags = T.array(T.string()):optional(),
  received_max_pos = T.number():optional(),
  received_min_pos = T.number():optional(),
  received_nflags = T.array(T.string()):optional(),
  replyto = T.boolean():optional(),
  requests_limit = T.one_of({ T.integer(), T.transform(T.string(), tonumber) }):optional(),
  require_symbols = T.one_of({
    T.array(T.string()),
    T.transform(T.string(), function(s)
      return { s }
    end)
  }):optional(),
  resolve_ip = T.boolean():optional(),
  return_bits = return_bits_schema:optional(),
  return_codes = return_codes_schema:optional(),
  returnbits = return_bits_schema:optional(),
  returncodes = return_codes_schema:optional(),
  returncodes_matcher = T.enum({ "equality", "glob", "luapattern", "radix", "regexp" }):optional(),
  selector = T.one_of({ { name = "string", schema = T.string() }, { name = "table", schema = T.table({}, { open = true }) } }):optional(),
  selector_flatten = T.boolean():optional(),
  symbol = T.string():optional(),
  symbols_prefixes = T.table({}, { open = true, extra = T.string() }):optional(),
  unknown = T.boolean():optional(),
  url_compose_map = lua_maps.map_schema:optional(),
  url_full_hostname = T.boolean():optional(),
  url_whitelist = lua_maps.map_schema:optional(),
  urls = T.boolean():optional(),
  whitelist = lua_maps.map_schema:optional(),
  whitelist_exception = T.one_of({
    T.array(T.string()),
    T.transform(T.string(), function(s)
      return { s }
    end)
  }):optional(),
  checks = T.array(T.enum(lua_util.keys(check_types))):optional(),
  exclude_checks = T.array(T.enum(lua_util.keys(check_types))):optional(),
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

return {
  check_types = check_types,
  rule_schema = T.table(rule_schema_tbl):doc({ summary = "RBL rule configuration schema" }),
  default_options = default_options,
  convert_checks = convert_checks,
}
