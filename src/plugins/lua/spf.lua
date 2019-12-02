--[[
Copyright (c) 2019, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

local N = "spf"
local lua_util = require "lua_util"
local rspamd_spf = require "rspamd_spf"
local bit = require "bit"

if confighelp then
  rspamd_config:add_example(nil, N,
      'Performs SPF checks',
      [[
spf {
  # Enable module
  enabled = true
  # Number of elements in the cache of parsed SPF records
  spf_cache_size = 2048;
  # Default max expire for an element in this cache
  spf_cache_expire = 1d;
  # Whitelist IPs from checks
  whitelist = "/path/to/some/file";
  # Maximum number of recursive DNS subrequests (e.g. includes chanin length)
  max_dns_nesting = 10;
  # Maximum count of DNS requests per record
  max_dns_requests = 30;
  # Minimum TTL enforced for all elements in SPF records
  min_cache_ttl = 5m;
  # Disable all IPv6 lookups
  disable_ipv6 = false;
}
  ]])
  return
end

local symbols = {
  fail = "R_SPF_FAIL",
  softfail = "R_SPF_SOFTFAIL",
  neutral = "R_SPF_NEUTRAL",
  allow = "R_SPF_ALLOW",
  dnsfail = "R_SPF_DNSFAIL",
  permfail = "R_SPF_PERMFAIL",
  na = "R_SPF_NA",
}

local default_config = {
  spf_cache_size = 2048,
  max_dns_nesting = 10,
  max_dns_requests = 30,
  whitelist = nil,
  min_cache_ttl = 60 * 5,
  disable_ipv6 = false,
  symbols = symbols
}

local local_config = rspamd_config:get_all_opt('spf')

if local_config then
  local_config = lua_util.override_defaults(default_config, local_config)
else
  local_config = default_config
end

local function spf_check_callback(task)
  local function flag_to_symbol(fl)
    if bit.band(fl, rspamd_spf.flags.temp_fail) ~= 0 then
      return local_config.symbols.dnsfail
    elseif bit.band(fl, rspamd_spf.flags.perm_fail) ~= 0 then
      return local_config.symbols.permfail
    elseif bit.band(fl, rspamd_spf.flags.na) ~= 0 then
      return local_config.symbols.na
    end

    return 'SPF_UNKNOWN'
  end

  local function policy_decode(res)
    if res == rspamd_spf.policy.fail then
      return local_config.symbols.fail,'-'
    elseif res == rspamd_spf.policy.pass then
      return local_config.symbols.allow,'+'
    elseif res == rspamd_spf.policy.soft_fail then
      return local_config.symbols.softfail,'~'
    elseif res == rspamd_spf.policy.neutral then
      return local_config.symbols.neutral,'?'
    end

    return 'SPF_UNKNOWN','?'
  end

  local function spf_resolved_cb(record, flags, err)
    if record then
      local result, flag_or_policy, error_or_addr = record:check_ip(task:get_from_ip())

      if result then
        local sym,code = policy_decode(flag_or_policy)
        local opt = string.format('%s%s', code, error_or_addr.str or '???')
        if bit.band(flags, rspamd_spf.flags.cached) ~= 0 then
          opt = opt .. ':c'
        end
        task:insert_result(sym, 1.0, opt)
      else
        local sym = flag_to_symbol(flag_or_policy)
        task:insert_result(sym, 1.0, error_or_addr)
      end
    else
      local sym = flag_to_symbol(flags)
      task:insert_result(sym, 1.0, err)
    end
  end

  rspamd_spf.resolve(task, spf_resolved_cb)
end

-- Register all symbols and init rspamd_spf library
rspamd_spf.config(local_config)
local sym_id = rspamd_config:register_symbol{
  name = 'SPF_CHECK',
  type = 'callback',
  flags = 'fine,empty',
  groups = {'policies','spf'},
  score = 0.0,
  callback = spf_check_callback
}

for _,sym in pairs(local_config.symbols) do
  rspamd_config:register_symbol{
    name = sym,
    type = 'virtual',
    parent = sym_id,
    groups = {'policies', 'spf'},
  }
end


