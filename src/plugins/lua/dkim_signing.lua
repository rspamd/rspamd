--[[
Copyright (c) 2016, Andrew Lewis <nerf@judo.za.org>
Copyright (c) 2016, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

local rspamd_logger = require "rspamd_logger"
local rspamd_util = require "rspamd_util"

local settings = {
  allow_envfrom_empty = true,
  allow_hdrfrom_mismatch = false,
  allow_hdrfrom_multiple = false,
  allow_username_mismatch = false,
  auth_only = true,
  domain = {},
  path = string.format('%s/%s/%s', rspamd_paths['DBDIR'], 'dkim', '$domain.$selector.key'),
  selector = 'dkim',
  symbol = 'DKIM_SIGNED',
  try_fallback = true,
  use_domain = 'header',
  use_esld = true,
}

local E = {}
local N = 'dkim_signing'

local function dkim_signing_cb(task)
  local auser = task:get_user()
  if settings.auth_only and not auser then
    if not (settings.sign_networks and settings.sign_networks:get_key(task:get_from_ip())) then
      rspamd_logger.debugm(N, task, 'ignoring unauthenticated user')
      return
    else
      rspamd_logger.debugm(N, task, 'mail is from address in sign_networks')
    end
  end
  local efrom = task:get_from('smtp')
  if not settings.allow_envfrom_empty and
      #(((efrom or E)[1] or E).addr or '') == 0 then
    rspamd_logger.debugm(N, task, 'empty envelope from not allowed')
    return false
  end
  local hfrom = task:get_from('mime')
  if not settings.allow_hdrfrom_multiple and hfrom[2] then
    rspamd_logger.debugm(N, task, 'multiple header from not allowed')
    return false
  end
  local dkim_domain
  local hdom = ((hfrom or E)[1] or E).domain
  local edom = ((efrom or E)[1] or E).domain
  if settings.use_domain == 'header' then
    dkim_domain = hdom
  else
    dkim_domain = edom
  end
  if not dkim_domain then
    rspamd_logger.debugm(N, task, 'could not extract dkim domain')
    return false
  end
  if settings.use_esld then
    dkim_domain = rspamd_util.get_tld(dkim_domain)
  end
  if not settings.allow_hdrfrom_mismatch and hdom ~= edom then
    rspamd_logger.debugm(N, task, 'domain mismatch not allowed: %1 != %2', hdom, edom)
    return false
  end
  if not settings.allow_username_mismatch then
    local udom = string.match(auser, '.*@(.*)')
    if not udom then
      rspamd_logger.debugm(N, task, 'couldnt find domain in username')
      return false
    end
    if settings.use_esld then
      udom = rspamd_util.get_tld(udom)
    end
    if udom ~= dkim_domain then
      rspamd_logger.debugm(N, task, 'user domain mismatch')
      return false
    end
  end
  local p = {}
  if settings.domain[dkim_domain] then
    p.selector = (settings.domain[dkim_domain] or E).selector
    p.key = (settings.domain[dkim_domain] or E).key
  end
  if not (p.key and p.selector) and not settings.try_fallback then
    rspamd_logger.debugm(N, task, 'dkim unconfigured and fallback disabled')
    return false
  end
  if not p.key then
    p.key = settings.path
  end
  if not p.selector then
    p.selector = settings.selector
  end
  p.key = string.gsub(p.key, '$selector', p.selector)
  p.key = string.gsub(p.key, '$domain', dkim_domain)
  p.domain = dkim_domain
  return rspamd_plugins.dkim.sign(task, p)
end

local opts =  rspamd_config:get_all_opt('dkim_signing')
if not opts then return end
for k,v in pairs(opts) do
  if k == 'sign_networks' then
    settings[k] = rspamd_map_add(N, k, 'radix', 'DKIM signing networks')
  else
    settings[k] = v
  end
end
if settings.use_domain ~= 'header' and settings.use_domain ~= 'envelope' then
  rspamd_logger.errx(rspamd_config, "Value for 'use_domain' is invalid")
  settings.use_domain = 'header'
end

rspamd_config:register_symbol({
  name = settings['symbol'],
  callback = dkim_signing_cb
})
