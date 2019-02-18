--[[
Copyright (c) 2016, Andrew Lewis <nerf@judo.za.org>
Copyright (c) 2017, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

local exports = {}

local E = {}
local lua_util = require "lua_util"
local rspamd_util = require "rspamd_util"
local logger = require "rspamd_logger"

local function check_violation(N, task, domain)
  -- Check for DKIM_REJECT
  local sym_check = 'R_DKIM_REJECT'

  if N == 'arc' then sym_check = 'ARC_REJECT' end
  if task:has_symbol(sym_check) then
    local sym = task:get_symbol(sym_check)
    logger.infox(task, 'skip signing for %s: violation %s found: %s',
        domain, sym_check, sym.options)
    return false
  end

  return true
end

local function insert_or_update_prop(N, task, p, prop, origin, data)
  if #p == 0 then
    local k = {}
    k[prop] = data
    table.insert(p, k)
    lua_util.debugm(N, task, 'add %s "%s" using %s', prop, data, origin)
  else
    for _, k in ipairs(p) do
      if not k[prop] then
        k[prop] = data
        lua_util.debugm(N, task, 'set %s to "%s" using %s', prop, data, origin)
      end
    end
  end
end

local function get_mempool_selectors(N, task)
  local p = {}
  local key_var = "dkim_key"
  local selector_var = "dkim_selector"
  if N == "arc" then
    key_var = "arc_key"
    selector_var = "arc_selector"
  end

  p.key = task:get_mempool():get_variable(key_var)
  p.selector = task:get_mempool():get_variable(selector_var)

  if (not p.key or not p.selector) then
    return false, {}
  end

  lua_util.debugm(N, task, 'override selector and key to %s:%s', p.key, p.selector)
  return true, p
end

local function parse_dkim_http_headers(N, task, settings)
  -- Configure headers
  local headers = {
    sign_header = settings.http_sign_header or "PerformDkimSign",
    sign_on_reject_header = settings.http_sign_on_reject_header_header or 'SignOnAuthFailed',
    domain_header = settings.http_domain_header or 'DkimDomain',
    selector_header = settings.http_selector_header or 'DkimSelector',
    key_header = settings.http_key_header or 'DkimPrivateKey'
  }

  if task:get_request_header(headers.sign_header) then
    local domain = task:get_request_header(headers.domain_header)
    local selector = task:get_request_header(headers.selector_header)
    local key = task:get_request_header(headers.key_header)

    if not (domain and selector and key) then

      logger.errx(task, 'missing required headers to sign email')
      return false,{}
    end

    -- Now check if we need to check the existing auth
    local hdr = task:get_request_header(headers.sign_on_reject_header)
    if not hdr or tostring(hdr) == '0' or tostring(hdr) == 'false' then
      if not check_violation(N, task, domain, selector) then
        return false, {}
      end
    end

    local p = {}
    local k = {
      domain = tostring(domain),
      rawkey = tostring(key),
      selector = tostring(selector),
    }
    table.insert(p, k)
    return true, p
  end

  lua_util.debugm(N, task, 'no sign header %s', headers.sign_header)
  return false,{}
end

local function prepare_dkim_signing(N, task, settings)
  local is_local, is_sign_networks

  if settings.use_http_headers then
    local res,tbl = parse_dkim_http_headers(N, task, settings)

    if not res then
      if not settings.allow_headers_fallback then
        return res,{}
      else
        lua_util.debugm(N, task, 'failed to read http headers, fallback to normal schema')
      end
    else
      return res,tbl
    end
  end

  local auser = task:get_user()
  local ip = task:get_from_ip()

  if ip and ip:is_local() then
    is_local = true
  end

  if settings.auth_only and auser then
    lua_util.debugm(N, task, 'user is authenticated')
  elseif (settings.sign_networks and settings.sign_networks:get_key(ip)) then
    is_sign_networks = true
    lua_util.debugm(N, task, 'mail is from address in sign_networks')
  elseif settings.sign_local and is_local then
    lua_util.debugm(N, task, 'mail is from local address')
  elseif settings.sign_inbound and not is_local and not auser then
    lua_util.debugm(N, task, 'mail was sent to us')
  else
    lua_util.debugm(N, task, 'ignoring unauthenticated mail')
    return false,{}
  end

  local efrom = task:get_from('smtp')
  if not settings.allow_envfrom_empty and
      #(((efrom or E)[1] or E).addr or '') == 0 then
    lua_util.debugm(N, task, 'empty envelope from not allowed')
    return false,{}
  end

  local hfrom = task:get_from('mime')
  if not settings.allow_hdrfrom_multiple and (hfrom or E)[2] then
    lua_util.debugm(N, task, 'multiple header from not allowed')
    return false,{}
  end

  local eto = task:get_recipients(0)

  local dkim_domain
  local hdom = ((hfrom or E)[1] or E).domain
  local edom = ((efrom or E)[1] or E).domain
  local tdom = ((eto or E)[1] or E).domain
  local udom = string.match(auser or '', '.*@(.*)')

  local function get_dkim_domain(dtype)
    if settings[dtype] == 'header' then
      return hdom
    elseif settings[dtype] == 'envelope' then
      return edom
    elseif settings[dtype] == 'auth' then
      return udom
    elseif settings[dtype] == 'recipient' then
      return tdom
    else
      return settings[dtype]:lower()
    end
  end

  if hdom then
    hdom = hdom:lower()
  end
  if edom then
    edom = edom:lower()
  end
  if udom then
    udom = udom:lower()
  end
  if tdom then
    tdom = tdom:lower()
  end

  if settings.use_domain_sign_networks and is_sign_networks then
    dkim_domain = get_dkim_domain('use_domain_sign_networks')
    lua_util.debugm(N, task, 'sign_networks: use domain(%s) for signature: %s',
      settings.use_domain_sign_networks, dkim_domain)
  elseif settings.use_domain_sign_local and is_local then
    dkim_domain = get_dkim_domain('use_domain_sign_local')
    lua_util.debugm(N, task, 'local: use domain(%s) for signature: %s',
      settings.use_domain_sign_local, dkim_domain)
  elseif settings.use_domain_sign_inbound and not is_local and not auser then
    dkim_domain = get_dkim_domain('use_domain_sign_inbound')
    lua_util.debugm(N, task, 'inbound: use domain(%s) for signature: %s',
      settings.use_domain_sign_inbound, dkim_domain)
  elseif settings.use_domain_custom then
    if type(settings.use_domain_custom) == 'string' then
      -- Load custom function
      local loadstring = loadstring or load
      local ret, res_or_err = pcall(loadstring(settings.use_domain_custom))
      if ret then
        if type(res_or_err) == 'function' then
          settings.use_domain_custom = res_or_err
          dkim_domain = settings.use_domain_custom(task)
          lua_util.debugm(N, task, 'use custom domain for signing: %s',
              dkim_domain)
        else
          logger.errx(task, 'cannot load dkim domain custom script: invalid type: %s, expected function',
              type(res_or_err))
          settings.use_domain_custom = nil
        end
      else
        logger.errx(task, 'cannot load dkim domain custom script: %s', res_or_err)
        settings.use_domain_custom = nil
      end
    else
      dkim_domain = settings.use_domain_custom(task)
      lua_util.debugm(N, task, 'use custom domain for signing: %s',
          dkim_domain)
    end
  else
    dkim_domain = get_dkim_domain('use_domain')
    lua_util.debugm(N, task, 'use domain(%s) for signature: %s',
      settings.use_domain, dkim_domain)
  end

  if not dkim_domain then
    lua_util.debugm(N, task, 'could not extract dkim domain')
    return false,{}
  end

  if settings.use_esld then
    dkim_domain = rspamd_util.get_tld(dkim_domain)
    if hdom then
      hdom = rspamd_util.get_tld(hdom)
    end
    if edom then
      edom = rspamd_util.get_tld(edom)
    end
  end

  lua_util.debugm(N, task, 'final DKIM domain: %s', dkim_domain)

  if edom and hdom and not settings.allow_hdrfrom_mismatch and hdom ~= edom then
    if settings.allow_hdrfrom_mismatch_local and is_local then
      lua_util.debugm(N, task, 'domain mismatch allowed for local IP: %1 != %2', hdom, edom)
    elseif settings.allow_hdrfrom_mismatch_sign_networks and is_sign_networks then
      lua_util.debugm(N, task, 'domain mismatch allowed for sign_networks: %1 != %2', hdom, edom)
    else
      lua_util.debugm(N, task, 'domain mismatch not allowed: %1 != %2', hdom, edom)
      return false,{}
    end
  end

  if auser and not settings.allow_username_mismatch then
    if not udom then
      lua_util.debugm(N, task, 'couldnt find domain in username')
      return false,{}
    end
    if settings.use_esld then
      udom = rspamd_util.get_tld(udom)
    end
    if udom ~= dkim_domain then
      lua_util.debugm(N, task, 'user domain mismatch')
      return false,{}
    end
  end

  local p = {}

  if settings.domain[dkim_domain] then
    -- support old style selector/paths
    if settings.domain[dkim_domain].selector or
       settings.domain[dkim_domain].path then
      local k = {}
      k.selector = settings.domain[dkim_domain].selector
      k.key = settings.domain[dkim_domain].path
      table.insert(p, k)
    end
    for _, s in ipairs((settings.domain[dkim_domain].selectors or {})) do
      lua_util.debugm(N, task, 'adding selector: %1', s)
      local k = {}
      k.selector = s.selector
      k.key = s.path
      table.insert(p, k)
    end
  end

  if #p == 0 then
    local ret, k = get_mempool_selectors(N, task)
    if ret then
      table.insert(p, k)
      lua_util.debugm(N, task, 'using mempool selector %s with key %s',
                      k.selector, k.key)
    end
  end

  if settings.selector_map then
    local data = settings.selector_map:get_key(dkim_domain)
    if data then
      insert_or_update_prop(N, task, p, 'selector', 'selector_map', data)
    else
      lua_util.debugm(N, task, 'no selector in map for %s', dkim_domain)
    end
  end

  if settings.path_map then
    local data = settings.path_map:get_key(dkim_domain)
    if data then
      insert_or_update_prop(N, task, p, 'key', 'path_map', data)
    else
      lua_util.debugm(N, task, 'no key in map for %s', dkim_domain)
    end
  end

  if #p == 0 and not settings.try_fallback then
    lua_util.debugm(N, task, 'dkim unconfigured and fallback disabled')
    return false,{}
  end

  if not settings.use_redis then
    insert_or_update_prop(N, task, p, 'key',
        'default path', settings.path)
  end

  insert_or_update_prop(N, task, p, 'selector',
        'default selector', settings.selector)

  if settings.check_violation then
    if not check_violation(N, task, p.domain) then
      return false,{}
    end
  end

  insert_or_update_prop(N, task, p, 'domain', 'dkim_domain',
    dkim_domain)

  return true,p
end

exports.prepare_dkim_signing = prepare_dkim_signing

return exports
