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
local fun = require "fun"

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
  local is_local, is_sign_networks, is_authed

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

  if settings.sign_condition and type(settings.sign_condition) == 'function' then
    -- Use sign condition only
    local ret = settings.sign_condition(task)

    if not ret then
      return false,{}
    end

    if ret[1] then
      return true,ret
    else
      return true,{ret}
    end
  end

  local auser = task:get_user()
  local ip = task:get_from_ip()

  if ip and ip:is_local() then
    is_local = true
  end

  if settings.sign_authenticated and auser then
    lua_util.debugm(N, task, 'user is authenticated')
    is_authed = true
  elseif (settings.sign_networks and settings.sign_networks:get_key(ip)) then
    is_sign_networks = true
    lua_util.debugm(N, task, 'mail is from address in sign_networks')
  elseif settings.sign_local and is_local then
    lua_util.debugm(N, task, 'mail is from local address')
  elseif settings.sign_inbound and not is_local and not auser then
    lua_util.debugm(N, task, 'mail was sent to us')
  else
    lua_util.debugm(N, task, 'mail is ineligible for signing')
    return false,{}
  end

  local efrom = task:get_from('smtp')
  local empty_envelope = false
  if #(((efrom or E)[1] or E).addr or '') == 0 then
    if not settings.allow_envfrom_empty then
      lua_util.debugm(N, task, 'empty envelope from not allowed')
      return false,{}
    else
      empty_envelope = true
    end
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

  local function is_skip_sign()
    return not (settings.sign_networks and is_sign_networks) and
        not (settings.sign_authenticated and is_authed) and
        not (settings.sign_local and is_local)
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

  if settings.signing_table and (settings.key_table or settings.use_vault) then
    -- OpenDKIM style
    if is_skip_sign() then
      lua_util.debugm(N, task,
          'skip signing: is_sign_network: %s, is_authed: %s, is_local: %s',
          is_sign_networks, is_authed, is_local)
      return false,{}
    end

    if not hfrom or not hfrom[1] or not hfrom[1].addr then
      lua_util.debugm(N, task,
          'signing_table: cannot get data when no header from is presented')
      return false,{}
    end
    local sign_entry = settings.signing_table:get_key(hfrom[1].addr)

    if sign_entry then
      -- Check opendkim style entries
      lua_util.debugm(N, task,
          'signing_table: found entry for %s: %s', hfrom[1].addr, sign_entry)
      if sign_entry == '%' then
        sign_entry = hdom
      end

      if settings.key_table then
      -- Now search in key table
      local key_entry = settings.key_table:get_key(sign_entry)

        if key_entry then
          local parts = lua_util.str_split(key_entry, ':')

          if #parts == 2 then
            -- domain + key
            local selector = settings.selector

            if not selector then
              logger.errx(task, 'no selector defined for sign_entry %s, key_entry %s',
                  sign_entry, key_entry)
              return false,{}
            end

            local res = {
              selector = selector,
              domain = parts[1]:gsub('%%', hdom)
            }

            local st = parts[2]:sub(1, 2)

            if st:sub(1, 1) == '/' or st == './' or st == '..' then
              res.key = parts[2]:gsub('%%', hdom)
              lua_util.debugm(N, task, 'perform dkim signing for %s, selector=%s, domain=%s, key file=%s',
                  hdom, selector, res.domain, res.key)
            else
              res.rawkey = parts[2] -- No sanity check here
              lua_util.debugm(N, task, 'perform dkim signing for %s, selector=%s, domain=%s, raw key used',
                  hdom, selector, res.domain)
            end

            return true,{res}
          elseif #parts == 3 then
            -- domain, selector, key
            local selector = parts[2]

            local res = {
              selector = selector,
              domain = parts[1]:gsub('%%', hdom)
            }

            local st = parts[3]:sub(1, 2)

            if st:sub(1, 1) == '/' or st == './' or st == '..' then
              res.key = parts[3]:gsub('%%', hdom)
              lua_util.debugm(N, task, 'perform dkim signing for %s, selector=%s, domain=%s, key file=%s',
                  hdom, selector, res.domain, res.key)
            else
              res.rawkey = parts[3] -- No sanity check here
              lua_util.debugm(N, task, 'perform dkim signing for %s, selector=%s, domain=%s, raw key used',
                  hdom, selector, res.domain)
            end

            return true,{res}
          else
            logger.errx(task, 'invalid key entry for sign entry %s: %s; when signing %s domain',
                sign_entry, key_entry, hdom)
            return false,{}
          end
        elseif settings.use_vault then
          -- Sign table is presented, the rest is covered by vault
          lua_util.debugm(N, task, 'check vault for %s, by sign entry %s, key entry is missing',
              hdom, sign_entry)
          return true, {
            domain = sign_entry,
            vault = true
          }
        else
          logger.errx(task, 'missing key entry for sign entry %s; when signing %s domain',
              sign_entry, hdom)
          return false,{}
        end
      else
        logger.errx(task, 'cannot get key entry for signing entry %s, when signing %s domain',
            sign_entry, hdom)
        return false,{}
      end
    else
      lua_util.debugm(N, task,
          'signing_table: no entry for %s', hfrom[1].addr)
      return false,{}
    end
  else
    if settings.use_domain_sign_networks and is_sign_networks then
      dkim_domain = get_dkim_domain('use_domain_sign_networks')
      lua_util.debugm(N, task,
          'sign_networks: use domain(%s) for signature: %s',
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

  -- Sanity checks
  if edom and hdom and not settings.allow_hdrfrom_mismatch and hdom ~= edom then
    if settings.allow_hdrfrom_mismatch_local and is_local then
      lua_util.debugm(N, task, 'domain mismatch allowed for local IP: %1 != %2', hdom, edom)
    elseif settings.allow_hdrfrom_mismatch_sign_networks and is_sign_networks then
      lua_util.debugm(N, task, 'domain mismatch allowed for sign_networks: %1 != %2', hdom, edom)
    else
      if empty_envelope and hdom then
        lua_util.debugm(N, task, 'domain mismatch allowed for empty envelope: %1 != %2', hdom, edom)
      else
        lua_util.debugm(N, task, 'domain mismatch not allowed: %1 != %2', hdom, edom)
        return false,{}
      end
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

  if settings.use_vault then
    if settings.vault_domains then
      if settings.vault_domains:get_key(dkim_domain) then
        return true, {
          domain = dkim_domain,
          vault = true,
        }
      else
        lua_util.debugm(N, task, 'domain %s is not designated for vault',
          dkim_domain)
        return false,{}
      end
    else
      -- TODO: try every domain in the vault
      return true, {
        domain = dkim_domain,
        vault = true,
      }
    end
  end

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

exports.sign_using_redis = function(N, task, settings, selectors, sign_func, err_func)
  local lua_redis = require "lua_redis"

  local function try_redis_key(selector, p)
    p.key = nil
    p.selector = selector
    local rk = string.format('%s.%s', p.selector, p.domain)
    local function redis_key_cb(err, data)
      if err then
        err_func(string.format("cannot make request to load DKIM key for %s: %s",
            rk, err))
      elseif type(data) ~= 'string' then
        lua_util.debugm(N, task, "missing DKIM key for %s", rk)
      else
        p.rawkey = data
        lua_util.debugm(N, task, 'found and parsed key for %s:%s in Redis',
            p.domain, p.selector)
        sign_func(task, p)
      end
    end
    local rret = lua_redis.redis_make_request(task,
        settings.redis_params, -- connect params
        rk, -- hash key
        false, -- is write
        redis_key_cb, --callback
        'HGET', -- command
        {settings.key_prefix, rk} -- arguments
    )
    if not rret then
      err_func(task,
          string.format( "cannot make request to load DKIM key for %s", rk))
    end
  end

  for _, p in ipairs(selectors) do
    if settings.selector_prefix then
      logger.infox(task, "using selector prefix '%s' for domain '%s'",
          settings.selector_prefix, p.domain);
      local function redis_selector_cb(err, data)
        if err or type(data) ~= 'string' then
          err_func(task, string.format("cannot make request to load DKIM selector for domain %s: %s",
              p.domain, err))
        else
          try_redis_key(data, p)
        end
      end
      local rret = lua_redis.redis_make_request(task,
          settings.redis_params, -- connect params
          p.domain, -- hash key
          false, -- is write
          redis_selector_cb, --callback
          'HGET', -- command
          {settings.selector_prefix, p.domain} -- arguments
      )
      if not rret then
        err_func(task, string.format("cannot make Redis request to load DKIM selector for domain %s",
            p.domain))
      end
    else
      try_redis_key(p.selector, p)
    end
  end
end

exports.sign_using_vault = function(N, task, settings, selectors, sign_func, err_func)
  local http = require "rspamd_http"
  local ucl = require "ucl"

  local full_url = string.format('%s/v1/%s/%s',
      settings.vault_url, settings.vault_path or 'dkim', selectors.domain)

  local function vault_callback(err, code, body, _)
    if code ~= 200 then
      err_func(task, string.format('cannot request data from the vault url: %s; %s (%s)',
          full_url, err, body))
    else
      local parser = ucl.parser()
      local res,parser_err = parser:parse_string(body)
      if not res then
        err_func(task, string.format('vault reply for %s (data=%s) cannot be parsed: %s',
            full_url, body, parser_err))
      else
        local obj = parser:get_object()

        if not obj or not obj.data then
          err_func(task, string.format('vault reply for %s (data=%s) is invalid, no data',
              full_url, body))
        else
          local elts = obj.data.selectors or {}

          -- Filter selectors by time/sanity
          local function is_selector_valid(p)
            if not p.key or not p.selector then
              return false
            end

            if p.valid_start then
              -- Check start time
              if rspamd_util.get_time() < tonumber(p.valid_start) then
                return false
              end
            end

            if p.valid_end then
              if rspamd_util.get_time() >= tonumber(p.valid_end) then
                return false
              end
            end

            return true
          end
          fun.each(function(p)
            local dkim_sign_data = {
              rawkey = p.key,
              selector = p.selector,
              domain = p.domain or selectors.domain,
              alg = p.alg,
            }
            lua_util.debugm(N, task, 'found and parsed key for %s:%s in Vault',
                dkim_sign_data.domain, dkim_sign_data.selector)
            sign_func(task, dkim_sign_data)
          end, fun.filter(is_selector_valid, elts))
        end
      end
    end
  end

  local ret = http.request{
    task = task,
    url = full_url,
    callback = vault_callback,
    timeout = settings.http_timeout or 5.0,
    no_ssl_verify = settings.no_ssl_verify,
    keepalive = true,
    headers = {
      ['X-Vault-Token'] = settings.vault_token,
    },
  }

  if not ret then
    err_func(task, string.format("cannot make HTTP request to load DKIM data domain %s",
        selectors.domain))
  end
end

exports.validate_signing_settings = function(settings)
  return settings.use_redis or
      settings.path or
      settings.domain or
      settings.path_map or
      settings.selector_map or
      settings.use_http_headers or
      (settings.signing_table and settings.key_table) or
      (settings.use_vault and settings.vault_url and settings.vault_token) or
      settings.sign_condition
end

exports.process_signing_settings = function(N, settings, opts)
  local lua_maps = require "lua_maps"
  for k,v in pairs(opts) do
    if k == 'sign_networks' then
      settings[k] = lua_maps.map_add(N, k, 'radix', 'DKIM signing networks')
    elseif k == 'path_map' then
      settings[k] = lua_maps.map_add(N, k, 'map', 'Paths to DKIM signing keys')
    elseif k == 'selector_map' then
      settings[k] = lua_maps.map_add(N, k, 'map', 'DKIM selectors')
    elseif k == 'signing_table' then
      settings[k] = lua_maps.map_add(N, k, 'glob', 'DKIM signing table')
    elseif k == 'key_table' then
      settings[k] = lua_maps.map_add(N, k, 'glob', 'DKIM keys table')
    elseif k == 'vault_domains' then
      settings[k] = lua_maps.map_add(N, k, 'glob', 'DKIM signing domains in vault')
    elseif k == 'sign_condition' then
      local ret,f = lua_util.callback_from_string(v)
      if ret then
        settings[k] = f
      else
        logger.errx(rspamd_config, 'cannot load sign condition %s: %s', v, f)
      end
    else
      settings[k] = v
    end
  end
end

return exports
