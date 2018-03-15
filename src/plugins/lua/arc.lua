--[[
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
]] --

local rspamd_logger = require "rspamd_logger"
local lua_util = require "lua_util"
local dkim_sign_tools = require "lua_dkim_tools"
local rspamd_util = require "rspamd_util"
local rspamd_rsa_privkey = require "rspamd_rsa_privkey"
local rspamd_rsa = require "rspamd_rsa"
local fun = require "fun"
local auth_results = require "lua_auth_results"
local hash = require "rspamd_cryptobox_hash"

if confighelp then
  return
end

local N = 'arc'

if not rspamd_plugins.dkim then
  rspamd_logger.errx(rspamd_config, "cannot enable arc plugin: dkim is disabled")
  return
end

local dkim_verify = rspamd_plugins.dkim.verify
local dkim_sign = rspamd_plugins.dkim.sign
local dkim_canonicalize = rspamd_plugins.dkim.canon_header_relaxed
local redis_params

if not dkim_verify or not dkim_sign or not dkim_canonicalize then
  rspamd_logger.errx(rspamd_config, "cannot enable arc plugin: dkim is disabled")
  return
end

local arc_symbols = {
  allow = 'ARC_ALLOW',
  invalid = 'ARC_INVALID',
  dnsfail = 'ARC_DNSFAIL',
  na = 'ARC_NA',
  reject = 'ARC_REJECT',
}

local symbols = {
  spf_allow_symbol = 'R_SPF_ALLOW',
  spf_deny_symbol = 'R_SPF_FAIL',
  spf_softfail_symbol = 'R_SPF_SOFTFAIL',
  spf_neutral_symbol = 'R_SPF_NEUTRAL',
  spf_tempfail_symbol = 'R_SPF_DNSFAIL',
  spf_permfail_symbol = 'R_SPF_PERMFAIL',
  spf_na_symbol = 'R_SPF_NA',

  dkim_allow_symbol = 'R_DKIM_ALLOW',
  dkim_deny_symbol = 'R_DKIM_REJECT',
  dkim_tempfail_symbol = 'R_DKIM_TEMPFAIL',
  dkim_na_symbol = 'R_DKIM_NA',
  dkim_permfail_symbol = 'R_DKIM_PERMFAIL',
}

local settings = {
  allow_envfrom_empty = true,
  allow_hdrfrom_mismatch = false,
  allow_hdrfrom_mismatch_local = false,
  allow_hdrfrom_mismatch_sign_networks = false,
  allow_hdrfrom_multiple = false,
  allow_username_mismatch = false,
  auth_only = true,
  domain = {},
  path = string.format('%s/%s/%s', rspamd_paths['DBDIR'], 'arc', '$domain.$selector.key'),
  sign_local = true,
  selector = 'arc',
  sign_symbol = 'ARC_SIGNED',
  try_fallback = true,
  use_domain = 'header',
  use_esld = true,
  use_redis = false,
  key_prefix = 'arc_keys', -- default hash name
}

local function parse_arc_header(hdr, target)
  local arr = fun.totable(fun.map(
    function(val)
      return fun.totable(fun.map(lua_util.rspamd_str_trim,
        fun.filter(function(v) return v and #v > 0 end,
          lua_util.rspamd_str_split(val.decoded, ';'))))
    end, hdr
  ))

  -- Now we have two tables in format:
  -- [sigs] -> [{sig1_elts}, {sig2_elts}...]
  for i,elts in ipairs(arr) do
    fun.each(function(v)
      if not target[i] then target[i] = {} end
      if v[1] and v[2] then
        target[i][v[1]] = v[2]
      end
    end, fun.map(function(elt)
      return lua_util.rspamd_str_split(elt, '=')
    end, elts))
    target[i].header = hdr[i].decoded
    target[i].raw_header = hdr[i].value
  end
end

local function arc_validate_seals(task, seals, sigs, seal_headers, sig_headers)
  for i = 1,#seals do
    if (sigs[i].i or 0) ~= i then
      rspamd_logger.infox(task, 'bad i value for signature: %s, expected %s',
        sigs[i].i, i)
      task:insert_result(arc_symbols['invalid'], 1.0, 'invalid count of seals and signatures')
      return false
    end
    if (seals[i].i or 0) ~= i then
      rspamd_logger.infox(task, 'bad i value for seal: %s, expected %s',
        seals[i].i, i)
      task:insert_result(arc_symbols['invalid'], 1.0, 'invalid count of seals and signatures')
      return false
    end

    if not seals[i].cv then
      task:insert_result(arc_symbols['invalid'], 1.0, 'no cv on i=' .. tostring(i))
      return false
    end

    if i == 1 then
      -- We need to ensure that cv of seal is equal to 'none'
      if seals[i].cv ~= 'none' then
        task:insert_result(arc_symbols['invalid'], 1.0, 'cv is not "none" for i=1')
        return false
      end
    else
      if seals[i].cv ~= 'pass' then
        task:insert_result(arc_symbols['reject'], 1.0, string.format('cv is %s on i=%d',
            seals[i].cv, i))
        return false
      end
    end
  end

  return true
end

local function arc_callback(task)
  local arc_sig_headers = task:get_header_full('ARC-Message-Signature')
  local arc_seal_headers = task:get_header_full('ARC-Seal')

  if not arc_sig_headers or not arc_seal_headers then
    task:insert_result(arc_symbols['na'], 1.0)
    return
  end

  if #arc_sig_headers ~= #arc_seal_headers then
    -- We mandate that count of seals is equal to count of signatures
    rspamd_logger.infox(task, 'number of seals (%s) is not equal to number of signatures (%s)',
        #arc_seal_headers, #arc_sig_headers)
    task:insert_result(arc_symbols['invalid'], 'invalid count of seals and signatures')
    return
  end

  local cbdata = {
    seals = {},
    sigs = {},
    checked = 0,
    res = 'success',
    errors = {}
  }

  parse_arc_header(arc_seal_headers, cbdata.seals)
  parse_arc_header(arc_sig_headers, cbdata.sigs)

  -- Fix i type
  fun.each(function(hdr)
    hdr.i = tonumber(hdr.i) or 0
  end, cbdata.seals)

  fun.each(function(hdr)
    hdr.i = tonumber(hdr.i) or 0
  end, cbdata.sigs)

  -- Now we need to sort elements according to their [i] value
  table.sort(cbdata.seals, function(e1, e2)
    return (e1.i or 0) < (e2.i or 0)
  end)
  table.sort(cbdata.sigs, function(e1, e2)
    return (e1.i or 0) < (e2.i or 0)
  end)

  rspamd_logger.debugm(N, task, 'got %s arc sections', #cbdata.seals)

  -- Now check sanity of what we have
  if not arc_validate_seals(task, cbdata.seals, cbdata.sigs,
    arc_seal_headers, arc_sig_headers) then
    return
  end

  task:cache_set('arc-sigs', cbdata.sigs)
  task:cache_set('arc-seals', cbdata.seals)

  local function arc_seal_cb(_, res, err, domain)
    cbdata.checked = cbdata.checked + 1
    rspamd_logger.debugm(N, task, 'checked arc seal: %s(%s), %s processed',
        res, err, cbdata.checked)

    if not res then
      cbdata.res = 'fail'
      if err and domain then
        table.insert(cbdata.errors, string.format('sig:%s:%s', domain, err))
      end
    end

    if cbdata.checked == #arc_sig_headers then
      if cbdata.res == 'success' then
        task:insert_result(arc_symbols['allow'], 1.0, 'i=' ..
            tostring(cbdata.checked))
      else
        task:insert_result(arc_symbols['reject'], 1.0,
          rspamd_logger.slog('seal check failed: %s, %s', cbdata.res,
            cbdata.errors))
      end
    end
  end

  local function arc_signature_cb(_, res, err, domain)
    rspamd_logger.debugm(N, task, 'checked arc signature %s: %s(%s), %s processed',
      domain, res, err, cbdata.checked)

    if not res then
      cbdata.res = 'fail'
      if err and domain then
        table.insert(cbdata.errors, string.format('sig:%s:%s', domain, err))
      end
    end
    if cbdata.res == 'success' then
      -- Verify seals
      cbdata.checked = 0
      fun.each(
        function(sig)
          local ret, lerr = dkim_verify(task, sig.header, arc_seal_cb, 'arc-seal')
          if not ret then
            cbdata.res = 'fail'
            table.insert(cbdata.errors, string.format('sig:%s:%s', sig.d or '', lerr))
            cbdata.checked = cbdata.checked + 1
            rspamd_logger.debugm(N, task, 'checked arc seal %s: %s(%s), %s processed',
              sig.d, ret, lerr, cbdata.checked)
          end
        end, cbdata.seals)
    else
      task:insert_result(arc_symbols['reject'], 1.0,
        rspamd_logger.slog('signature check failed: %s, %s', cbdata.res,
          cbdata.errors))
    end
  end

  -- Now we can verify all signatures
  local processed = 0
  local sig = cbdata.sigs[#cbdata.sigs]
  local ret,err = dkim_verify(task, sig.header, arc_signature_cb, 'arc-sign')

  if not ret then
    cbdata.res = 'fail'
    table.insert(cbdata.errors, string.format('sig:%s:%s', sig.d or '', err))
  else
    processed = processed + 1
    rspamd_logger.debugm(N, task, 'processed arc signature %s[%s]: %s(%s), %s processed',
      sig.d, sig.i, ret, err, cbdata.checked)
  end

  if processed == 0 then
    task:insert_result(arc_symbols['reject'], 1.0,
      rspamd_logger.slog('cannot verify %s of %s signatures: %s',
        #arc_sig_headers - processed, #arc_sig_headers, cbdata.errors))
  end
end

local opts = rspamd_config:get_all_opt('arc')
if not opts or type(opts) ~= 'table' then
  return
end

if opts['symbols'] then
  for k,_ in pairs(arc_symbols) do
    if opts['symbols'][k] then
      arc_symbols[k] = opts['symbols'][k]
    end
  end
end


local id = rspamd_config:register_symbol({
  name = 'ARC_CALLBACK',
  type = 'callback',
  callback = arc_callback
})

rspamd_config:register_symbol({
  name = arc_symbols['allow'],
  flags = 'nice',
  parent = id,
  type = 'virtual',
  score = -1.0,
  group = 'policies',
})
rspamd_config:register_symbol({
  name = arc_symbols['reject'],
  parent = id,
  type = 'virtual',
  score = 2.0,
  group = 'policies',
})
rspamd_config:register_symbol({
  name = arc_symbols['invalid'],
  parent = id,
  type = 'virtual',
  score = 1.0,
  group = 'policies',
})
rspamd_config:register_symbol({
  name = arc_symbols['dnsfail'],
  parent = id,
  type = 'virtual',
  score = 0.0,
  group = 'policies',
})
rspamd_config:register_symbol({
  name = arc_symbols['na'],
  parent = id,
  type = 'virtual',
  score = 0.0,
  group = 'policies',
})

rspamd_config:register_dependency('ARC_CALLBACK', symbols['spf_allow_symbol'])
rspamd_config:register_dependency('ARC_CALLBACK', symbols['dkim_allow_symbol'])

local function arc_sign_seal(task, params, header)
  local fold_type = "crlf"
  local arc_sigs = task:cache_get('arc-sigs')
  local arc_seals = task:cache_get('arc-seals')
  local arc_auth_results = task:get_header_full('ARC-Authentication-Results') or {}
  local cur_auth_results = auth_results.gen_auth_results(task) or ''
  local privkey

  if task:has_flag("milter") then
    fold_type = "lf"
  end

  if params.rawkey then
    privkey = rspamd_rsa_privkey.load_pem(params.rawkey)
  elseif params.key then
    privkey = rspamd_rsa_privkey.load_file(params.key)
  end

  if not privkey then
    rspamd_logger.errx(task, 'cannot load private key for signing')
  end


  local sha_ctx = hash.create_specific('sha256')

  -- Update using previous seals + sigs + AAR
  local cur_idx = 1
  if arc_seals then
    cur_idx = #arc_seals + 1
    for i = (cur_idx - 1), 1, (-1) do
      if arc_auth_results[i] then
        local s = dkim_canonicalize('ARC-Authentication-Results',
          arc_auth_results[i].value)
        sha_ctx:update(s)
        rspamd_logger.debugm(N, task, 'update signature with header: %s', s)
      end
      if arc_sigs[i] then
        local s = dkim_canonicalize('ARC-Message-Signature',
          arc_sigs[i].raw_header)
        sha_ctx:update(s)
        rspamd_logger.debugm(N, task, 'update signature with header: %s', s)
      end
      if arc_seals[i] then
        local s = dkim_canonicalize('ARC-Seal', arc_seals[i].raw_header)
        sha_ctx:update(s)
        rspamd_logger.debugm(N, task, 'update signature with header: %s', s)
      end
    end
  end

  header = rspamd_util.fold_header(
    'ARC-Message-Signature',
    header, fold_type)

  cur_auth_results = rspamd_util.fold_header(
    'ARC-Authentication-Results',
    cur_auth_results, fold_type)

  cur_auth_results = string.format('i=%d; %s', cur_idx, cur_auth_results)
  local s = dkim_canonicalize('ARC-Authentication-Results',
    cur_auth_results)
  sha_ctx:update(s)
  rspamd_logger.debugm(N, task, 'update signature with header: %s', s)
  s = dkim_canonicalize('ARC-Message-Signature', header)
  sha_ctx:update(s)
  rspamd_logger.debugm(N, task, 'update signature with header: %s', s)

  local cur_arc_seal = string.format('i=%d; s=%s; d=%s; t=%d; a=rsa-sha256; cv=%s; b=',
      cur_idx, params.selector, params.domain, math.floor(rspamd_util.get_time()), params.arc_cv)
  s = string.format('%s:%s', 'arc-seal', cur_arc_seal)
  sha_ctx:update(s)
  rspamd_logger.debugm(N, task, 'initial update signature with header: %s', s)

  local sig = rspamd_rsa.sign_memory(privkey, sha_ctx:bin())
  cur_arc_seal = string.format('%s%s', cur_arc_seal,
    sig:base64())

  task:set_milter_reply({
    add_headers = {
      ['ARC-Authentication-Results'] = cur_auth_results,
      ['ARC-Message-Signature'] = header,
      ['ARC-Seal'] = rspamd_util.fold_header(
        'ARC-Seal',
        cur_arc_seal, fold_type),
    }
  })
  task:insert_result(settings.sign_symbol, 1.0, string.format('i=%d', cur_idx))
end

local function arc_signing_cb(task)
  local arc_seals = task:cache_get('arc-seals')

  local ret,p = dkim_sign_tools.prepare_dkim_signing(N, task, settings)

  if not ret then
    return
  end

  p.arc_cv = 'none'
  p.arc_idx = 1
  p.no_cache = true
  p.sign_type = 'arc-sign'

  if arc_seals then
    p.arc_idx = #arc_seals + 1

    if task:has_symbol(arc_symbols.allow) then
      p.arc_cv = 'pass'
    else
      p.arc_cv = 'fail'
    end
  end

  if settings.use_redis then
    local function try_redis_key(selector)
      p.key = nil
      p.selector = selector
      local rk = string.format('%s.%s', p.selector, p.domain)
      local function redis_key_cb(err, data)
        if err or type(data) ~= 'string' then
          rspamd_logger.infox(rspamd_config, "cannot make request to load DKIM key for %s: %s",
            rk, err)
        else
          p.rawkey = data
          local dret, hdr = dkim_sign(task, p)
          if dret then
            return arc_sign_seal(task, p, hdr)
          end
        end
      end
      local rret = rspamd_redis_make_request(task,
        redis_params, -- connect params
        rk, -- hash key
        false, -- is write
        redis_key_cb, --callback
        'HGET', -- command
        {settings.key_prefix, rk} -- arguments
      )
      if not rret then
        rspamd_logger.infox(rspamd_config, "cannot make request to load DKIM key for %s", rk)
      end
    end
    if settings.selector_prefix then
      rspamd_logger.infox(rspamd_config, "Using selector prefix %s for domain %s", settings.selector_prefix, p.domain);
      local function redis_selector_cb(err, data)
        if err or type(data) ~= 'string' then
          rspamd_logger.infox(rspamd_config, "cannot make request to load DKIM selector for domain %s: %s", p.domain, err)
        else
          try_redis_key(data)
        end
      end
      local rret = rspamd_redis_make_request(task,
        redis_params, -- connect params
        p.domain, -- hash key
        false, -- is write
        redis_selector_cb, --callback
        'HGET', -- command
        {settings.selector_prefix, p.domain} -- arguments
      )
      if not rret then
        rspamd_logger.infox(rspamd_config, "cannot make request to load DKIM selector for %s", p.domain)
      end
    else
      if not p.selector then
        rspamd_logger.errx(task, 'No selector specified')
        return false
      end
      try_redis_key(p.selector)
    end
  else
    if (p.key and p.selector) then
      p.key = lua_util.template(p.key, {domain = p.domain, selector = p.selector})
      if not rspamd_util.file_exists(p.key) then
        rspamd_logger.debugm(N, task, 'file %s does not exists', p.key)
        return false
      end
      local dret, hdr = dkim_sign(task, p)
      if dret then
        return arc_sign_seal(task, p, hdr)
      end
    else
      rspamd_logger.infox(task, 'key path or dkim selector unconfigured; no signing')
      return false
    end
  end
end

for k,v in pairs(opts) do
  if k == 'sign_networks' then
    settings[k] = rspamd_map_add(N, k, 'radix', 'DKIM signing networks')
  elseif k == 'path_map' then
    settings[k] = rspamd_map_add(N, k, 'map', 'Paths to DKIM signing keys')
  elseif k == 'selector_map' then
    settings[k] = rspamd_map_add(N, k, 'map', 'DKIM selectors')
  else
    settings[k] = v
  end
end
if not (settings.use_redis or settings.path or
    settings.domain or settings.path_map or settings.selector_map) then
  rspamd_logger.infox(rspamd_config, 'mandatory parameters missing, disable arc signing')
  lua_util.disable_module(N, "fail")
  return
end

if settings.use_redis then
  redis_params = rspamd_parse_redis_server('arc')

  if not redis_params then
    rspamd_logger.errx(rspamd_config, 'no servers are specified, but module is configured to load keys from redis, disable arc signing')
    lua_util.disable_module(N, "config")
    return
  end
end

rspamd_config:register_symbol({
  name = settings['sign_symbol'],
  callback = arc_signing_cb
})

-- Do not sign unless valid
rspamd_config:register_dependency(settings['sign_symbol'], 'ARC_CALLBACK')
