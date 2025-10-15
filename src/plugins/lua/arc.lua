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
]] --

local rspamd_logger = require "rspamd_logger"
local lua_util = require "lua_util"
local dkim_sign_tools = require "lua_dkim_tools"
local rspamd_util = require "rspamd_util"
local fun = require "fun"
local lua_auth_results = require "lua_auth_results"
local hash = require "rspamd_cryptobox_hash"
local lua_mime = require "lua_mime"
local dkim_ffi = require "lua_ffi/dkim"

if confighelp then
  return
end

local N = 'arc'
local AR_TRUSTED_CACHE_KEY = 'arc_trusted_aar'

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

local settings = {
  allow_envfrom_empty = true,
  allow_hdrfrom_mismatch = false,
  allow_hdrfrom_mismatch_local = false,
  allow_hdrfrom_mismatch_sign_networks = false,
  allow_hdrfrom_multiple = false,
  allow_username_mismatch = false,
  sign_authenticated = true,
  domain = {},
  path = string.format('%s/%s/%s', rspamd_paths['DBDIR'], 'arc', '$domain.$selector.key'),
  sign_local = true,
  selector = 'arc',
  sign_symbol = 'ARC_SIGNED',
  try_fallback = true,
  use_domain = 'header',
  use_esld = true,
  use_redis = false,
  key_prefix = 'arc_keys',       -- default hash name
  reuse_auth_results = false,    -- Reuse the existing authentication results
  whitelisted_signers_map = nil, -- Trusted signers domains
  whitelist = nil,               -- Domains with broken ARC implementations to trust despite validation failures
  adjust_dmarc = true,           -- Adjust DMARC rejected policy for trusted forwarders
  allowed_ids = nil,             -- Allowed settings id
  forbidden_ids = nil,           -- Banned settings id
}

-- To match normal AR
local ar_settings = lua_auth_results.default_settings

local function parse_arc_header(hdr, target, is_aar)
  -- Split elements by ';' and trim spaces
  local arr = fun.totable(fun.map(
    function(val)
      return fun.totable(fun.map(lua_util.rspamd_str_trim,
        fun.filter(function(v)
            return v and #v > 0
          end,
          lua_util.rspamd_str_split(val.decoded, ';')
        )
      ))
    end, hdr
  ))

  -- v[1] is the key and v[2] is the value
  local function fill_arc_header_table(v, t)
    if v[1] and v[2] then
      local key = lua_util.rspamd_str_trim(v[1])
      local value = lua_util.rspamd_str_trim(v[2])
      t[key] = value
    end
  end

  -- Now we have two tables in format:
  -- [arc_header] -> [{arc_header1_elts}, {arc_header2_elts}...]
  for i, elts in ipairs(arr) do
    if not target[i] then
      target[i] = {}
    end
    if not is_aar then
      -- For normal ARC headers we split by kv pair, like k=v
      fun.each(function(v)
          fill_arc_header_table(v, target[i])
        end,
        fun.map(function(elt)
          return lua_util.rspamd_str_split(elt, '=')
        end, elts)
      )
    else
      -- For AAR we check special case of i=%d and pass everything else to
      -- AAR specific parser
      for _, elt in ipairs(elts) do
        if string.match(elt, "%s*i%s*=%s*%d+%s*") then
          local pair = lua_util.rspamd_str_split(elt, '=')
          fill_arc_header_table(pair, target[i])
        else
          -- Normal element
          local ar_elt = lua_auth_results.parse_ar_element(elt)

          if ar_elt then
            if not target[i].ar then
              target[i].ar = {}
            end
            table.insert(target[i].ar, ar_elt)
          end
        end
      end
    end
    target[i].header = hdr[i].decoded
    target[i].raw_header = hdr[i].value
  end

  -- sort by i= attribute
  table.sort(target, function(a, b)
    return (tonumber(a.i) or 0) < (tonumber(b.i) or 0)
  end)
end

local function arc_validate_seals(task, seals, sigs, seal_headers, sig_headers)
  local fail_reason
  for i = 1, #seals do
    if (sigs[i].i or 0) ~= i then
      fail_reason = string.format('bad i for signature: %d, expected %d; d=%s',
        sigs[i].i, i, sigs[i].d)
      rspamd_logger.infox(task, fail_reason)
      task:insert_result(arc_symbols['invalid'], 1.0, fail_reason)
      return false, fail_reason
    end
    if (seals[i].i or 0) ~= i then
      fail_reason = string.format('bad i for seal: %d, expected %d; d=%s',
        seals[i].i, i, seals[i].d)
      rspamd_logger.infox(task, fail_reason)
      task:insert_result(arc_symbols['invalid'], 1.0, fail_reason)
      return false, fail_reason
    end

    if not seals[i].cv then
      fail_reason = string.format('no cv on i=%d', i)
      task:insert_result(arc_symbols['invalid'], 1.0, fail_reason)
      return false, fail_reason
    end

    if i == 1 then
      -- We need to ensure that cv of seal is equal to 'none'
      if seals[i].cv ~= 'none' then
        fail_reason = 'cv is not "none" for i=1'
        task:insert_result(arc_symbols['invalid'], 1.0, fail_reason)
        return false, fail_reason
      end
    else
      if seals[i].cv ~= 'pass' then
        fail_reason = string.format('cv is %s on i=%d', seals[i].cv, i)
        task:insert_result(arc_symbols['reject'], 1.0, fail_reason)
        return true, fail_reason
      end
    end
  end

  return true, nil
end

local function arc_callback(task)
  local arc_sig_headers = task:get_header_full('ARC-Message-Signature')
  local arc_seal_headers = task:get_header_full('ARC-Seal')
  local arc_ar_headers = task:get_header_full('ARC-Authentication-Results')

  if not arc_sig_headers or not arc_seal_headers then
    task:insert_result(arc_symbols['na'], 1.0)
    return
  end

  if #arc_sig_headers ~= #arc_seal_headers then
    -- We mandate that count of seals is equal to count of signatures
    rspamd_logger.infox(task, 'number of seals (%s) is not equal to number of signatures (%s)',
      #arc_seal_headers, #arc_sig_headers)
    task:insert_result(arc_symbols['invalid'], 1.0, 'invalid count of seals and signatures')
    return
  end

  local cbdata = {
    seals = {},
    sigs = {},
    ars = {},
    res = 'success',
    errors = {},
    allowed_by_trusted = false
  }

  parse_arc_header(arc_seal_headers, cbdata.seals, false)
  parse_arc_header(arc_sig_headers, cbdata.sigs, false)

  if arc_ar_headers then
    parse_arc_header(arc_ar_headers, cbdata.ars, true)
  end

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

  lua_util.debugm(N, task, 'got %s arc sections', #cbdata.seals)

  -- Now check sanity of what we have
  local valid, validation_error = arc_validate_seals(task, cbdata.seals, cbdata.sigs,
    arc_seal_headers, arc_sig_headers)
  if not valid then
    task:cache_set('arc-failure', validation_error)
    return
  end

  task:cache_set('arc-sigs', cbdata.sigs)
  task:cache_set('arc-seals', cbdata.seals)
  task:cache_set('arc-authres', cbdata.ars)

  if validation_error then
    -- ARC rejection but no strong failure for signing
    return
  end

  local function gen_arc_seal_cb(index, sig)
    return function(_, res, err, domain)
      lua_util.debugm(N, task, 'checked arc seal: %s(%s), %s processed',
        res, err, index)

      if not res then
        -- Check if this domain is whitelisted for broken ARC implementations
        if settings.whitelist and domain and settings.whitelist:get_key(domain) then
          rspamd_logger.infox(task, 'ARC seal validation failed for whitelisted domain %s, treating as valid: %s',
            domain, err)
          lua_util.debugm(N, task, 'whitelisted domain %s ARC seal failure ignored', domain)
          res = true -- Treat as valid to continue the chain
        else
          cbdata.res = 'fail'
          if err and domain then
            table.insert(cbdata.errors, string.format('sig:%s:%s', domain, err))
          end
        end
      end

      if settings.whitelisted_signers_map and cbdata.res == 'success' then
        if settings.whitelisted_signers_map:get_key(sig.d) then
          -- Whitelisted signer has been found in a valid chain
          local mult = 1.0
          local cur_aar = cbdata.ars[index]
          if not cur_aar then
            rspamd_logger.warnx(task, "cannot find Arc-Authentication-Results for trusted " ..
              "forwarder %s on i=%s", domain, cbdata.index)
          else
            task:cache_set(AR_TRUSTED_CACHE_KEY, cur_aar)
            local seen_dmarc
            for _, ar in ipairs(cur_aar.ar) do
              if ar.dmarc then
                local dmarc_fwd = ar.dmarc
                seen_dmarc = true
                if dmarc_fwd == 'reject' or dmarc_fwd == 'fail' or dmarc_fwd == 'quarantine' then
                  lua_util.debugm(N, "found rejected dmarc on forwarding")
                  mult = 0.0
                elseif dmarc_fwd == 'pass' then
                  mult = 1.0
                end
              elseif ar.spf then
                local spf_fwd = ar.spf
                if spf_fwd == 'reject' or spf_fwd == 'fail' or spf_fwd == 'quarantine' then
                  lua_util.debugm(N, "found rejected spf on forwarding")
                  if not seen_dmarc then
                    mult = mult * 0.5
                  end
                end
              end
            end
          end
          task:insert_result(arc_symbols.trusted_allow, mult,
            string.format('%s:s=%s:i=%d', domain, sig.s, index))
        end
      end

      if index == #arc_sig_headers then
        if cbdata.res == 'success' then
          local arc_allow_result = string.format('%s:s=%s:i=%d',
            domain, sig.s, index)
          task:insert_result(arc_symbols.allow, 1.0, arc_allow_result)
          task:cache_set('arc-allow', arc_allow_result)
        else
          task:insert_result(arc_symbols.reject, 1.0,
            rspamd_logger.slog('seal check failed: %s, %s', cbdata.res,
              cbdata.errors))
        end
      end
    end
  end

  local function arc_signature_cb(_, res, err, domain)
    lua_util.debugm(N, task, 'checked arc signature %s: %s(%s)',
      domain, res, err)

    if not res then
      -- Check if this domain is whitelisted for broken ARC implementations
      if settings.whitelist and domain and settings.whitelist:get_key(domain) then
        rspamd_logger.infox(task, 'ARC signature validation failed for whitelisted domain %s, treating as valid: %s',
          domain, err)
        lua_util.debugm(N, task, 'whitelisted domain %s ARC signature failure ignored', domain)
        res = true -- Treat as valid to continue the chain
      else
        cbdata.res = 'fail'
        if err and domain then
          table.insert(cbdata.errors, string.format('sig:%s:%s', domain, err))
        end
      end
    end
    if cbdata.res == 'success' then
      -- Verify seals
      for i, sig in ipairs(cbdata.seals) do
        local ret, lerr = dkim_verify(task, sig.header, gen_arc_seal_cb(i, sig), 'arc-seal')
        if not ret then
          -- Check if this domain is whitelisted for broken ARC implementations
          if settings.whitelist and sig.d and settings.whitelist:get_key(sig.d) then
            rspamd_logger.infox(task, 'ARC seal dkim_verify failed for whitelisted domain %s, treating as valid: %s',
              sig.d, lerr)
            lua_util.debugm(N, task, 'whitelisted domain %s ARC seal dkim_verify failure ignored', sig.d)
          else
            cbdata.res = 'fail'
            table.insert(cbdata.errors, string.format('seal:%s:s=%s:i=%s:%s',
              sig.d or '', sig.s or '', sig.i or '', lerr))
            lua_util.debugm(N, task, 'checked arc seal %s: %s(%s), %s processed',
              sig.d, ret, lerr, i)
          end
        end
      end
    else
      task:insert_result(arc_symbols['reject'], 1.0,
        rspamd_logger.slog('signature check failed: %s, %s', cbdata.res,
          cbdata.errors))
    end
  end

  --[[
  1.  Collect all ARC Sets currently attached to the message.  If there
       are none, the Chain Validation Status is "none" and the algorithm
       stops here.  The maximum number of ARC Sets that can be attached
       to a message is 50.  If more than the maximum number exist the
       Chain Validation Status is "fail" and the algorithm stops here.
       In the following algorithm, the maximum ARC instance value is
       referred to as "N".

   2.  If the Chain Validation Status of the highest instance value ARC
       Set is "fail", then the Chain Validation status is "fail" and the
       algorithm stops here.

   3.  Validate the structure of the Authenticated Received Chain.  A
       valid ARC has the following conditions:

       1.  Each ARC Set MUST contain exactly one each of the three ARC
           header fields (AAR, AMS, and AS).

       2.  The instance values of the ARC Sets MUST form a continuous
           sequence from 1..N with no gaps or repetition.

       3.  The "cv" value for all ARC-Seal header fields must be non-
           failing.  For instance values > 1, the value must be "pass".
           For instance value = 1, the value must be "none".

       *  If any of these conditions are not met, the Chain Validation
          Status is "fail" and the algorithm stops here.

   4.  Validate the AMS with the greatest instance value (most recent).
       If validation fails, then the Chain Validation Status is "fail"
       and the algorithm stops here.

   5 - 7. Optional, not implemented
   8.  Validate each AS beginning with the greatest instance value and
       proceeding in decreasing order to the AS with the instance value
       of 1.  If any AS fails to validate, the Chain Validation Status
       is "fail" and the algorithm stops here.
   9.  If the algorithm reaches this step, then the Chain Validation
       Status is "pass", and the algorithm is complete.
  ]] --

  local processed = 0
  local sig = cbdata.sigs[#cbdata.sigs] -- last AMS
  local ret, err = dkim_verify(task, sig.header, arc_signature_cb, 'arc-sign')

  if not ret then
    -- Check if this domain is whitelisted for broken ARC implementations
    if settings.whitelist and sig.d and settings.whitelist:get_key(sig.d) then
      rspamd_logger.infox(task, 'ARC signature dkim_verify failed for whitelisted domain %s, treating as valid: %s',
        sig.d, err)
      lua_util.debugm(N, task, 'whitelisted domain %s ARC signature dkim_verify failure ignored', sig.d)
      processed = processed + 1
    else
      cbdata.res = 'fail'
      table.insert(cbdata.errors, string.format('sig:%s:%s', sig.d or '', err))
    end
  else
    processed = processed + 1
    lua_util.debugm(N, task, 'processed arc signature %s[%s]: %s(%s), %s total',
      sig.d, sig.i, ret, err, #cbdata.seals)
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
  for k, _ in pairs(arc_symbols) do
    if opts['symbols'][k] then
      arc_symbols[k] = opts['symbols'][k]
    end
  end
end

local id = rspamd_config:register_symbol({
  name = 'ARC_CHECK',
  type = 'callback',
  group = 'policies',
  groups = { 'arc' },
  callback = arc_callback,
  augmentations = { lua_util.dns_timeout_augmentation(rspamd_config) },
})
rspamd_config:register_symbol({
  name = 'ARC_CALLBACK', -- compatibility symbol
  type = 'virtual,skip',
  parent = id,
})

rspamd_config:register_symbol({
  name = arc_symbols['allow'],
  parent = id,
  type = 'virtual',
  score = -1.0,
  group = 'policies',
  groups = { 'arc' },
})
rspamd_config:register_symbol({
  name = arc_symbols['reject'],
  parent = id,
  type = 'virtual',
  score = 2.0,
  group = 'policies',
  groups = { 'arc' },
})
rspamd_config:register_symbol({
  name = arc_symbols['invalid'],
  parent = id,
  type = 'virtual',
  score = 1.0,
  group = 'policies',
  groups = { 'arc' },
})
rspamd_config:register_symbol({
  name = arc_symbols['dnsfail'],
  parent = id,
  type = 'virtual',
  score = 0.0,
  group = 'policies',
  groups = { 'arc' },
})
rspamd_config:register_symbol({
  name = arc_symbols['na'],
  parent = id,
  type = 'virtual',
  score = 0.0,
  group = 'policies',
  groups = { 'arc' },
})

rspamd_config:register_dependency('ARC_CHECK', 'SPF_CHECK')
rspamd_config:register_dependency('ARC_CHECK', 'DKIM_CHECK')

local function arc_sign_seal(task, params, header)
  local arc_sigs = task:cache_get('arc-sigs')
  local arc_seals = task:cache_get('arc-seals')
  local arc_auth_results = task:cache_get('arc-authres')
  local cur_auth_results
  local privkey

  -- Load key using dkim_ffi which supports both RSA and ed25519
  if params.rawkey then
    local key_format
    -- Distinguish between pem and base64
    if string.match(params.rawkey, '^-----BEGIN') then
      key_format = 'pem'
    else
      key_format = 'base64'
    end
    privkey = dkim_ffi.load_sign_key(params.rawkey, key_format)
  elseif params.key then
    privkey = dkim_ffi.load_sign_key(params.key, 'file')
  end

  if not privkey then
    rspamd_logger.errx(task, 'cannot load private key for signing')
    return
  end

  if settings.reuse_auth_results then
    local ar_header = task:get_header('Authentication-Results')

    if ar_header then
      lua_util.debugm(N, task, 'reuse authentication results header for ARC')
      cur_auth_results = ar_header
    else
      lua_util.debugm(N, task, 'cannot reuse authentication results, header is missing')
      cur_auth_results = lua_auth_results.gen_auth_results(task, ar_settings) or ''
    end
  else
    cur_auth_results = lua_auth_results.gen_auth_results(task, ar_settings) or ''
  end

  local cur_idx = 1
  if arc_seals then
    cur_idx = #arc_seals + 1
  end

  header = lua_util.fold_header_with_encoding(task,
    'ARC-Message-Signature',
    header,
    { structured = true, encode = false })

  cur_auth_results = string.format('i=%d; %s', cur_idx, cur_auth_results)
  cur_auth_results = lua_util.fold_header_with_encoding(task,
    'ARC-Authentication-Results',
    cur_auth_results,
    { stop_chars = ';', structured = true, encode = false })

  -- Add the current AAR and AMS headers so they can be signed by the seal
  lua_mime.modify_headers(task, {
    add = {
      ['ARC-Authentication-Results'] = { order = 1, value = cur_auth_results },
      ['ARC-Message-Signature'] = { order = 1, value = header },
    },
  })

  -- Create seal signature using dkim_ffi which supports both RSA and ed25519
  local dkim_headers = 'arc-authentication-results:arc-message-signature'
  -- Include all previous arc-seal headers
  for i = 1, cur_idx - 1 do
    dkim_headers = dkim_headers .. ':arc-seal'
  end

  local sign_context = dkim_ffi.create_sign_context(task, privkey, dkim_headers, 'arc-seal')
  if not sign_context then
    rspamd_logger.errx(task, 'cannot create sign context for ARC seal')
    return
  end

  -- Call rspamd_dkim_sign to create the seal
  local ffi = require('ffi')
  local gstring = ffi.C.rspamd_dkim_sign(task:topointer(), params.selector, params.domain,
    0, 0, cur_idx, params.arc_cv, sign_context)

  if not gstring then
    rspamd_logger.errx(task, 'cannot create ARC seal signature')
    return
  end

  local cur_arc_seal = ffi.string(gstring.str, gstring.len)
  ffi.C.g_string_free(gstring, true)

  -- Add the final ARC-Seal header
  lua_mime.modify_headers(task, {
    add = {
      ['ARC-Seal'] = {
        order = 1,
        value = lua_util.fold_header_with_encoding(task,
          'ARC-Seal', cur_arc_seal,
          { structured = true, encode = false })
      }
    },
    -- RFC requires a strict order for these headers to be inserted
    order = { 'ARC-Authentication-Results', 'ARC-Message-Signature', 'ARC-Seal' },
  })
  task:insert_result(settings.sign_symbol, 1.0,
    string.format('%s:s=%s:i=%d', params.domain, params.selector, cur_idx))
end

local function prepare_arc_selector(task, sel)
  local arc_seals = task:cache_get('arc-seals')

  if not arc_seals then
    -- Check if our arc is broken
    local failure_reason = task:cache_get('arc-failure')
    if failure_reason then
      rspamd_logger.infox(task, 'skip ARC as the existing chain is broken: %s', failure_reason)
      return false
    end
  end

  sel.arc_cv = 'none'
  sel.arc_idx = 1
  sel.no_cache = true
  sel.sign_type = 'arc-sign'

  if arc_seals then
    sel.arc_idx = #arc_seals + 1

    local function default_arc_cv()
      if task:cache_get('arc-allow') then
        sel.arc_cv = 'pass'
      else
        sel.arc_cv = 'fail'
      end
    end

    local function arc_result_from_ar(ar_header)
      ar_header = ar_header or ""
      for k, v in string.gmatch(ar_header, "(%w+)=(%w+)") do
        if k == 'arc' then
          return v
        end
      end
      return nil
    end

    if settings.reuse_auth_results then
      local ar_header = task:get_header('Authentication-Results')

      if ar_header then
        local arc_match = arc_result_from_ar(ar_header)

        if arc_match then
          if arc_match == 'none' or arc_match == 'pass' then
            -- none should be converted to `pass`
            sel.arc_cv = 'pass'
          else
            sel.arc_cv = 'fail'
          end
        else
          default_arc_cv()
        end
      else
        -- Cannot reuse, use normal path
        default_arc_cv()
      end
    else
      default_arc_cv()
    end
  end

  return true
end

local function do_sign(task, sign_params)
  if not prepare_arc_selector(task, sign_params) then
    -- Broken arc
    return
  end

  if settings.check_pubkey then
    local resolve_name = sign_params.selector .. "._domainkey." .. sign_params.domain
    task:get_resolver():resolve_txt({
      task = task,
      name = resolve_name,
      callback = function(_, _, results, err)
        if not err and results and results[1] then
          sign_params.pubkey = results[1]
          sign_params.strict_pubkey_check = not settings.allow_pubkey_mismatch
        elseif not settings.allow_pubkey_mismatch then
          rspamd_logger.errx(task, 'public key for domain %s/%s is not found: %s, skip signing',
            sign_params.domain, sign_params.selector, err)
          return
        else
          rspamd_logger.infox(task, 'public key for domain %s/%s is not found: %s',
            sign_params.domain, sign_params.selector, err)
        end

        local dret, hdr = dkim_sign(task, sign_params)
        if dret then
          arc_sign_seal(task, sign_params, hdr)
        end
      end,
      forced = true
    })
  else
    local dret, hdr = dkim_sign(task, sign_params)
    if dret then
      arc_sign_seal(task, sign_params, hdr)
    end
  end
end

local function sign_error(task, msg)
  rspamd_logger.errx(task, 'signing failure: %s', msg)
end

local function arc_signing_cb(task)
  local ret, selectors = dkim_sign_tools.prepare_dkim_signing(N, task, settings)

  if not ret then
    return
  end

  if settings.use_redis then
    dkim_sign_tools.sign_using_redis(N, task, settings, selectors, do_sign, sign_error)
  else
    if selectors.vault then
      dkim_sign_tools.sign_using_vault(N, task, settings, selectors, do_sign, sign_error)
    else
      -- TODO: no support for multiple sigs
      local cur_selector = selectors[1]
      prepare_arc_selector(task, cur_selector)
      if ((cur_selector.key or cur_selector.rawkey) and cur_selector.selector) then
        if cur_selector.key then
          cur_selector.key = lua_util.template(cur_selector.key, {
            domain = cur_selector.domain,
            selector = cur_selector.selector
          })

          local exists, err = rspamd_util.file_exists(cur_selector.key)
          if not exists then
            if err and err == 'No such file or directory' then
              lua_util.debugm(N, task, 'cannot read key from %s: %s', cur_selector.key, err)
            else
              rspamd_logger.warnx(task, 'cannot read key from %s: %s', cur_selector.key, err)
            end
            return false
          end
        end

        do_sign(task, cur_selector)
      else
        rspamd_logger.infox(task, 'key path or dkim selector unconfigured; no signing')
        return false
      end
    end
  end
end

dkim_sign_tools.process_signing_settings(N, settings, opts)

-- Process ARC-specific maps that aren't handled by dkim_sign_tools
local lua_maps = require "lua_maps"

if opts.whitelisted_signers_map then
  settings.whitelisted_signers_map = lua_maps.map_add_from_ucl(opts.whitelisted_signers_map, 'set',
    'ARC trusted signers domains')
  if not settings.whitelisted_signers_map then
    rspamd_logger.errx(rspamd_config, 'cannot load whitelisted_signers_map')
    settings.whitelisted_signers_map = nil
  else
    rspamd_logger.infox(rspamd_config, 'loaded ARC whitelisted signers map')
  end
end

if opts.whitelist then
  settings.whitelist = lua_maps.map_add_from_ucl(opts.whitelist, 'set',
    'ARC domains with broken implementations')
  if not settings.whitelist then
    rspamd_logger.errx(rspamd_config, 'cannot load ARC whitelist map')
    settings.whitelist = nil
  else
    rspamd_logger.infox(rspamd_config, 'loaded ARC whitelist map')
  end
end

if not dkim_sign_tools.validate_signing_settings(settings) then
  rspamd_logger.infox(rspamd_config, 'mandatory parameters missing, disable arc signing')
  return
end

local ar_opts = rspamd_config:get_all_opt('milter_headers')

if ar_opts and ar_opts.routines then
  local routines = ar_opts.routines

  if routines['authentication-results'] then
    ar_settings = lua_util.override_defaults(ar_settings,
      routines['authentication-results'])
  end
end

if settings.use_redis then
  redis_params = rspamd_parse_redis_server('arc')

  if not redis_params then
    rspamd_logger.errx(rspamd_config, 'no servers are specified, ' ..
      'but module is configured to load keys from redis, disable arc signing')
    return
  end

  settings.redis_params = redis_params
end

local sym_reg_tbl = {
  name = settings['sign_symbol'],
  callback = arc_signing_cb,
  groups = { "policies", "arc" },
  flags = 'ignore_passthrough',
  score = 0.0,
}
if type(settings.allowed_ids) == 'table' then
  sym_reg_tbl.allowed_ids = settings.allowed_ids
end
if type(settings.forbidden_ids) == 'table' then
  sym_reg_tbl.forbidden_ids = settings.forbidden_ids
end

if settings.whitelisted_signers_map then
  arc_symbols.trusted_allow = arc_symbols.trusted_allow or 'ARC_ALLOW_TRUSTED'
  rspamd_config:register_symbol({
    name = arc_symbols.trusted_allow,
    parent = id,
    type = 'virtual',
    score = -2.0,
    group = 'policies',
    groups = { 'arc' },
  })
end

rspamd_config:register_symbol(sym_reg_tbl)

-- Do not sign unless checked
rspamd_config:register_dependency(settings['sign_symbol'], 'ARC_CHECK')
-- We need to check dmarc before signing as we have to produce valid AAR header
-- see #3613
rspamd_config:register_dependency(settings['sign_symbol'], 'DMARC_CHECK')

if settings.adjust_dmarc and settings.whitelisted_signers_map then
  local function arc_dmarc_adjust_cb(task)
    local trusted_arc_ar = task:cache_get(AR_TRUSTED_CACHE_KEY)
    local sym_to_adjust
    if task:has_symbol(ar_settings.dmarc_symbols.reject) then
      sym_to_adjust = ar_settings.dmarc_symbols.reject
    elseif task:has_symbol(ar_settings.dmarc_symbols.quarantine) then
      sym_to_adjust = ar_settings.dmarc_symbols.quarantine
    end
    if sym_to_adjust and trusted_arc_ar and trusted_arc_ar.ar then
      for _, ar in ipairs(trusted_arc_ar.ar) do
        if ar.dmarc then
          local dmarc_fwd = ar.dmarc
          if dmarc_fwd == 'pass' then
            rspamd_logger.infox(task, "adjust dmarc reject score as trusted forwarder "
              .. "proved DMARC validity for %s", ar['header.from'])
            task:adjust_result(sym_to_adjust, 0.1,
              'ARC trusted')
          end
        end
      end
    end
  end
  rspamd_config:register_symbol({
    name = 'ARC_DMARC_ADJUSTMENT',
    callback = arc_dmarc_adjust_cb,
    type = 'callback',
  })
  rspamd_config:register_dependency('ARC_DMARC_ADJUSTMENT', 'DMARC_CHECK')
  rspamd_config:register_dependency('ARC_DMARC_ADJUSTMENT', 'ARC_CHECK')
end
