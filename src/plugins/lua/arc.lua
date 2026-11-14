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
local lua_mime = require "lua_mime"
local hash = require "rspamd_cryptobox_hash"
local dynconf = require "lua_dynconf"

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
local dkim_load_sign_key = rspamd_plugins.dkim.load_sign_key
local dkim_sign_key_get_alg = rspamd_plugins.dkim.sign_key_get_alg
local dkim_sign_digest = rspamd_plugins.dkim.sign_digest
local dkim_canonicalize = rspamd_plugins.dkim.canon_header_relaxed
local redis_params

if not dkim_verify or not dkim_sign or not dkim_canonicalize then
  rspamd_logger.errx(rspamd_config, "cannot enable arc plugin: dkim is disabled")
  return
end

local default_symbols = {
  allow = 'ARC_ALLOW',
  invalid = 'ARC_INVALID',
  dnsfail = 'ARC_DNSFAIL',
  na = 'ARC_NA',
  reject = 'ARC_REJECT',
}

local settings = {
  symbols = lua_util.shallowcopy(default_symbols),
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
  trusted_authserv_id = nil,     -- AuthservID to match when reusing auth results
  whitelisted_signers_map = nil, -- Trusted signers domains
  whitelist = nil,               -- Domains with broken ARC implementations to trust despite validation failures
  adjust_dmarc = true,           -- Adjust DMARC rejected policy for trusted forwarders
  allowed_ids = nil,             -- Allowed settings id
  forbidden_ids = nil,           -- Banned settings id
}

-- To match normal AR
local ar_settings = lua_auth_results.default_settings

-- Get Authentication-Results header, optionally filtering by trusted authserv-id
local function get_trusted_ar_header(task)
  -- The values as they are, not decoded: they are copied into the seal, and an
  -- encoded-word decoded in a comment would close it and add a result
  local ar_headers = task:get_header_full('Authentication-Results')

  if not ar_headers or #ar_headers == 0 then
    return nil
  end

  if settings.trusted_authserv_id then
    for _, hdr in ipairs(ar_headers) do
      local authserv_id = string.match(hdr.value or '', '^%s*([^;%s]+)')
      if authserv_id and authserv_id == settings.trusted_authserv_id then
        lua_util.debugm(N, task, 'found trusted AR header with authserv-id: %s', authserv_id)
        return hdr.value
      end
    end
    lua_util.debugm(N, task, 'no AR header matched trusted authserv-id: %s',
        settings.trusted_authserv_id)
    return nil
  end

  return ar_headers[1].value
end

local function parse_arc_header(hdr, target, is_aar)
  -- v[1] is the key and v[2] is the value
  local function fill_arc_header_table(v, t)
    if v[1] and v[2] then
      local key = lua_util.rspamd_str_trim(v[1])
      local value = lua_util.rspamd_str_trim(v[2])
      t[key] = value
    end
  end

  for i, val in ipairs(hdr) do
    if not target[i] then
      target[i] = {}
    end

    if not is_aar then
      -- For ARC-Seal / ARC-Message-Signature: split by ';' then by '='
      local elts = fun.totable(fun.map(lua_util.rspamd_str_trim,
        fun.filter(function(v)
            return v and #v > 0
          end,
          lua_util.rspamd_str_split(val.decoded, ';')
        )
      ))
      fun.each(function(v)
          fill_arc_header_table(v, target[i])
        end,
        fun.map(function(elt)
          return lua_util.rspamd_str_split(elt, '=')
        end, elts)
      )
    else
      -- For AAR: a parser that respects comments and quoted strings when
      -- splitting on ';' (fixes #5963); comments nested too deep give no
      -- AAR, which fails the chain
      -- Not the decoded value: an encoded-word decoded in a comment (e.g. the
      -- sender a forwarder put there) would close it and add a result
      local parsed = lua_auth_results.parse_aar_header(val.value)
      if parsed then
        if parsed.i then
          target[i].i = parsed.i
        end
        if parsed.ar then
          target[i].ar = parsed.ar
        end
        target[i].truncated = parsed.truncated
      end
    end

    target[i].header = val.decoded
    target[i].raw_header = val.value
  end

  -- sort by i= attribute
  table.sort(target, function(a, b)
    return (tonumber(a.i) or 0) < (tonumber(b.i) or 0)
  end)
end

-- The results of a method in an AAR: only the result of the method of an
-- element counts, other `key=value` pairs are properties, or text that a
-- comment failed to hide
local function aar_method_results(aar, method)
  local res = {}
  for _, ar in ipairs(aar.ar or {}) do
    if ar.method == method and ar[method] then
      table.insert(res, ar)
    end
  end
  return res
end

-- The DMARC results that a split on every ';' finds, ignoring comments and
-- quotes: text that should have been a comment (a sender written unescaped)
-- may open a quote or a comment that hides a later result from the split
-- that respects them
local function naive_dmarc_count(raw)
  -- Each place where an element can start one: after ';' or after a comment
  -- in front of it, blanks between. Never fewer than the split finds
  local n = 0
  for _ in (';' .. raw):gmatch('[;)]%s*[Dd][Mm][Aa][Rr][Cc]%s*[/=]') do
    n = n + 1
  end
  return n
end

-- The DMARC result of an AAR: a forwarder writes one. More of them means that
-- text that should have been a comment looks like a result: when unsure, do
-- not take any. The second value is true then
local function aar_dmarc_result(aar)
  local res = aar_method_results(aar, 'dmarc')
  -- An AAR too long to be read gives no result to trust either
  if aar.truncated or #res > 1 or (aar.raw_header and naive_dmarc_count(aar.raw_header) > #res) then
    return nil, true
  end
  return res[1], false
end

local function arc_validate_seals(task, seals, sigs, ars)
  local fail_reason
  -- Each ARC set must contain exactly one AAR; extra AARs are not covered
  -- by any seal and must not be used as trusted results
  if #ars ~= #seals then
    fail_reason = string.format('invalid count of ARC-Authentication-Results: %d, expected %d',
      #ars, #seals)
    rspamd_logger.infox(task, fail_reason)
    task:insert_result(settings.symbols['invalid'], 1.0, fail_reason)
    return false, fail_reason
  end
  for i = 1, #seals do
    if (sigs[i].i or 0) ~= i then
      fail_reason = string.format('bad i for signature: %d, expected %d; d=%s',
        sigs[i].i, i, sigs[i].d)
      rspamd_logger.infox(task, fail_reason)
      task:insert_result(settings.symbols['invalid'], 1.0, fail_reason)
      return false, fail_reason
    end
    if (seals[i].i or 0) ~= i then
      fail_reason = string.format('bad i for seal: %d, expected %d; d=%s',
        seals[i].i, i, seals[i].d)
      rspamd_logger.infox(task, fail_reason)
      task:insert_result(settings.symbols['invalid'], 1.0, fail_reason)
      return false, fail_reason
    end
    if (tonumber(ars[i].i) or 0) ~= i then
      fail_reason = string.format('bad i for authentication results: %s, expected %d',
        tostring(ars[i].i), i)
      rspamd_logger.infox(task, fail_reason)
      task:insert_result(settings.symbols['invalid'], 1.0, fail_reason)
      return false, fail_reason
    end

    if not seals[i].cv then
      fail_reason = string.format('no cv on i=%d', i)
      task:insert_result(settings.symbols['invalid'], 1.0, fail_reason)
      return false, fail_reason
    end

    if i == 1 then
      -- We need to ensure that cv of seal is equal to 'none'
      if seals[i].cv ~= 'none' then
        fail_reason = 'cv is not "none" for i=1'
        task:insert_result(settings.symbols['invalid'], 1.0, fail_reason)
        return false, fail_reason
      end
    else
      if seals[i].cv ~= 'pass' then
        fail_reason = string.format('cv is %s on i=%d', seals[i].cv, i)
        task:insert_result(settings.symbols['reject'], 1.0, fail_reason)
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

  lua_util.debugm(N, task, 'ARC verification: found %s ARC-MS, %s ARC-Seal, %s ARC-AR headers',
                  arc_sig_headers and #arc_sig_headers or 0,
                  arc_seal_headers and #arc_seal_headers or 0,
                  arc_ar_headers and #arc_ar_headers or 0)

  if arc_sig_headers then
    for i, hdr in ipairs(arc_sig_headers) do
      lua_util.debugm(N, task, 'ARC-Message-Signature[%s]: %s', i, hdr.decoded)
    end
  end

  if arc_seal_headers then
    for i, hdr in ipairs(arc_seal_headers) do
      lua_util.debugm(N, task, 'ARC-Seal[%s]: %s', i, hdr.decoded)
    end
  end

  if arc_ar_headers then
    for i, hdr in ipairs(arc_ar_headers) do
      lua_util.debugm(N, task, 'ARC-Authentication-Results[%s]: %s', i, hdr.decoded)
    end
  end

  if not arc_sig_headers or not arc_seal_headers then
    lua_util.debugm(N, task, 'ARC verification failed: missing required headers')
    task:insert_result(settings.symbols['na'], 1.0)
    return
  end

  -- A chain that fails here is not sealed further either (see 'arc-failure')
  local function fail_chain(reason)
    task:insert_result(settings.symbols['invalid'], 1.0, reason)
    task:cache_set('arc-failure', reason)
  end

  if #arc_seal_headers > 50 or (arc_ar_headers and #arc_ar_headers > 50) then
    -- RFC 8617 5.2: at most 50 sets, else the chain fails
    fail_chain('too many ARC sets')
    return
  end

  if #arc_sig_headers ~= #arc_seal_headers then
    -- We mandate that count of seals is equal to count of signatures
    rspamd_logger.infox(task, 'number of seals (%s) is not equal to number of signatures (%s)',
      #arc_seal_headers, #arc_sig_headers)
    fail_chain('invalid count of seals and signatures')
    return
  end

  if arc_ar_headers and #arc_ar_headers ~= #arc_seal_headers then
    -- Each set has one AAR (checked again with the seals): not parsed for nothing
    fail_chain(string.format('invalid count of ARC-Authentication-Results: %d, expected %d',
      #arc_ar_headers, #arc_seal_headers))
    return
  end

  local cbdata = {
    seals = {},
    sigs = {},
    ars = {},
    res = 'success',
    errors = {},
    -- Count all seals up front: cached keys can complete verification inline.
    seals_remaining = #arc_seal_headers,
    seal_domains = {},
    seal_verified = {},
  }

  parse_arc_header(arc_seal_headers, cbdata.seals, false)
  parse_arc_header(arc_sig_headers, cbdata.sigs, false)

  if arc_ar_headers then
    -- Results that the parser cannot read fail the chain
    local ok, err = pcall(parse_arc_header, arc_ar_headers, cbdata.ars, true)
    if not ok then
      rspamd_logger.infox(task, 'cannot parse ARC-Authentication-Results: %s', err)
      fail_chain('cannot parse ARC-Authentication-Results')
      return
    end
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
    cbdata.ars)
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

  local function finish_arc_seals()
    if cbdata.res ~= 'success' then
      task:insert_result(settings.symbols.reject, 1.0,
        rspamd_logger.slog('seal check failed: %s, %s', cbdata.res,
          cbdata.errors))
      return
    end

    -- Publish trust only after the entire chain succeeds, in instance order.
    if settings.whitelisted_signers_map then
      -- A forwarder vouches for the message as it passed it on, not for what
      -- the later hops did to it: anyone can add an ARC set of their own after
      -- a genuine one, and change the message on the way. So a trusted
      -- forwarder counts only if every later instance up to N, the hop that
      -- handed the message to us, is a trusted forwarder too.
      local first_trusted = #cbdata.seals + 1
      if not cbdata.ams_verified then
        -- The whitelist keeps the chain valid, but without the newest AMS
        -- the AARs can belong to any message
        rspamd_logger.infox(task, 'do not trust forwarders: the newest ARC-Message-Signature ' ..
          'was not verified')
      end
      for index = cbdata.ams_verified and #cbdata.seals or 0, 1, -1 do
        -- The d= whose key verified the seal, as the C parser read it:
        -- our own split of the header can see a different d=
        local domain = cbdata.seal_domains[index]
        if not settings.whitelisted_signers_map:get_key(domain) then
          break
        end
        if not cbdata.seal_verified[index] then
          -- The whitelist keeps the chain valid, but a failed seal does not
          -- authenticate its d= or the AAR of its instance
          rspamd_logger.infox(task, 'do not trust forwarder %s on i=%s: its seal was not verified',
            domain, index)
          break
        end
        first_trusted = index
      end

      local trusted_aars = {}
      for index, sig in ipairs(cbdata.seals) do
        local domain = cbdata.seal_domains[index]
        if index < first_trusted then
          if cbdata.ams_verified and cbdata.seal_verified[index] and
              settings.whitelisted_signers_map:get_key(domain) then
            rspamd_logger.infox(task, 'do not trust forwarder %s on i=%s: a later hop is not trusted',
              domain, index)
          end
        else
          -- Whitelisted signer has been found in a valid chain
          local mult = 1.0
          local cur_aar = cbdata.ars[index]
          if not cur_aar then
            rspamd_logger.warnx(task, "cannot find Arc-Authentication-Results for trusted " ..
              "forwarder %s on i=%s", domain, index)
          else
            table.insert(trusted_aars, cur_aar)
            local dmarc, ambiguous = aar_dmarc_result(cur_aar)
            local dmarc_fwd = dmarc and dmarc.dmarc
            if ambiguous then
              rspamd_logger.infox(task, 'forwarder %s on i=%s has more than one DMARC result',
                domain, index)
              mult = 0.0
            elseif dmarc_fwd == 'reject' or dmarc_fwd == 'fail' or dmarc_fwd == 'quarantine' then
              lua_util.debugm(N, "found rejected dmarc on forwarding")
              mult = 0.0
            elseif dmarc_fwd ~= 'pass' then
              for _, ar in ipairs(aar_method_results(cur_aar, 'spf')) do
                local spf_fwd = ar.spf
                if spf_fwd == 'reject' or spf_fwd == 'fail' or spf_fwd == 'quarantine' then
                  lua_util.debugm(N, "found rejected spf on forwarding")
                  mult = 0.5
                end
              end
            end
          end
          task:insert_result(settings.symbols.trusted_allow, mult,
            string.format('%s:s=%s:i=%d', domain, sig.s, index))
        end
      end

      if #trusted_aars > 0 then
        -- In instance order
        task:cache_set(AR_TRUSTED_CACHE_KEY, trusted_aars)
      end
    end

    local index = #cbdata.seals
    local sig = cbdata.seals[index]
    local arc_allow_result = string.format('%s:s=%s:i=%d',
      cbdata.seal_domains[index], sig.s, index)
    task:insert_result(settings.symbols.allow, 1.0, arc_allow_result)
    task:cache_set('arc-allow', arc_allow_result)
  end

  local function gen_arc_seal_cb(index, sig)
    return function(_, res, err, domain)
      -- Also used when verification cannot start and no callback is scheduled.
      if cbdata.seal_domains[index] then
        return
      end
      domain = domain or sig.d or ''
      cbdata.seal_domains[index] = domain
      cbdata.seal_verified[index] = res and true or false
      lua_util.debugm(N, task, 'checked arc seal: %s(%s), %s processed',
        res, err, index)

      if not res then
        if settings.whitelist and settings.whitelist:get_key(domain) then
          rspamd_logger.infox(task, 'ARC seal validation failed for whitelisted domain %s, treating as valid: %s',
            domain, err)
          lua_util.debugm(N, task, 'whitelisted domain %s ARC seal failure ignored', domain)
        else
          cbdata.res = 'fail'
          table.insert(cbdata.errors, string.format('seal:%s:s=%s:i=%s:%s',
            domain, sig.s or '', sig.i or '', err or 'verification failed'))
        end
      end

      cbdata.seals_remaining = cbdata.seals_remaining - 1
      if cbdata.seals_remaining == 0 then
        finish_arc_seals()
      end
    end
  end

  local function arc_signature_cb(_, res, err, domain)
    lua_util.debugm(N, task, 'checked arc signature %s: %s(%s)',
      domain, res, err)
    -- Only the newest AMS binds the sealed AARs to this message
    cbdata.ams_verified = res and true or false

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
        local callback = gen_arc_seal_cb(i, sig)
        local ret, lerr = dkim_verify(task, sig.header, callback, 'arc-seal')
        if not ret then
          callback(task, false, lerr, sig.d)
        end
      end
    else
      task:insert_result(settings.symbols['reject'], 1.0,
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

  local sig = cbdata.sigs[#cbdata.sigs] -- last AMS
  local ret, err = dkim_verify(task, sig.header, arc_signature_cb, 'arc-sign')

  if not ret then
    -- No callback is scheduled, so complete the signature check here
    arc_signature_cb(task, false, err or 'verification failed', sig.d or '')
  else
    lua_util.debugm(N, task, 'processed arc signature %s[%s]: %s(%s), %s total',
      sig.d, sig.i, ret, err, #cbdata.seals)
  end
end

local opts = rspamd_config:get_all_opt('arc')
if not opts or type(opts) ~= 'table' then
  return
end

local dyn_settings, dyn_err = dynconf.register(N, {
  defaults = settings,
  opts = opts,
  dynamic = {
    'trusted_authserv_id',
    'reuse_auth_results',
    'check_pubkey',
    'allow_pubkey_mismatch',
  },
})
if not dyn_settings then
  rspamd_logger.errx(rspamd_config, 'cannot configure %s: %s', N, dyn_err)
  lua_util.disable_module(N, 'config')
  return
end
settings = dyn_settings

-- Only known symbol names are configurable, and only when the value is truthy
do
  local user_symbols = type(opts.symbols) == 'table' and opts.symbols or {}
  local res = {}
  for k, v in pairs(default_symbols) do
    res[k] = user_symbols[k] or v
  end
  settings.symbols = res
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
  name = settings.symbols['allow'],
  parent = id,
  type = 'virtual',
  score = -1.0,
  group = 'policies',
  groups = { 'arc' },
})
rspamd_config:register_symbol({
  name = settings.symbols['reject'],
  parent = id,
  type = 'virtual',
  score = 2.0,
  group = 'policies',
  groups = { 'arc' },
})
rspamd_config:register_symbol({
  name = settings.symbols['invalid'],
  parent = id,
  type = 'virtual',
  score = 1.0,
  group = 'policies',
  groups = { 'arc' },
})
rspamd_config:register_symbol({
  name = settings.symbols['dnsfail'],
  parent = id,
  type = 'virtual',
  score = 0.0,
  group = 'policies',
  groups = { 'arc' },
})
rspamd_config:register_symbol({
  name = settings.symbols['na'],
  parent = id,
  type = 'virtual',
  score = 0.0,
  group = 'policies',
  groups = { 'arc' },
})

-- Weak deps: ARC verification works without SPF/DKIM, just less info in AAR header
rspamd_config:register_dependency('ARC_CHECK', 'SPF_CHECK')
rspamd_config:register_dependency('ARC_CHECK', 'DKIM_CHECK')

local function arc_sign_seal(task, params, header)
  local arc_seals = task:cache_get('arc-seals')
  local cur_auth_results

  if settings.reuse_auth_results then
    local ar_header = get_trusted_ar_header(task)

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

  -- Create ARC-Seal signature manually using SHA256 hash
  -- We must canonicalize all ARC headers in order and sign them
  local sha_ctx = hash.create_specific('sha256')

  -- Canonicalize previous ARC sets if they exist (arc_seals already retrieved above)
  local arc_sigs = task:cache_get('arc-sigs')
  local arc_auth_results = task:cache_get('arc-authres')

  if arc_seals then
    for i = 1, #arc_seals do
      if arc_auth_results[i] then
        local s = dkim_canonicalize('ARC-Authentication-Results', arc_auth_results[i].raw_header)
        sha_ctx:update(s)
        lua_util.debugm(N, task, 'canonicalized previous AAR[%d]: %s', i, s)
      end
      if arc_sigs[i] then
        local s = dkim_canonicalize('ARC-Message-Signature', arc_sigs[i].raw_header)
        sha_ctx:update(s)
        lua_util.debugm(N, task, 'canonicalized previous AMS[%d]: %s', i, s)
      end
      if arc_seals[i] then
        local s = dkim_canonicalize('ARC-Seal', arc_seals[i].raw_header)
        sha_ctx:update(s)
        lua_util.debugm(N, task, 'canonicalized previous AS[%d]: %s', i, s)
      end
    end
  end

  -- Canonicalize the new ARC-Authentication-Results header
  local s = dkim_canonicalize('ARC-Authentication-Results', cur_auth_results)
  sha_ctx:update(s)
  lua_util.debugm(N, task, 'canonicalized new AAR: %s', s)

  -- Canonicalize the new ARC-Message-Signature header
  s = dkim_canonicalize('ARC-Message-Signature', header)
  sha_ctx:update(s)
  lua_util.debugm(N, task, 'canonicalized new AMS: %s', s)

  -- Load the signing key
  local sign_key = dkim_load_sign_key(task, {
    key = params.key,
    rawkey = params.rawkey,
  })

  if not sign_key then
    rspamd_logger.errx(task, 'cannot load signing key')
    return
  end

  -- Get the algorithm from the key
  local algorithm = dkim_sign_key_get_alg(sign_key)
  if not algorithm or algorithm == 'unknown' then
    rspamd_logger.errx(task, 'cannot determine key algorithm')
    return
  end

  -- Construct partial ARC-Seal header (without signature) using detected algorithm
  local cur_arc_seal = string.format('i=%d; a=%s; d=%s; s=%s; cv=%s; t=%d; b=',
    cur_idx, algorithm, params.domain, params.selector, params.arc_cv,
    math.floor(rspamd_util.get_time()))

  -- Canonicalize the partial ARC-Seal and add to hash
  local seal_canon = string.format('%s:%s', 'arc-seal', cur_arc_seal)
  sha_ctx:update(seal_canon)
  lua_util.debugm(N, task, 'canonicalized partial seal: %s', seal_canon)

  -- Now sign the complete digest
  local dret, sig_b64 = dkim_sign_digest(task, {
    sign_key = sign_key,
    digest = sha_ctx:bin(),
  })

  if not dret or not sig_b64 then
    rspamd_logger.errx(task, 'cannot create ARC seal signature')
    return
  end

  -- Get appropriate line ending
  local nl_type
  if task:has_flag("milter") then
    nl_type = "lf"
  else
    nl_type = task:get_newlines_type()
  end

  -- Fold the signature to 70 chars per line
  local folded_sig = rspamd_util.encode_base64(rspamd_util.decode_base64(sig_b64), 70, nl_type)
  cur_arc_seal = cur_arc_seal .. folded_sig

  -- Add all ARC headers with a deterministic order. Each header is prepended
  -- (order = 1), and the `order` list controls the emission sequence, so the
  -- resulting message has ARC-Seal, ARC-Message-Signature, ARC-Authentication-Results
  -- top to bottom. Some validators (e.g. O365) reject sets in any other layout.
  lua_util.debugm(N, task, 'adding ARC-Authentication-Results: %s', cur_auth_results)
  lua_util.debugm(N, task, 'adding ARC-Message-Signature: %s', header)
  lua_util.debugm(N, task, 'adding ARC-Seal: %s', cur_arc_seal)

  lua_mime.modify_headers(task, {
    add = {
      ['ARC-Authentication-Results'] = { order = 1, value = cur_auth_results },
      ['ARC-Message-Signature'] = { order = 1, value = header },
      ['ARC-Seal'] = {
        order = 1,
        value = lua_util.fold_header_with_encoding(task,
          'ARC-Seal', cur_arc_seal,
          { structured = true, encode = false })
      }
    },
    -- Emission order: each header is prepended, so listing AAR, AMS, AS here
    -- yields AS, AMS, AAR in the final message (newest seal on top)
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
      local ar_header = get_trusted_ar_header(task)

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

-- `symbols` is already merged with the defaults in settings: do not let the raw (possibly partial)
-- user table replace it
do
  local signing_opts = {}
  for k, v in pairs(opts) do
    if k ~= 'symbols' then
      signing_opts[k] = v
    end
  end
  dkim_sign_tools.process_signing_settings(N, settings, signing_opts)
end

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
  settings.symbols.trusted_allow = settings.symbols.trusted_allow or 'ARC_ALLOW_TRUSTED'
  rspamd_config:register_symbol({
    name = settings.symbols.trusted_allow,
    parent = id,
    type = 'virtual',
    score = -2.0,
    group = 'policies',
    groups = { 'arc' },
    one_shot = true,
  })
end

rspamd_config:register_symbol(sym_reg_tbl)

-- Hard: ARC signing needs arc-seals cache from ARC_CHECK
rspamd_config:register_dependency(settings['sign_symbol'], 'ARC_CHECK', true)
-- Hard: ARC signing needs DMARC result for valid AAR header (#3613)
rspamd_config:register_dependency(settings['sign_symbol'], 'DMARC_CHECK', true)

if settings.adjust_dmarc and settings.whitelisted_signers_map then
  -- A domain as DMARC compares it: lowercase A-labels, no trailing dot
  local function normalize_domain(task, domain)
    if type(domain) ~= 'string' then
      return nil
    end
    -- Some implementations put an address there
    domain = domain:match('^<?(.-)>?$'):match('([^@]*)$'):gsub('%.$', '')
    if domain == '' then
      return nil
    end
    if domain:find('[\128-\255]') then
      domain = task:get_resolver():idna_convert_utf8(domain, task:get_mempool())
      -- What does not convert comes back with U+FFFD
      if not domain or domain:find('[\128-\255]') then
        return nil
      end
    end
    return domain:lower()
  end

  local function arc_dmarc_adjust_cb(task)
    local trusted_aars = task:cache_get(AR_TRUSTED_CACHE_KEY)
    local sym_to_adjust
    if task:has_symbol(ar_settings.dmarc_symbols.reject) then
      sym_to_adjust = ar_settings.dmarc_symbols.reject
    elseif task:has_symbol(ar_settings.dmarc_symbols.quarantine) then
      sym_to_adjust = ar_settings.dmarc_symbols.quarantine
    end
    if not sym_to_adjust or not trusted_aars then
      return
    end
    -- A forwarder proves DMARC for the From it saw, which must be the From
    -- that DMARC has checked here (the one the message came with)
    local from = task:get_from({ 'mime', 'orig' })
    if not from or not from[1] or from[2] then
      return
    end
    local from_domain = normalize_domain(task, from[1].domain)
    if not from_domain then
      return
    end
    for _, aar in ipairs(trusted_aars) do
      local ar = aar_dmarc_result(aar)
      if ar and ar.dmarc == 'pass' then
        local proved_domain = normalize_domain(task, ar['header.from'])
        if proved_domain == from_domain then
          rspamd_logger.infox(task, "adjust dmarc reject score as trusted forwarder "
            .. "proved DMARC validity for %s", from_domain)
          task:adjust_result(sym_to_adjust, 0.1,
            'ARC trusted')
          return
        end
        rspamd_logger.infox(task, "do not adjust dmarc reject score: trusted forwarder "
          .. "proved DMARC validity for %s, not for %s", proved_domain, from_domain)
      end
    end
  end

  rspamd_config:register_symbol({
    name = 'ARC_DMARC_ADJUSTMENT',
    callback = arc_dmarc_adjust_cb,
    type = 'callback',
  })
  -- Hard: reads both DMARC policy symbols and ARC trusted cache
  rspamd_config:register_dependency('ARC_DMARC_ADJUSTMENT', 'DMARC_CHECK', true)
  rspamd_config:register_dependency('ARC_DMARC_ADJUSTMENT', 'ARC_CHECK', true)
end
