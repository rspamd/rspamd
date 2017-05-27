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
local fun = require "fun"

if confighelp then
  return
end

local N = 'arc'
local dkim_verify = rspamd_plugins.dkim.verify

local arc_symbols = {
  allow = 'ARC_POLICY_ALLOW',
  invalid = 'ARC_BAD_POLICY',
  dnsfail = 'ARC_DNSFAIL',
  na = 'ARC_NA',
  reject = 'ARC_POLICY_REJECT',
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
  end
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
  for i = 1,#cbdata.seals do
    if (cbdata.sigs[i].i or 0) ~= i then
      rspamd_logger.infox(task, 'bad i value for signature: %s, expected %s',
        cbdata.sigs[i].i, i)
      task:insert_result(arc_symbols['invalid'], 1.0, 'invalid count of seals and signatures')
      return
    end
    if (cbdata.seals[i].i or 0) ~= i then
      rspamd_logger.infox(task, 'bad i value for seal: %s, expected %s',
        cbdata.seals[i].i, i)
      task:insert_result(arc_symbols['invalid'], 1.0, 'invalid count of seals and signatures')
      return
    end

    cbdata.sigs[i].header = arc_sig_headers[i].decoded
    cbdata.seals[i].header = arc_seal_headers[i].decoded
  end

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
        task:insert_result(arc_symbols['allow'], 1.0, cbdata.errors)
      else
        task:insert_result(arc_symbols['reject'], 1.0, cbdata.errors)
      end
    end
  end

  local function arc_signature_cb(_, res, err, domain)
    cbdata.checked = cbdata.checked + 1

    rspamd_logger.debugm(N, task, 'checked arc signature %s: %s(%s), %s processed',
      domain, res, err, cbdata.checked)

    if not res then
      cbdata.res = 'fail'
      if err and domain then
        table.insert(cbdata.errors, string.format('sig:%s:%s', domain, err))
      end
    end

    if cbdata.checked == #arc_sig_headers then
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
        task:insert_result(arc_symbols['reject'], 1.0, cbdata.errors)
      end
    end
  end

  -- Now we can verify all signatures
  fun.each(
    function(sig)
      local ret,err = dkim_verify(task, sig.header, arc_signature_cb, 'arc-sign')

      if not ret then
        cbdata.res = 'fail'
        table.insert(cbdata.errors, string.format('sig:%s:%s', sig.d or '', err))
        cbdata.checked = cbdata.checked + 1
        rspamd_logger.debugm(N, task, 'checked arc sig %s: %s(%s), %s processed',
          sig.d, ret, err, cbdata.checked)
      end
    end, cbdata.sigs)

  if cbdata.checked == #arc_sig_headers then
    task:insert_result(arc_symbols['reject'], 1.0, cbdata.errors)
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
  group = 'arc',
})
rspamd_config:register_symbol({
  name = arc_symbols['reject'],
  parent = id,
  type = 'virtual',
  score = 2.0,
  group = 'arc',
})
rspamd_config:register_symbol({
  name = arc_symbols['invalid'],
  parent = id,
  type = 'virtual',
  score = 1.0,
  group = 'arc',
})
rspamd_config:register_symbol({
  name = arc_symbols['dnsfail'],
  parent = id,
  type = 'virtual',
  score = 0.0,
  group = 'arc',
})
rspamd_config:register_symbol({
  name = arc_symbols['na'],
  parent = id,
  type = 'virtual',
  score = 0.0,
  group = 'arc',
})

rspamd_config:register_dependency(id, symbols['spf_allow_symbol'])
rspamd_config:register_dependency(id, symbols['dkim_allow_symbol'])