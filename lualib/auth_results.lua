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

local global = require "global_functions"

local default_settings = {
  spf_symbols = {
    pass = 'R_SPF_ALLOW',
    fail = 'R_SPF_FAIL',
    softfail = 'R_SPF_SOFTFAIL',
    neutral = 'R_SPF_NEUTRAL',
    temperror = 'R_SPF_DNSFAIL',
    none = 'R_SPF_NA',
    permerror = 'R_SPF_PERMFAIL',
  },
  dkim_symbols = {
    pass = 'R_DKIM_ALLOW',
    fail = 'R_DKIM_REJECT',
    temperror = 'R_DKIM_TEMPFAIL',
    none = 'R_DKIM_NA',
    permerror = 'R_DKIM_PERMFAIL',
  },
  dmarc_symbols = {
    pass = 'DMARC_POLICY_ALLOW',
    permerror = 'DMARC_BAD_POLICY',
    temperror = 'DMARC_DNSFAIL',
    none = 'DMARC_NA',
    reject = 'DMARC_POLICY_REJECT',
    softfail = 'DMARC_POLICY_SOFTFAIL',
    quarantine = 'DMARC_POLICY_QUARANTINE',
  },
  arc_symbols = {
    pass = 'ARC_ALLOW',
    permerror = 'ARC_INVALID',
    temperror = 'ARC_DNSFAIL',
    none = 'ARC_NA',
    reject = 'ARC_REJECT',
  },
}

local exports = {}

local function gen_auth_results(task, settings)
  local table = table
  local pairs = pairs
  local ipairs = ipairs
  local auth_results, hdr_parts = {}, {}

  if not settings then
    settings = default_settings
  end

  local auth_types = {
    dkim = settings.dkim_symbols,
    dmarc = settings.dmarc_symbols,
    spf = settings.spf_symbols,
    arc = settings.arc_symbols,
  }

  local common = {
    symbols = {}
  }

  local received = task:get_received_headers() or {}
  local mxname = (received[1] or {}).by_hostname
  if mxname then
    table.insert(hdr_parts, mxname)
  end

  for auth_type, symbols in pairs(auth_types) do
    for key, sym in pairs(symbols) do
      if not common.symbols.sym then
        local s = task:get_symbol(sym)
        if not s then
          common.symbols[sym] = false
        else
          common.symbols[sym] = s
          if not auth_results[auth_type] then
            auth_results[auth_type] = {key}
          else
            table.insert(auth_results[auth_type], key)
          end

          if auth_type ~= 'dkim' then
            break
          end
        end
      end
    end
  end

  for auth_type, keys in pairs(auth_results) do
    for _, key in ipairs(keys) do
      local hdr = ''
      if auth_type == 'dmarc' and key ~= 'none' then
        local opts = common.symbols[auth_types['dmarc'][key]][1]['options'] or {}
        hdr = hdr .. 'dmarc='
        if key == 'reject' or key == 'quarantine' or key == 'softfail' then
          hdr = hdr .. 'fail'
        else
          hdr = hdr .. key
        end
        if key == 'pass' then
          hdr = hdr .. ' policy=' .. opts[2]
          hdr = hdr .. ' header.from=' .. opts[1]
        elseif key ~= 'none' then
          local t = global.rspamd_str_split(opts[1], ' : ')
          local dom = t[1]
          local rsn = t[2]
          if rsn then
            hdr = hdr .. ' reason="' .. rsn .. '"'
          end
          hdr = hdr .. ' header.from=' .. dom
          if key == 'softfail' then
            hdr = hdr .. ' policy=none'
          else
            hdr = hdr .. ' policy=' .. key
          end
        end
        table.insert(hdr_parts, hdr)
      elseif auth_type == 'dkim' and key ~= 'none' then
        if common.symbols[auth_types['dkim'][key]][1] then
          local opts = common.symbols[auth_types['dkim'][key]][1]['options']
          for _, v in ipairs(opts) do
            hdr = hdr .. auth_type .. '=' .. key .. ' header.d=' .. v
            table.insert(hdr_parts, hdr)
          end
        end
      elseif auth_type == 'arc' and key ~= 'none' then
        if common.symbols[auth_types['arc'][key]][1] then
          local opts = common.symbols[auth_types['arc'][key]][1]['options'] or {}
          for _, v in ipairs(opts) do
            hdr = hdr .. auth_type .. '=' .. key .. ' (' .. v .. ')'
            table.insert(hdr_parts, hdr)
          end
        end
      elseif auth_type == 'spf' and key ~= 'none' then
        hdr = hdr .. auth_type .. '=' .. key
        local smtp_from = task:get_from('smtp')
        if smtp_from['addr'] ~= '' and smtp_from['addr'] ~= nil then
          hdr = hdr .. ' smtp.mailfrom=' .. smtp_from['addr']
        else
          local helo = task:get_helo()
          if helo then
            hdr = hdr .. ' smtp.helo=' .. task:get_helo()
          end
        end
        table.insert(hdr_parts, hdr)
      end
    end
  end

  local u = task:get_user()
  local smtp_from = task:get_from('smtp')

  if u and smtp_from then
    local hdr

    if #smtp_from[1]['addr'] > 0 then
      hdr = string.format('auth=pass smtp.auth=%s smtp.mailfrom=%s',
        u, smtp_from[1]['addr'])
    else
      hdr = string.format('auth=pass smtp.auth=%s', u)
    end

    table.insert(hdr_parts, hdr)
  end

  if #hdr_parts > 0 then
    return table.concat(hdr_parts, '; ')
  end

  return nil
end

exports.gen_auth_results = gen_auth_results

return exports
