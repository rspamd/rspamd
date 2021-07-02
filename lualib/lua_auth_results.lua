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

local rspamd_util = require "rspamd_util"
local lua_util = require "lua_util"

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
  dkim_symbols = {
    none = 'R_DKIM_NA',
  },
  add_smtp_user = true,
}

local exports = {
  default_settings = default_settings
}

local local_hostname = rspamd_util.get_hostname()

local function gen_auth_results(task, settings)
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

  local mta_hostname = task:get_request_header('MTA-Name') or
      task:get_request_header('MTA-Tag')
  if mta_hostname then
    mta_hostname = tostring(mta_hostname)
  else
    mta_hostname = local_hostname
  end

  table.insert(hdr_parts, mta_hostname)

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

  local dkim_results = task:get_dkim_results()
  -- For each signature we set authentication results
  -- dkim=neutral (body hash did not verify) header.d=example.com header.s=sel header.b=fA8VVvJ8;
  -- dkim=neutral (body hash did not verify) header.d=example.com header.s=sel header.b=f8pM8o90;

  for _,dres in ipairs(dkim_results) do
    local ar_string = 'none'

    if dres.result == 'reject' then
      ar_string = 'fail' -- imply failure, not neutral
    elseif dres.result == 'allow' then
      ar_string = 'pass'
    elseif dres.result == 'bad record' or dres.result == 'permerror' then
      ar_string = 'permerror'
    elseif dres.result == 'tempfail' then
      ar_string = 'temperror'
    end
    local hdr = {}

    hdr[1] = string.format('dkim=%s', ar_string)

    if dres.fail_reason then
      hdr[#hdr + 1] = string.format('(%s)', lua_util.maybe_smtp_quote_value(dres.fail_reason))
    end

    if dres.domain then
      hdr[#hdr + 1] = string.format('header.d=%s', lua_util.maybe_smtp_quote_value(dres.domain))
    end

    if dres.selector then
      hdr[#hdr + 1] = string.format('header.s=%s', lua_util.maybe_smtp_quote_value(dres.selector))
    end

    if dres.bhash then
      hdr[#hdr + 1] = string.format('header.b=%s', lua_util.maybe_smtp_quote_value(dres.bhash))
    end

    table.insert(hdr_parts, table.concat(hdr, ' '))
  end

  if #dkim_results == 0 then
    -- We have no dkim results, so check for DKIM_NA symbol
    if common.symbols[settings.dkim_symbols.none] then
      table.insert(hdr_parts, 'dkim=none')
    end
  end

  for auth_type, keys in pairs(auth_results) do
    for _, key in ipairs(keys) do
      local hdr = ''
      if auth_type == 'dmarc' then
        local opts = common.symbols[auth_types['dmarc'][key]][1]['options'] or {}
        hdr = hdr .. 'dmarc='
        if key == 'reject' or key == 'quarantine' or key == 'softfail' then
          hdr = hdr .. 'fail'
        else
          hdr = hdr .. lua_util.maybe_smtp_quote_value(key)
        end
        if key == 'pass' then
          hdr = hdr .. ' (policy=' .. lua_util.maybe_smtp_quote_value(opts[2]) .. ')'
          hdr = hdr .. ' header.from=' .. lua_util.maybe_smtp_quote_value(opts[1])
        elseif key ~= 'none' then
          local t = {opts[1]:match('^([^%s]+) : (.*)$')}
          if #t > 0 then
            local dom = t[1]
            local rsn = t[2]
            if rsn then
              hdr = string.format('%s reason=%s', hdr, lua_util.maybe_smtp_quote_value(rsn))
            end
            hdr = string.format('%s header.from=%s', hdr, lua_util.maybe_smtp_quote_value(dom))
          end
          if key == 'softfail' then
            hdr = hdr .. ' (policy=none)'
          else
            hdr = hdr .. ' (policy=' .. lua_util.maybe_smtp_quote_value(key) .. ')'
          end
        end
        table.insert(hdr_parts, hdr)
      elseif auth_type == 'arc' then
        if common.symbols[auth_types['arc'][key]][1] then
          local opts = common.symbols[auth_types['arc'][key]][1]['options'] or {}
          for _, v in ipairs(opts) do
            hdr = string.format('%s%s=%s (%s)', hdr, auth_type,
                lua_util.maybe_smtp_quote_value(key), lua_util.maybe_smtp_quote_value(v))
            table.insert(hdr_parts, hdr)
          end
        end
      elseif auth_type == 'spf' then
        -- Main type
        local sender
        local sender_type
        local smtp_from = task:get_from({'smtp','orig'})

        if smtp_from and
            smtp_from[1] and
            smtp_from[1]['addr'] ~= '' and
            smtp_from[1]['addr'] ~= nil then
          sender = lua_util.maybe_smtp_quote_value(smtp_from[1]['addr'])
          sender_type = 'smtp.mailfrom'
        else
          local helo = task:get_helo()
          if helo then
            sender = lua_util.maybe_smtp_quote_value(helo)
            sender_type = 'smtp.helo'
          end
        end

        if sender and sender_type then
          -- Comment line
          local comment = ''
          if key == 'pass' then
            comment = string.format('%s: domain of %s designates %s as permitted sender',
                mta_hostname, sender, tostring(task:get_from_ip() or 'unknown'))
          elseif key == 'fail' then
            comment = string.format('%s: domain of %s does not designate %s as permitted sender',
                mta_hostname, sender, tostring(task:get_from_ip() or 'unknown'))
          elseif key == 'neutral' or key == 'softfail' then
            comment = string.format('%s: %s is neither permitted nor denied by domain of %s',
                mta_hostname, tostring(task:get_from_ip() or 'unknown'), sender)
          elseif key == 'permerror' then
            comment = string.format('%s: domain of %s uses mechanism not recognized by this client',
                mta_hostname, sender)
          elseif key == 'temperror' then
            comment = string.format('%s: error in processing during lookup of %s: DNS error',
                mta_hostname, sender)
          elseif key == 'none' then
            comment = string.format('%s: domain of %s has no SPF policy when checking %s',
                mta_hostname, sender, tostring(task:get_from_ip() or 'unknown'))
          end
          hdr = string.format('%s=%s (%s) %s=%s', auth_type, key,
              comment, sender_type, sender)
        else
          hdr = string.format('%s=%s', auth_type, key)
        end


        table.insert(hdr_parts, hdr)
      end
    end
  end

  local u = task:get_user()
  local smtp_from = task:get_from({'smtp','orig'})

  if u and smtp_from then
    local hdr = {[1] = 'auth=pass'}

    if settings['add_smtp_user'] then
      table.insert(hdr,'smtp.auth=' .. lua_util.maybe_smtp_quote_value(u))
    end
    if smtp_from[1]['addr'] then
      table.insert(hdr,'smtp.mailfrom=' .. lua_util.maybe_smtp_quote_value(smtp_from[1]['addr']))
    end

    table.insert(hdr_parts, table.concat(hdr,' '))
  end

  if #hdr_parts > 0 then
    if #hdr_parts == 1 then
      hdr_parts[2] = 'none'
    end
    return table.concat(hdr_parts, '; ')
  end

  return nil
end

exports.gen_auth_results = gen_auth_results

return exports
