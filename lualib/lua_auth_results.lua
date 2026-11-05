--[[
Copyright (c) 2016-2026, Vsevolod Stakhov <vsevolod@rspamd.com>

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

-- The text of a comment, which ends at the first unescaped ')': the sender
-- or a reason in it must not close it and add results of its own
-- ("x)dmarc=pass header.from=bank.example(y"@attacker.example)
local function escape_comment(s)
  s = tostring(s):gsub('%c', function(c)
    return c == '\t' and c or '?'
  end)
  return (s:gsub('[\\()]', '\\%0'))
end

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
            auth_results[auth_type] = { key }
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

  for _, dres in ipairs(dkim_results) do
    local ar_string = 'none'

    if dres.result == 'reject' then
      ar_string = 'fail' -- imply failure, not neutral
    elseif dres.result == 'allow' then
      ar_string = 'pass'
    elseif dres.result == 'bad record' or dres.result == 'permerror' or dres.result == 'permfail' then
      ar_string = 'permerror'
    elseif dres.result == 'tempfail' then
      ar_string = 'temperror'
    end
    local hdr = {}

    hdr[1] = string.format('dkim=%s', ar_string)

    if dres.fail_reason then
      hdr[#hdr + 1] = string.format('(%s)',
          escape_comment(lua_util.maybe_smtp_quote_value(dres.fail_reason)))
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
          hdr = hdr .. ' (policy=' .. escape_comment(lua_util.maybe_smtp_quote_value(opts[2])) .. ')'
          hdr = hdr .. ' header.from=' .. lua_util.maybe_smtp_quote_value(opts[1])
        elseif key ~= 'none' then
          local t = { opts[1]:match('^([^%s]+) : (.*)$') }
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
            hdr = hdr .. ' (policy=' .. escape_comment(lua_util.maybe_smtp_quote_value(key)) .. ')'
          end
        end
        table.insert(hdr_parts, hdr)
      elseif auth_type == 'arc' then
        if common.symbols[auth_types['arc'][key]][1] then
          local opts = common.symbols[auth_types['arc'][key]][1]['options'] or {}
          for _, v in ipairs(opts) do
            hdr = string.format('%s%s=%s (%s)', hdr, auth_type,
                lua_util.maybe_smtp_quote_value(key),
                escape_comment(lua_util.maybe_smtp_quote_value(v)))
            table.insert(hdr_parts, hdr)
          end
        end
      elseif auth_type == 'spf' then
        -- Main type
        local sender
        local sender_type
        local smtp_from = task:get_from({ 'smtp', 'orig' })

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
              escape_comment(comment), sender_type, sender)
        else
          hdr = string.format('%s=%s', auth_type, key)
        end

        table.insert(hdr_parts, hdr)
      end
    end
  end

  local u = task:get_user()
  local smtp_from = task:get_from({ 'smtp', 'orig' })

  if u and smtp_from then
    local hdr = { [1] = 'auth=pass' }

    if settings['add_smtp_user'] then
      table.insert(hdr, 'smtp.auth=' .. lua_util.maybe_smtp_quote_value(u))
    end
    if smtp_from[1]['addr'] then
      table.insert(hdr, 'smtp.mailfrom=' .. lua_util.maybe_smtp_quote_value(smtp_from[1]['addr']))
    end

    table.insert(hdr_parts, table.concat(hdr, ' '))
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

-- Shared LPeg primitives for AR/AAR parsing (built once on first use)
local ar_lpeg_atoms

local function get_ar_lpeg_atoms()
  if ar_lpeg_atoms then
    return ar_lpeg_atoms
  end

  local lpeg = require "lpeg"
  local P, R, S, V, C, Cs, Ct, Cg, Cf = lpeg.P, lpeg.R, lpeg.S, lpeg.V, lpeg.C, lpeg.Cs, lpeg.Ct, lpeg.Cg, lpeg.Cf

  local space = S(" \t") ^ 0
  -- As in `quoted_value`, so both agree on where a quoted value ends
  local doublequoted = space * P '"' * ((1 - S '"\\') + (P '\\' * 1)) ^ 0 * '"' * space
  -- A quoted-pair does not close or open a comment (RFC 5322)
  local comment = space * P { "(" * ((P '\\' * 1) + (1 - S "()\\") + V(1)) ^ 0 * ")" } * space
  local name = C((1 - S('=(" \t')) ^ 1) * space
  -- A value may be a quoted-string (RFC 8601): its content, unescaped
  local quoted_value = P '"' * Cs(((P '\\' / '') * 1 + (1 - S '"\\')) ^ 0) * P '"' * space
  local pair = Cg(name * "=" * space * (quoted_value + name)) * space

  -- Single AR element grammar: "dkim=pass (comment) header.d=example.com" → table
  local elt_grammar = Cf(Ct("") * (pair + comment + doublequoted) ^ 1, rawset)
  -- The method of an element, e.g. "dkim" of "dkim/1=pass": its first token,
  -- after any comments, which RFC 8601 2.2 allows anywhere
  local method_grammar = (space * comment) ^ 0 * space *
      C((R("az", "AZ", "09") + S "_-") ^ 1) * space * S "/="

  -- AAR header split grammar: splits on ";" while respecting comments and quotes.
  -- Each captured element is the raw text between semicolons (trimmed).
  local safe_char = (comment + doublequoted + (1 - S ";")) -- consume one "safe" token
  local element = C(safe_char ^ 1) -- capture the raw text of one element
  local sep = P ";" * space
  local aar_split_grammar = Ct(space * element * (sep * element) ^ 0)

  ar_lpeg_atoms = {
    elt_grammar = elt_grammar,
    method_grammar = method_grammar,
    aar_split_grammar = aar_split_grammar,
  }
  return ar_lpeg_atoms
end

-- Parse a single AR element (e.g. "dkim=pass header.d=example.com") into a kv table.
-- The table also has `method`: the method of the element, e.g. "dkim". Only the
-- result of that method is a result of the element, other `key=value` pairs
-- are properties, or text that a comment failed to hide.
local function parse_ar_element(elt)
  local atoms = get_ar_lpeg_atoms()
  local res = atoms.elt_grammar:match(elt)
  if res then
    local method = atoms.method_grammar:match(elt)
    res.method = method and method:lower() or nil
  end
  return res
end
exports.parse_ar_element = parse_ar_element

-- Split an AAR header value into elements by ";" while respecting comments and
-- quoted strings, then parse each element.  Returns { i = <number>,
-- ar = { {method=result, ...}, ... } } or nil on failure.
local function parse_aar_header(decoded)
  local atoms = get_ar_lpeg_atoms()
  local elts = atoms.aar_split_grammar:match(decoded)
  if not elts or #elts == 0 then
    return nil
  end

  local result = {}

  for _, raw_elt in ipairs(elts) do
    local trimmed = raw_elt:match("^%s*(.-)%s*$")
    if trimmed and #trimmed > 0 and trimmed:match("^i%s*=%s*%d+$") then
      -- ARC instance tag
      local v = trimmed:match("^i%s*=%s*(%d+)$")
      result.i = v
    else
      -- Try to parse as an AR element (method=result prop=value ...)
      local ar_elt = parse_ar_element(trimmed)
      if ar_elt then
        if not result.ar then
          result.ar = {}
        end
        table.insert(result.ar, ar_elt)
      end
      -- Elements without '=' (like authserv-id) are silently skipped
    end
  end

  return result
end
exports.parse_aar_header = parse_aar_header

local function get_ar_hostname(ar_value)
  if not ar_value or ar_value == '' then
    return nil
  end

  local hostname = ar_value:match('^%s*([^;%s%(]+)')

  if hostname then
    return hostname:lower()
  end

  return nil
end
exports.get_ar_hostname = get_ar_hostname

return exports
