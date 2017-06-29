local exports = {}
local lpeg = require 'lpeg'

local split_grammar = {}
exports.rspamd_str_split = function(s, sep)
  local gr = split_grammar[sep]

  if not gr then
    local _sep = lpeg.P(sep)
    local elem = lpeg.C((1 - _sep)^0)
    local p = lpeg.Ct(elem * (_sep * elem)^0)
    gr = p
    split_grammar[sep] = gr
  end

  return gr:match(s)
end

local space = lpeg.S' \t\n\v\f\r'
local nospace = 1 - space
local ptrim = space^0 * lpeg.C((space^0 * nospace^1)^0)
local match = lpeg.match
exports.rspamd_str_trim = function(s)
  return match(ptrim, s)
end

-- Robert Jay Gould http://lua-users.org/wiki/SimpleRound
exports.round = function(num, numDecimalPlaces)
  local mult = 10^(numDecimalPlaces or 0)
  return math.floor(num * mult) / mult
end

exports.template = function(tmpl, keys)
  local var_lit = lpeg.P { lpeg.R("az") + lpeg.R("AZ") + lpeg.R("09") + "_" }
  local var = lpeg.P { (lpeg.P("$") / "") * ((var_lit^1) / keys) }
  local var_braced = lpeg.P { (lpeg.P("${") / "") * ((var_lit^1) / keys) * (lpeg.P("}") / "") }

  local template_grammar = lpeg.Cs((var + var_braced + 1)^0)

  return lpeg.match(template_grammar, tmpl)
end

exports.remove_email_aliases = function(addr)
  local function check_gmail_user(addr)
    -- Remove all points
    local no_dots_user = string.gsub(addr.user, '.', '')
    local cap, pluses = string.match(no_dots_user, '^([^%+][^%+]*)(%+.*)$')
    if cap then
      return cap, rspamd_str_split(pluses, '+'), nil
    elseif no_dots_user ~= addr.user then
      return no_dots_user
    end

    return nil
  end

  local function check_address(addr)
    if addr.user then
      local cap, pluses = string.match(addr.user, '^([^%+][^%+]*)(%+.*)$')
      if cap then
        return cap, rspamd_str_split(pluses, '+'), nil
      end
    end

    return nil
  end

  local function set_addr(addr, new_user, new_domain)
    if new_user then
      addr.user = new_user
    end
    if new_domain then
      addr.domain = new_domain
    end

    if addr.domain then
      addr.addr = string.format('%s@%s', addr.user, addr.domain)
    else
      addr.addr = string.format('%s@', addr.user)
    end

    if addr.name and #addr.name > 0 then
      addr.raw = string.format('"%s" <%s>', addr.name, addr.addr)
    else
      addr.raw = string.format('<%s>', addr.addr)
    end
  end

  local function check_gmail(addr)
    local nu, tags, nd = check_gmail_user(addr)

    if nu then
      return nu, tags, nd
    end

    return nil
  end

  local function check_gmail(addr)
    local nd = 'gmail.com'
    local nu, tags = check_gmail_user(addr)

    if nu then
      return nu, tags, nd
    end

    return nil, nil, nd
  end

  local specific_domains = {
    ['gmail.com'] = check_gmail,
    ['googlemail.com'] = check_googlemail,
  }

  if addr then
    if addr.domain and specific_domains[addr.domain] then
      local nu, tags, nd = specific_domains[addr.domain](addr)
      if nu or nd then
        set_addr(addr, nu, nd)

        return nu, tags
      end
    else
      local nu, tags, nd = check_address(addr)
      if nu or nd then
        set_addr(addr, nu, nd)

        return nu, tags
      end
    end

    return nil
  end
end

return exports
