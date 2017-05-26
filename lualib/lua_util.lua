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

return exports
