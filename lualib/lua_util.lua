local exports = {}

local split_grammar = {}
exports.rspamd_str_split = function(s, sep)
  local lpeg = require "lpeg"
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

return exports
