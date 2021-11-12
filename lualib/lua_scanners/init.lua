--[[
Copyright (c) 2018, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

--[[[
-- @module lua_scanners
-- This module contains external scanners functions
--]]

local fun = require "fun"

local exports = {
}

local function require_scanner(name)
  local sc = require ("lua_scanners/" .. name)

  exports[sc.name or name] = sc
end

-- Antiviruses
require_scanner('clamav')
require_scanner('fprot')
require_scanner('kaspersky_av')
require_scanner('kaspersky_se')
require_scanner('savapi')
require_scanner('sophos')
require_scanner('virustotal')
require_scanner('avast')

-- Other scanners
require_scanner('dcc')
require_scanner('oletools')
require_scanner('icap')
require_scanner('vadesecure')
require_scanner('spamassassin')
require_scanner('p0f')
require_scanner('razor')
require_scanner('pyzor')
require_scanner('cloudmark')

exports.add_scanner = function(name, t, conf_func, check_func)
  assert(type(conf_func) == 'function' and type(check_func) == 'function',
      'bad arguments')
  exports[name] = {
    type = t,
    configure = conf_func,
    check = check_func,
  }
end

exports.filter = function(t)
  return fun.tomap(fun.filter(function(_, elt)
    return type(elt) == 'table' and elt.type and (
        (type(elt.type) == 'string' and elt.type == t) or
        (type(elt.type) == 'table' and fun.any(function(tt) return tt == t end, elt.type))
    )
  end, exports))
end

return exports
