--[[
Copyright (c) 2017, Andrew Lewis <nerf@judo.za.org>
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

-- A plugin that forces actions

local E = {}
local N = 'force_actions'

local function gen_cb(sym, act, message)
  return function(task)
    local s = task:get_symbol(sym)
    if not s then return end
    task:set_pre_result(act, message)
    return true
  end
end

local function configure_module()
  local opts = rspamd_config:get_all_opt(N)
  if not opts then
    return false
  end
  if type(opts.actions) ~= 'table' then
    return false
  end
  for action, symbols in pairs(opts.actions) do
    if type(symbols) == 'table' then
      for _, symbol in ipairs(symbols) do
        local message = (opts.messages or E)[symbol]
        local id = rspamd_config:register_symbol({
          type = 'normal',
          name = 'FORCE_ACTION_ON_' .. symbol,
          callback = gen_cb(symbol, action, message),
        })
        rspamd_config:register_dependency(id, symbol)
      end
    end
  end
end

configure_module()
