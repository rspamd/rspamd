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
]]--

local ansicolors = require "ansicolors"

local function printf(fmt, ...)
  print(string.format(fmt, ...))
end

local function highlight(str)
  return ansicolors.white .. str .. ansicolors.reset
end

local function print_plugins_table(tbl, what)
  local mods = {}
  for k, _ in pairs(tbl) do
    table.insert(mods, k)
  end

  printf("Modules %s: %s", highlight(what), table.concat(mods, ", "))
end

return function(args, _)
  print_plugins_table(rspamd_plugins_state.enabled, "enabled")
  print_plugins_table(rspamd_plugins_state.disabled_explicitly,
      "disabled (explicitly)")
  print_plugins_table(rspamd_plugins_state.disabled_unconfigured,
      "disabled (unconfigured)")
  print_plugins_table(rspamd_plugins_state.disabled_redis,
      "disabled (no Redis)")
  print_plugins_table(rspamd_plugins_state.disabled_experimental,
      "disabled (experimental)")
  print_plugins_table(rspamd_plugins_state.disabled_failed,
      "disabled (failed)")
end