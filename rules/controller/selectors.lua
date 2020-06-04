--[[
Copyright (c) 2020, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

local lua_selectors = require "lua_selectors"

-- Controller selectors plugin

local function handle_list_transforms(_, conn)
  conn:send_ucl(lua_selectors.list_transforms())
end

local function handle_list_extractors(_, conn)
  conn:send_ucl(lua_selectors.list_extractors())
end

local function handle_check_selector(_, conn, req_params)
  if req_params.selector and req_params.selector ~= '' then
    local selector = lua_selectors.create_selector_closure(rspamd_config,
        req_params.selector, '', true)
      conn:send_ucl({success = selector and true})
  else
    conn:send_error(404, 'missing selector')
  end
end

local function handle_check_message(task, conn, req_params)
  if req_params.selector and req_params.selector ~= '' then
    local selector = lua_selectors.create_selector_closure(rspamd_config,
        req_params.selector, '', true)
    if not selector then
      conn:send_error(500, 'invalid selector')
    else
      task:process_message()
      local elts = selector(task)
      conn:send_ucl({success = true, data = elts})
    end
  else
    conn:send_error(404, 'missing selector')
  end
end

return {
  list_extractors = {
    handler = handle_list_extractors,
    enable = true,
  },
  list_transforms = {
    handler = handle_list_transforms,
    enable = true,
  },
  check_selector = {
    handler = handle_check_selector,
    enable = true,
  },
  check_message = {
    handler = handle_check_message,
    enable = true,
    need_task = true,
  }
}
