--[[
Copyright (c) 2023, Vsevolod Stakhov <vsevolod@rspamd.com>

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

local function handle_gen_fuzzy(task, conn, req_params)
  if type(rspamd_plugins.fuzzy_check) == 'table' then
    local ret, hashes
    task:process_message()
    if req_params.rule then
      ret, hashes = pcall(rspamd_plugins.fuzzy_check.hex_hashes, task, req_params.rule)
    elseif req_params.flag then
      ret, hashes = pcall(rspamd_plugins.fuzzy_check.hex_hashes, task, tonumber(req_params.flag))
    else
      conn:send_error(404, 'missing rule or flag')
      return
    end

    if ret then
      conn:send_ucl({ success = true, hashes = hashes })
    else
      conn:send_error(500, 'cannot generate hashes')
    end
  else
    conn:send_error(404, 'fuzzy_check is not enabled')
  end
end

return {
  hashes = {
    handler = handle_gen_fuzzy,
    need_task = true,
    enable = false
  },
}