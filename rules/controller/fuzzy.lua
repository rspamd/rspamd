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

local function handle_fuzzy_storages(_task, conn)
  if type(rspamd_plugins.fuzzy_check) == 'table'
      and type(rspamd_plugins.fuzzy_check.list_storages) == 'function' then
    local ok, result = pcall(rspamd_plugins.fuzzy_check.list_storages, rspamd_config)

    if ok then
      conn:send_ucl({ success = true, storages = result })
    else
      conn:send_error(500, 'cannot list fuzzy storages')
    end
  else
    conn:send_error(404, 'fuzzy_check is not enabled')
  end
end

-- Per-server liveness probe of the configured fuzzy storages: ping every
-- server of every rule and reply once all pings have settled (each ping is
-- bounded by its own timeout). GET-only, no mutation: like fuzzy_ping, the
-- probe does not feed the upstream ok/fail bookkeeping, so the read-only
-- password is enough.
local fuzzy_status_ping_timeout = 2.0

local function handle_fuzzy_status(task, conn)
  if type(rspamd_plugins.fuzzy_check) == 'table'
      and type(rspamd_plugins.fuzzy_check.ping_storage_all) == 'function' then
    local pok, storages = pcall(rspamd_plugins.fuzzy_check.list_storages, rspamd_config)

    if not pok then
      conn:send_error(500, 'cannot list fuzzy storages')
      return
    end

    local results = {}
    local expected = 0
    local done = 0
    local setup_done = false
    local replied = false

    -- The reply goes out once every expected result has landed; the
    -- deadline passes force to flush a partial reply (a lost callback must
    -- not hang the request until the client timeout)
    local function reply(force)
      if setup_done and not replied and (force or done >= expected) then
        replied = true
        conn:send_ucl({ success = true, storages = results })
      end
    end

    -- Safety net: a lost or erroring callback must not hang the request
    -- until the client timeout
    task:add_timer(fuzzy_status_ping_timeout + 1.0, function() reply(true) end)

    for rule_name in pairs(storages) do
      local servers = {}
      results[rule_name] = { servers = servers }

      local ok, _, count = pcall(rspamd_plugins.fuzzy_check.ping_storage_all, task,
        function(success, _ip, latency_or_err, server_name)
          done = done + 1
          local entry = { name = server_name, ok = success and true or false }
          if success then
            entry.latency = latency_or_err
          else
            entry.error = latency_or_err
          end
          servers[#servers + 1] = entry
          reply()
        end, rule_name, fuzzy_status_ping_timeout)

      if not ok then
        conn:send_error(500, 'cannot ping fuzzy storages')
        return
      end

      if (count or 0) == 0 then
        -- No pingable servers (e.g. SRV not resolved yet): report no
        -- status for the rule rather than an empty result set
        results[rule_name] = nil
      else
        expected = expected + count
      end
    end

    -- Synchronous results (unresolved addresses, connect failures) arrive
    -- before the matching count is added to `expected`, so the reply is
    -- armed only after the whole setup pass
    setup_done = true

    if done >= expected then
      reply()
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
  storages = {
    handler = handle_fuzzy_storages,
    need_task = false,
    enable = false
  },
  status = {
    handler = handle_fuzzy_status,
    need_task = false,
    enable = false
  },
}
