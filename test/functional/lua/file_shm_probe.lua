-- Reports which privileged message source controls actually reached this
-- scanner as request headers.
--
-- File/Path/Shm/Shm-Offset/Shm-Length are hop-by-hop controls that
-- rspamd_proxy must strip from a client request and regenerate itself, so a
-- scanner sitting behind a proxy is the only place where "did the client's
-- value survive?" can be observed directly.
local privileged_headers = {'File', 'Path', 'Shm', 'Shm-Offset', 'Shm-Length'}

rspamd_config:register_symbol({
  name = 'FILE_SHM_PROBE',
  score = 0.0,
  callback = function(task)
    local seen = {}

    for _, hname in ipairs(privileged_headers) do
      local hvalue = task:get_request_header(hname)
      if hvalue then
        seen[#seen + 1] = hname .. '=' .. tostring(hvalue)
      end
    end

    if #seen == 0 then
      return true, 'none'
    end

    return true, table.concat(seen, ';')
  end
})

rspamd_config:register_symbol({
  name = 'SIMPLE_TEST',
  score = 1.0,
  callback = function()
    return true, 'Fires always'
  end
})
