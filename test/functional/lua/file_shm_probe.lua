-- Reports which privileged message source controls actually reached this
-- scanner as request headers.
--
-- File/Path/Shm/Shm-Offset/Shm-Length are hop-by-hop controls that
-- rspamd_proxy must strip from a client request and regenerate itself, so a
-- scanner sitting behind a proxy is the only place where "did the client's
-- value survive?" can be observed directly.
local privileged_headers = {'File', 'Path', 'Shm', 'Shm-Offset', 'Shm-Length'}

-- Ordinary query arguments that share a URL with a stripped privileged one.
-- Removing a privileged argument means rebuilding the URL around it, and the
-- '?' delimiter is easy to duplicate while doing so, which renames the first
-- surviving argument to '?From'. Both spellings are therefore reported, so
-- that a mangled rebuild is named rather than merely missed.
local ordinary_headers = {'From', '?From'}

local function report_headers(task, names)
  local seen = {}

  for _, hname in ipairs(names) do
    local hvalue = task:get_request_header(hname)
    if hvalue then
      seen[#seen + 1] = hname .. '=' .. tostring(hvalue)
    end
  end

  if #seen == 0 then
    return 'none'
  end

  return table.concat(seen, ';')
end

rspamd_config:register_symbol({
  name = 'FILE_SHM_PROBE',
  score = 0.0,
  callback = function(task)
    return true, report_headers(task, privileged_headers)
  end
})

rspamd_config:register_symbol({
  name = 'REQUEST_ARG_PROBE',
  score = 0.0,
  callback = function(task)
    return true, report_headers(task, ordinary_headers)
  end
})

rspamd_config:register_symbol({
  name = 'SIMPLE_TEST',
  score = 1.0,
  callback = function()
    return true, 'Fires always'
  end
})
