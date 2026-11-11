rspamd_config:register_symbol({
  name = 'GET_FROM',
  score = 1.0,
  callback = function(task)
    local a = task:get_from('mime')
    if not a then return end
    a = a[1]
    return true, (a.name or '') .. ',' .. (a.addr or '') .. ',' .. (a.user or '') .. ',' .. (a.domain or '')
  end
})

-- Rewrites the MIME from, simulating a module like aliases; the original
-- address must remain reachable via the 'orig' flavour.
-- Gated on the Rewrite-Mime-From request header to stay inert in tests that
-- do not opt in (the merged suite runs all symbols when no settings passed)
rspamd_config:register_symbol({
  name = 'REWRITE_MIME_FROM',
  type = 'prefilter',
  callback = function(task)
    if not task:get_request_header('Rewrite-Mime-From') then
      return
    end
    task:set_from('mime', {
      name = 'Forged',
      user = 'forged',
      domain = 'forged.example.net',
      addr = 'forged@forged.example.net',
    }, 'alias')
  end
})

rspamd_config:register_symbol({
  name = 'GET_FROM_ORIG',
  score = 1.0,
  callback = function(task)
    local a = task:get_from({ 'mime', 'orig' })
    if not a then return end
    local naddrs = #a
    a = a[1]
    return true, string.format('%s,%s,%s,%s,%s',
        a.name or '', a.addr or '', a.user or '', a.domain or '', naddrs)
  end
})
