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
