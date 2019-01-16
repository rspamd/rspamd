rspamd_config:register_symbol({
  name = 'SIMPLE_TEST',
  score = 1.0,
  callback = function(task)
    local a = task:get_from('mime')[1]
    task:insert_result('GET_FROM', 0.0, a.name .. ',' .. a.addr .. ',' .. a.user .. ',' .. a.domain)
  end
})
