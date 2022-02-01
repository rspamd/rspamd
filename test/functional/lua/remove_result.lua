local id = rspamd_config:register_symbol({
  name = 'REMOVE_RESULT_CB',
  callback = function(task)
    task:insert_result('REMOVE_RESULT_UNEXPECTED', 1.0, 'ohno')
  end,
  type = 'callback',
})

rspamd_config:register_symbol({
  name = 'REMOVE_RESULT_UNEXPECTED',
  type = 'virtual',
  score = 0.1,
  group = 'remove_result_test',
  parent = id,
})

rspamd_config:register_symbol({
  name = 'REMOVE_RESULT_EXPECTED',
  callback = function(task)
    return task:remove_result('REMOVE_RESULT_UNEXPECTED') and true or false
  end,
  type = 'normal',
  score = 0.1,
})

rspamd_config:register_dependency('REMOVE_RESULT_EXPECTED', 'REMOVE_RESULT_UNEXPECTED')
