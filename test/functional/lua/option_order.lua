rspamd_config:register_symbol({
  name = 'TBL_OPTION_ORDER',
  score = 1.0,
  callback = function()
    return true, {'one', 'two', 'three', '4', '5', 'a'}
  end
})

rspamd_config:register_symbol({
  name = 'OPTION_ORDER',
  score = 1.0,
  callback = function()
    return true, 'one', 'two', 'three', '4', '5', 'a'
  end
})
