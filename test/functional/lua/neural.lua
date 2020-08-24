rspamd_config:register_symbol({
  name = 'SPAM_SYMBOL',
  score = 5.0,
  callback = function()
    return true, 'Fires always'
  end
})

rspamd_config:register_symbol({
  name = 'HAM_SYMBOL',
  score = -3.0,
  callback = function()
    return true, 'Fires always'
  end
})

rspamd_config:register_symbol({
  name = 'NEUTRAL_SYMBOL',
  score = 1.0,
  flags = 'explicit_disable',
  callback = function()
    return true, 'Fires always'
  end
})