rspamd_config:register_symbol({
  name = 'SPAM_SYMBOL',
  score = 1.0,
  callback = function()
    return true, 'Fires always'
  end
})

rspamd_config:register_symbol({
  name = 'HAM_SYMBOL',
  score = -1.0,
  callback = function()
    return true, 'Fires always'
  end
})