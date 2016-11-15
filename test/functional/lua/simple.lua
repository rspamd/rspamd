rspamd_config:register_symbol({
  name = 'SIMPLE_TEST',
  score = 1.0,
  callback = function()
    return true, 'Fires always'
  end
})
