rspamd_config:register_symbol({
  name = 'SIMPLE_PRE',
  score = 1.0,
  priority = 9, -- after settings
  type = 'prefilter',
  callback = function()
    return true, 'Fires always'
  end
})

rspamd_config:register_symbol({
  name = 'SIMPLE_POST',
  score = 1.0,
  type = 'postfilter',
  callback = function()
    return true, 'Fires always'
  end
})

rspamd_config:register_symbol({
  name = 'SIMPLE_TEST',
  score = 1.0,
  callback = function()
    return true, 'Fires always'
  end
})
