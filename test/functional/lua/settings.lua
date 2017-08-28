rspamd_config:register_symbol({
  name = 'SIMPLE_PRE',
  score = 1.0,
  priority = 9, -- after settings
  group = 'a',
  type = 'prefilter',
  callback = function()
    return true, 'Fires always'
  end
})

rspamd_config:register_symbol({
  name = 'SIMPLE_POST',
  score = 1.0,
  type = 'postfilter',
  group = 'c',
  callback = function()
    return true, 'Fires always'
  end
})

rspamd_config:register_symbol({
  name = 'SIMPLE_TEST',
  score = 1.0,
  group = 'b',
  callback = function()
    return true, 'Fires always'
  end
})
