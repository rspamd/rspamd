rspamd_config:register_symbol({
  name = 'EXPRESSIONS_B',
  score = 1.0,
  callback = function()
    return true, 'Fires always'
  end
})

rspamd_config:register_symbol({
  name = 'POLICY_REMOVE_WEIGHT_A',
  score = 1.0,
  callback = function()
    return true, 'Fires always'
  end
})
rspamd_config:register_symbol({
  name = 'POLICY_REMOVE_WEIGHT_B',
  score = 1.0,
  callback = function()
    return true, 'Fires always'
  end
})
rspamd_config:register_symbol({
  name = 'POLICY_FORCE_REMOVE_A',
  score = 1.0,
  callback = function()
    return true, 'Fires always'
  end
})
rspamd_config:register_symbol({
  name = 'POLICY_FORCE_REMOVE_B',
  score = 1.0,
  callback = function()
    return true, 'Fires always'
  end
})
rspamd_config:register_symbol({
  name = 'POLICY_LEAVE_A',
  score = 1.0,
  callback = function()
    return true, 'Fires always'
  end
})
rspamd_config:register_symbol({
  name = 'POLICY_LEAVE_B',
  score = 1.0,
  callback = function()
    return true, 'Fires always'
  end
})

rspamd_config:register_symbol({
  name = 'DEFAULT_POLICY_REMOVE_WEIGHT_A',
  score = 1.0,
  callback = function()
    return true, 'Fires always'
  end
})
rspamd_config:register_symbol({
  name = 'DEFAULT_POLICY_REMOVE_WEIGHT_B',
  score = 1.0,
  callback = function()
    return true, 'Fires always'
  end
})
rspamd_config:register_symbol({
  name = 'DEFAULT_POLICY_REMOVE_SYMBOL_A',
  score = 1.0,
  callback = function()
    return true, 'Fires always'
  end
})
rspamd_config:register_symbol({
  name = 'DEFAULT_POLICY_REMOVE_SYMBOL_B',
  score = 1.0,
  callback = function()
    return true, 'Fires always'
  end
})
rspamd_config:register_symbol({
  name = 'DEFAULT_POLICY_LEAVE_A',
  score = 1.0,
  callback = function()
    return true, 'Fires always'
  end
})
rspamd_config:register_symbol({
  name = 'DEFAULT_POLICY_LEAVE_B',
  score = 1.0,
  callback = function()
    return true, 'Fires always'
  end
})
