rspamd_config:register_symbol({
  name = 'HEADER_OPTIONS_TEST',
  score = 0,
  callback = function()
    return true, { '95.33%', 'literal%2C', 'first,second' }
  end,
})
