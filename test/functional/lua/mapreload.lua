local test_map = rspamd_config:add_map ({
  url = '${MAP_FILE}',
  type = 'set',
})

rspamd_config:register_symbol({
  name = 'MAP_SET_HIT_AND_MISS',
  score = 1.0,
  callback = function()
    if (test_map:get_key('example.com') and not test_map:get_key('rspamd.com')) then
      return true, 'example.com'
    elseif (test_map:get_key('rspamd.com') and not test_map:get_key('example.com')) then
      return true, 'rspamd.com'
    end
  end
})
