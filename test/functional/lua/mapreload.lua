local test_map = rspamd_config:add_map ({
  url = '${MAP_FILE}',
  type = 'set',
})

rspamd_config:register_symbol({
  name = 'MAP_SET_HIT_AND_MISS',
  score = 1.0,
  callback = function()
    local has_example = test_map:get_key('example.com')
    local has_rspamdtest = test_map:get_key('rspamd-test.com')
    if has_example and not has_rspamdtest then
      return true, 'example.com'
    elseif has_rspamdtest and not has_example then
      return true, 'rspamd.com'
    else
      return true, string.format('invalid: has_example=%s, has_rspamdtest=%s', has_example, has_rspamdtest)
    end
  end
})
