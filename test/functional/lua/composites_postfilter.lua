-- Test for composite with postfilter + filter symbols
-- This test demonstrates bug #5674

-- Normal filter symbol (executed during FILTERS stage)
rspamd_config:register_symbol({
  type = 'normal',
  name = 'TEST_FILTER_SYM',
  callback = function(task)
    task:insert_result('TEST_FILTER_SYM', 1.0)
  end
})
rspamd_config:set_metric_symbol({
  name = 'TEST_FILTER_SYM',
  score = 1.0
})

-- Postfilter symbol (executed during POST_FILTERS stage)
rspamd_config:register_symbol({
  type = 'postfilter',
  name = 'TEST_POSTFILTER_SYM',
  callback = function(task)
    task:insert_result('TEST_POSTFILTER_SYM', 1.0)
  end
})
rspamd_config:set_metric_symbol({
  name = 'TEST_POSTFILTER_SYM',
  score = 1.0
})

-- Composite is defined in merged-local.conf
-- TEST_POSTFILTER_COMPOSITE = TEST_FILTER_SYM & TEST_POSTFILTER_SYM
-- This should match when both symbols are present
-- BUG: Currently fails because composite is evaluated before postfilter runs
-- and is not re-evaluated in the second pass
