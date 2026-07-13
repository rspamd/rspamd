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

-- Regression for the inverse of #5674: a composite that depends ONLY on
-- filter-stage symbols must be evaluated in the FIRST composites pass so that
-- it (and its groups) are visible from postfilters via task:get_symbols() /
-- task:get_groups(). NOSTAT is set on essentially every virtual/callback rule
-- (regexp, multimap, rbl, ...); a filter-stage symbol carrying NOSTAT must not
-- cause the composite to be wrongly deferred to the second (post-filters) pass.
rspamd_config:register_symbol({
  type = 'normal',
  flags = 'nostat',
  name = 'TEST_NOSTAT_FILTER_SYM',
  callback = function(task)
    task:insert_result('TEST_NOSTAT_FILTER_SYM', 1.0)
  end
})
rspamd_config:set_metric_symbol({
  name = 'TEST_NOSTAT_FILTER_SYM',
  score = 1.0
})

-- Postfilter that observes whether the first-pass composite has already fired.
-- It only inserts its marker if TEST_FIRSTPASS_COMPOSITE is already present,
-- which can only happen if the composite was evaluated during the first pass.
rspamd_config:register_symbol({
  type = 'postfilter',
  name = 'TEST_OBSERVE_FIRSTPASS_COMPOSITE',
  callback = function(task)
    if task:has_symbol('TEST_FIRSTPASS_COMPOSITE') then
      task:insert_result('TEST_COMPOSITE_SEEN_IN_POSTFILTER', 1.0)
    end
  end
})
rspamd_config:set_metric_symbol({
  name = 'TEST_COMPOSITE_SEEN_IN_POSTFILTER',
  score = 1.0
})

-- Composite TEST_FIRSTPASS_COMPOSITE = TEST_NOSTAT_FILTER_SYM is defined in
-- merged-local.conf
