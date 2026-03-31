-- Test symbols for settings merge functional tests

-- Basic symbol that always fires
rspamd_config:register_symbol({
  name = 'MERGE_TEST_BASIC',
  score = 1.0,
  group = 'merge_test',
  callback = function()
    return true, 'basic'
  end
})

-- Symbol with a HARD dependency on MERGE_TEST_BASIC
rspamd_config:register_symbol({
  name = 'MERGE_HARD_DEP',
  score = 1.0,
  group = 'merge_test',
  callback = function()
    return true, 'hard_dep'
  end
})
rspamd_config:register_dependency('MERGE_HARD_DEP', 'MERGE_TEST_BASIC')

-- Symbol with a WEAK dependency on MERGE_TEST_BASIC
rspamd_config:register_symbol({
  name = 'MERGE_WEAK_DEP',
  score = 1.0,
  group = 'merge_test',
  callback = function()
    return true, 'weak_dep'
  end
})
rspamd_config:register_dependency('MERGE_WEAK_DEP', 'MERGE_TEST_BASIC', true)

-- Symbol in a separate group for group enable/disable tests
rspamd_config:register_symbol({
  name = 'MERGE_GROUP_SYM',
  score = 2.0,
  group = 'merge_group',
  callback = function()
    return true, 'group_sym'
  end
})

-- Another symbol in the merge_group
rspamd_config:register_symbol({
  name = 'MERGE_GROUP_SYM2',
  score = 3.0,
  group = 'merge_group',
  callback = function()
    return true, 'group_sym2'
  end
})

-- A prefilter for testing settings deps
rspamd_config:register_symbol({
  name = 'MERGE_PRE',
  score = 0.5,
  type = 'prefilter',
  priority = 9,
  group = 'merge_test',
  flags = 'empty',
  callback = function()
    return true, 'pre'
  end
})
