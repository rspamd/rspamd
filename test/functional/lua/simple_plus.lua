local test_symbols = {
  SIMPLE_TEST_001 = 0.01,
  SIMPLE_TEST_002 = 11,
  SIMPLE_TEST_003 = 5.0,
  SIMPLE_TEST_004 = 10.0,
  SIMPLE_TEST_005 = 0.01,
  SIMPLE_TEST_006 = 0.10,
  SIMPLE_TEST_007 = 0.11,
  SIMPLE_TEST_008 = 0.12,
  SIMPLE_TEST_009 = 0.13,
  SIMPLE_TEST_010 = 0.14,
  SIMPLE_TEST_011 = -0.01,
  SIMPLE_TEST_012 = -0.1,
  SIMPLE_TEST_013 = -10.0,
}

for k, v in pairs(test_symbols) do

  rspamd_config:register_symbol({
    name = k,
    group = 'simple_tests',
    score = v,
    callback = function()
      return true
    end
  })

end
