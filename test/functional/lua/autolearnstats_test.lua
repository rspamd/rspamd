-- Test symbols for autolearnstats functional test.
-- Fires high-score symbols based on the mime From address to trigger autolearn.

local function make_from_check(pattern)
  return function(task)
    local from = task:get_from('mime')
    if from and from[1] and from[1].addr:find(pattern) then
      return true
    end
  end
end

-- Two positive symbols to satisfy npositive > 1 and score >= 15 (reject) for spam verdict
for i = 1, 2 do
  rspamd_config:register_symbol({
    name = 'TEST_SPAM_' .. i,
    score = 8.0,
    callback = make_from_check('spam@'),
  })
end

-- Four negative symbols to satisfy nnegative > 3 for ham verdict
for i = 1, 4 do
  rspamd_config:register_symbol({
    name = 'TEST_HAM_' .. i,
    score = -4.0,
    callback = make_from_check('ham@'),
  })
end
