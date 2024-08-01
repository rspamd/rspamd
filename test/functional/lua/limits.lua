local true_cb_gen = function()
  return function()
    return true
  end
end

local test_weights = { 1, 2, 4, 8, 16 }
for _, i in ipairs(test_weights) do
  rspamd_config:register_symbol('GR_POSITIVE' .. tostring(i), 1.0, true_cb_gen())

  if i > 1 then
    rspamd_config:register_dependency('GR_POSITIVE' .. tostring(i), 'GR_POSITIVE' .. tostring(i / 2))
  end

  rspamd_config:register_symbol('GR_NEGATIVE' .. tostring(i), 1.0, true_cb_gen())

  if i > 1 then
    rspamd_config:register_dependency('GR_NEGATIVE' .. tostring(i), 'GR_NEGATIVE' .. tostring(i / 2))
  end
end

rspamd_config:register_dependency('GR_NEGATIVE1', 'GR_POSITIVE16')