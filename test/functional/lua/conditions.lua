local logger = require 'rspamd_logger'

rspamd_config:register_symbol({
  name = 'ANY_A',
  score = -1.0,
  group = "any",
  callback = function()
    return true, 'hello3'
  end
})

rspamd_config:add_condition('ANY_A', function(task)
  logger.infox(task, 'hello from condition1')
  task:insert_result('ANY_A', 1.0, 'hello1')
  return true
end)

rspamd_config:add_condition('ANY_A', function(task)
  logger.infox(task, 'hello from condition2')
  task:insert_result('ANY_A', 1.0, 'hello2')
  return true
end)
