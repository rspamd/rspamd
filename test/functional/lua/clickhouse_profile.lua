-- One symbol of the group that the clickhouse profile test selects
rspamd_config:register_symbol({
  name = 'CHPROF_SYM',
  score = 0.1,
  group = 'chprof',
  callback = function(task)
    task:insert_result('CHPROF_SYM', 1.0)
  end,
})
