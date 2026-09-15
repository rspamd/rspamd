local envelope = { 'connection', 'helo', 'sender', 'recipients' }

local id = rspamd_config:register_symbol {
  name = 'DATA_PRODUCER',
  required_inputs = envelope,
  replay_version = 1,
  callback = function(task)
    local sender = task:get_from('smtp')[1].user
    task:get_mempool():set_variable('data_callback_ran', true)
    task:insert_result('DATA_PRODUCER', 1.0, sender)
    task:set_check_fact('sender', sender)
    if sender == 'reject' then
      task:insert_result('DATA_REJECT', 1.0)
    elseif sender == 'defer' then
      task:insert_result('DATA_DEFER', 1.0)
    elseif sender == 'async' or sender == 'timeout' then
      task:add_timer(sender == 'timeout' and 0.5 or 0.05, function() end)
    end
  end,
}
for _, name in ipairs({ 'DATA_REJECT', 'DATA_DEFER' }) do
  rspamd_config:register_symbol { name = name, type = 'virtual', parent = id }
end

rspamd_config:register_symbol {
  name = 'EOM_CONSUMER',
  callback = function(task)
    assert(task:get_content():len() > 0)
    local mode = task:get_mempool():get_variable('data_callback_ran', 'bool') and 'full' or 'replayed'
    assert(task:get_check_fact('DATA_PRODUCER', 'sender') == task:get_from('smtp')[1].user)
    task:set_milter_reply {
      add_headers = { ['X-Multistage-Test'] = { value = mode, order = -1 } },
    }
  end,
}
rspamd_config:register_dependency('EOM_CONSUMER', 'DATA_PRODUCER')

rspamd_config:register_symbol {
  name = 'DATA_OBSERVER',
  type = 'idempotent',
  required_inputs = envelope,
  terminal_observer = true,
  callback = function(task)
    local event = task:get_terminal_event()
    if event then
      assert(event.decision_stage == 'data' and not event.has_body)
    end
  end,
}
