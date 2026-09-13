local spf = require 'rspamd_spf'
local ucl = require 'ucl'
require('global_functions')()

-- Count entry into the real resolver separately from DNS caching.
local resolve = spf.resolve
spf.resolve = function(task, callback)
  task:get_mempool():set_variable('integration_spf_calls', 1)
  return resolve(task, callback)
end

for _, plugin in ipairs({ 'spf', 'rbl', 'multimap' }) do
  dofile('/source/src/plugins/lua/' .. plugin .. '.lua')
end

local envelope = { 'connection', 'helo', 'sender', 'recipients' }

rspamd_config:register_symbol {
  name = 'INTEGRATION_SLOW',
  required_inputs = envelope,
  replay_version = 1,
  callback = function(task)
    local user = task:get_from('smtp')[1].user or ''

    if user:match('^slow') then
      task:add_timer(0.8, function() end)
    end
  end,
}

rspamd_config:register_symbol {
  name = 'INTEGRATION_BODY',
  callback = function(task)
    assert(task:get_content():len() > 0)
    task:insert_result('INTEGRATION_BODY', 1)

    if task:get_header('X-Reject-EOM') then
      task:set_pre_result('reject', 'Rejected after body inspection', 'postfix integration')
    end
  end,
}

rspamd_config:register_symbol {
  name = 'INTEGRATION_OBSERVER',
  type = 'idempotent',
  required_inputs = envelope,
  terminal_observer = true,
  callback = function(task)
    local terminal = task:get_terminal_event()
    local state = {
      from = task:get_from('smtp')[1].addr,
      terminal = terminal or false,
      dns = task:get_dns_req(),
      spf_calls = task:get_mempool():get_variable('integration_spf_calls', 'double') or 0,
      spf = task:get_mempool():get_variable('spf_result') or false,
      symbols = {},
    }

    for _, symbol in ipairs(task:get_symbols_all()) do
      state.symbols[symbol.name] = symbol.options or {}
    end

    if terminal then
      assert(terminal.decision_stage == 'data' and not terminal.has_body)
      assert(not state.symbols.INTEGRATION_BODY)
    else
      assert(task:get_content():len() > 0 and state.symbols.INTEGRATION_BODY)
      task:set_milter_reply {
        add_headers = { ['X-Multistage-Integration'] = {
          value = ucl.to_format(state, 'json-compact'), order = -1,
        } },
      }
    end

    local output = assert(io.open('/tmp/postfix-data/events.jsonl', 'a'))
    output:write(ucl.to_format(state, 'json-compact'), '\n')
    output:close()
  end,
}
