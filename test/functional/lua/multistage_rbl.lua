local rspamd_ip = require 'rspamd_ip'
local ucl = require 'ucl'
local plugins = rspamd_paths.CONFDIR .. '/../src/plugins/lua/'
local relay = rspamd_config:get_all_opt('external_relay')

if relay.enabled then
  dofile(plugins .. 'external_relay.lua')
end

dofile(plugins .. 'rbl.lua')

rspamd_config:register_symbol {
  name = 'RBL_TEST_REQUIRED',
  callback = function(task)
    if task:get_header('X-RBL-Required') then
      task:insert_result('RBL_TEST_REQUIRED', 1)
    end
  end,
}

rspamd_config:register_symbol {
  name = 'RBL_TEST_PREFILTER',
  type = 'prefilter',
  callback = function(task)
    local change = task:get_header('X-RBL-Change')

    if change == 'ip' then
      task:set_from_ip(rspamd_ip.from_string('192.0.2.2'))
    elseif change == 'white' then
      task:set_from_ip(rspamd_ip.from_string('192.0.2.3'))
    elseif change == 'disable' then
      task:disable_symbol('RBL_MIXED')
    end
  end,
}

rspamd_config:register_symbol {
  name = 'RBL_TEST_OBSERVER',
  type = 'postfilter',
  callback = function(task)
    local state = { symbols = {}, facts = {} }

    for _, symbol in ipairs(task:get_symbols_all()) do
      if symbol.name:match('^RBL_') then
        state.symbols[symbol.name] = { score = symbol.score, options = symbol.options }
      end
    end

    for _, name in ipairs({ 'RBL_MIXED', 'RBL_WHITE', 'RBL_SELECTED' }) do
      state.facts[name] = task:get_check_fact(name .. '_ENVELOPE', 'complete') or false
    end

    task:set_milter_reply {
      add_headers = { ['X-RBL-Test'] = { value = ucl.to_format(state, 'json-compact'), order = -1 } },
    }
  end,
}

local policy = rspamd_config:register_symbol {
  name = 'RBL_TEST_POLICY',
  required_inputs = { 'connection', 'helo', 'sender' },
  replay_version = 1,
  callback = function(task)
    local plan = task:get_check_fact('RBL_MIXED_ENVELOPE', 'plan')
    local answers = task:get_check_fact('RBL_MIXED_ENVELOPE', 'answers')

    if plan and answers and task:get_from('smtp')[1].user == 'reject' then
      for _, answer in pairs(answers) do
        if answer.results[1] == '127.0.0.2' then
          task:insert_result('DATA_REJECT', 1)
          break
        end
      end
    end
  end,
}

rspamd_config:register_symbol { name = 'DATA_REJECT', type = 'virtual', parent = policy }
rspamd_config:register_dependency('RBL_TEST_POLICY', 'RBL_MIXED_ENVELOPE')

rspamd_config:register_settings_id('rbl_only_virtual', {
  RBL_MIXED_HIT = true,
  RBL_TEST_OBSERVER = true,
}, nil)

rspamd_config:register_settings_id('rbl_disable_public', nil, { RBL_MIXED = true })
