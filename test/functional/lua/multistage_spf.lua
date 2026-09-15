local rspamd_spf = require 'rspamd_spf'
local rspamd_ip = require 'rspamd_ip'
local ucl = require 'ucl'

-- Count real resolver entry, including the synchronous no-domain path. The
-- production SPF callback still uses the real resolver and record evaluator.
local resolve = rspamd_spf.resolve
rspamd_spf.resolve = function(task, callback)
  local mpool = task:get_mempool()
  mpool:set_variable('spf_test_resolves', 1)

  return resolve(task, function(...)
    callback(...)

    if task:get_from('smtp')[1].user == 'callback-error' then
      error('deliberate SPF callback failure after inserting results')
    end
  end)
end

local plugins = rspamd_paths.CONFDIR .. '/../src/plugins/lua/'

-- Match the module loader: disabled modules must not register relay rules.
local relay = rspamd_config:get_all_opt('external_relay')

if relay and relay.enabled then
  dofile(plugins .. 'external_relay.lua')
end

-- Dependencies registered by external_relay must also work before SPF loads.
dofile(plugins .. 'spf.lua')
dofile(plugins .. 'dmarc.lua')

-- These changes happen only once the real message is available.
rspamd_config:register_symbol {
  name = 'SPF_TEST_PREFILTER',
  type = 'prefilter',
  callback = function(task)
    local change = task:get_header('X-SPF-Test-Change')

    if change == 'ip' then
      task:set_from_ip(rspamd_ip.from_string('192.0.2.2'))
    elseif change == 'whitelist' then
      task:set_from_ip(rspamd_ip.from_string('192.0.2.10'))
    elseif change == 'disable' then
      task:disable_symbol('SPF_CHECK')
    elseif change == 'sender' then
      task:set_from('smtp', 'rewritten@fail.example.com')
    end
  end,
}

-- Exercise the existing explicit early policy only for a chosen failed sender.
local early = rspamd_config:register_symbol {
  name = 'SPF_TEST_POLICY',
  required_inputs = { 'connection', 'helo', 'sender' },
  replay_version = 1,
  callback = function(task)
    local fact = task:get_check_fact('SPF_CHECK', 'spf')

    if fact and fact.result == 'fail' and task:get_from('smtp')[1].user == 'reject' then
      task:insert_result('DATA_REJECT', 1)
    end
  end,
}
rspamd_config:register_symbol { name = 'DATA_REJECT', type = 'virtual', parent = early }
rspamd_config:register_dependency('SPF_TEST_POLICY', 'SPF_CHECK')

rspamd_config:register_symbol {
  name = 'SPF_TEST_OBSERVER',
  type = 'postfilter',
  callback = function(task)
    local mpool = task:get_mempool()
    local state = {
      resolves = mpool:get_variable('spf_test_resolves', 'double') or 0,
      result = mpool:get_variable('spf_result') or false,
      record = mpool:get_variable('spf_record') or false,
      dmarc_checks = mpool:get_variable('dmarc_checks', 'double') or 0,
      dmarc_result = mpool:get_variable('dmarc_result') or false,
      facts = task:get_check_fact('SPF_CHECK', 'spf') or false,
      symbols = {},
    }

    for _, symbol in ipairs(task:get_symbols_all()) do
      if symbol.name:match('^R_SPF_') or symbol.name:match('^DMARC_') then
        state.symbols[symbol.name] = { score = symbol.score, options = symbol.options }
      end
    end

    task:set_milter_reply {
      add_headers = { ['X-SPF-Test'] = { value = ucl.to_format(state, 'json-compact'), order = -1 } },
    }
  end,
}
