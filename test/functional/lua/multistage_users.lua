local ucl = require 'ucl'
local rspamd_ip = require 'rspamd_ip'
local plugins = rspamd_paths.CONFDIR .. '/../src/plugins/lua/'

require('global_functions')()

if rspamd_config:get_all_opt('external_relay').enabled then
  dofile(plugins .. 'external_relay.lua')
end

dofile(plugins .. 'asn.lua')
dofile(plugins .. 'multimap.lua')
dofile(plugins .. 'settings.lua')

-- Deliberately not an ASN dependency: a real rewriter would defer ASN at
-- DATA. This simulates an input change at the replay boundary.
rspamd_config:register_symbol {
  name = 'USER_CHANGE_IP', type = 'prefilter', priority = 20,
  callback = function(task)
    if task:get_header('X-Change-IP') then
      task:set_from_ip(rspamd_ip.from_string('192.0.2.2'))
    end
  end,
}
rspamd_config:register_symbol {
  name = 'USER_OBSERVER', type = 'postfilter',
  callback = function(task)
    local mpool = task:get_mempool()
    local state = {
      asn = mpool:get_variable('asn') or false,
      ipnet = mpool:get_variable('ipnet') or false,
      country = mpool:get_variable('country') or false,
      facts = task:get_check_fact('ASN_CHECK', 'asn') or false,
      dns = task:get_dns_req(),
      symbols = {},
    }

    for _, symbol in ipairs(task:get_symbols_all()) do
      if symbol.name:match('^USER_') or symbol.name == 'ASN' or symbol.name == 'ASN_FAIL' then
        state.symbols[symbol.name] = { score = symbol.score, options = symbol.options }
      end
    end

    task:set_milter_reply {
      add_headers = { ['X-User-Test'] = { value = ucl.to_format(state, 'json-compact'), order = -1 } },
    }
  end,
}

rspamd_config:register_settings_id('ordinary_disable', nil, { USER_ASN = true, USER_HELO = true })
