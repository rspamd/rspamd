local rspamd_ip = require 'rspamd_ip'
local rspamd_logger = require 'rspamd_logger'

local radix_map = rspamd_config:add_map ({
  url = rspamd_env.RADIX_MAP,
  type = 'radix',
})

local map_map = rspamd_config:add_map ({
  url = rspamd_env.MAP_MAP,
  type = 'map',
})

local regexp_map = rspamd_config:add_map ({
  url = rspamd_env.REGEXP_MAP,
  type = 'regexp',
})

rspamd_config:register_symbol({
  name = 'RADIX_KV',
  score = 1.0,
  callback = function()
    local sip = {'8.8.8.8', '::1', '192.168.1.1', '10.0.1.1'}
    local expected = {'test one', 'another', '1', false}
    for i = 1, #sip do
      if (radix_map:get_key(rspamd_ip.from_string(sip[i])) ~= expected[i]) then
        local rip = rspamd_ip.from_string(sip[i])
        local val = radix_map:get_key(rip)
        return true, rspamd_logger.slog('plain: get_key(%s) [%s] -> %s [%s] [expected %s]', rip, type(rip), val, type(val), expected[i])
      end
      if (radix_map:get_key(sip[i]) ~= expected[i]) then
        local val = radix_map:get_key(sip[i])
        return true, rspamd_logger.slog('string: get_key(%s) [%s] -> %s [%s] [expected %s]', sip[i], type(sip[i]), val, type(val), expected[i])
      end
    end
    return true, 'no worry'
  end
})

rspamd_config:register_symbol({
  name = 'MAP_KV',
  score = 1.0,
  callback = function()
    local str = {'foo', 'asdf.example.com', 'asdf', 'barf'}
    local expected = {'bar', 'value', '', false}
    for i = 1, #str do
      if (map_map:get_key(str[i]) ~= expected[i]) then
        local val = map_map:get_key(str[i])
        return true, rspamd_logger.slog('get_key(%s) [%s] -> %s [%s] [expected %s]', str[i], type(str[i]), val, type(val), expected[i])
      end
    end
    return true, 'no worry'
  end,
})

rspamd_config:register_symbol({
  name = 'REGEXP_KV',
  score = 1.0,
  callback = function()
    local str = {'foo', 'asdf.example.com', 'asdf', 'barf'}
    local expected = {'bar', 'value', '1', false}
    for i = 1, #str do
      if (regexp_map:get_key(str[i]) ~= expected[i]) then
        local val = regexp_map:get_key(str[i])
        return true, rspamd_logger.slog('get_key(%s) [%s] -> %s [%s] [expected %s]', str[i], type(str[i]), val, type(val), expected[i])
      end
    end
    return true, 'no worry'
  end,
})
