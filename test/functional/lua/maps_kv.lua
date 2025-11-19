local rspamd_ip = require 'rspamd_ip'
local rspamd_logger = require 'rspamd_logger'
local lua_maps = require "lua_maps"

-- Only load maps if environment variables are set
local radix_map, map_map, regexp_map

if rspamd_env.RADIX_MAP then
  radix_map = rspamd_config:add_map ({
    url = rspamd_env.RADIX_MAP,
    type = 'radix',
  })
end

if rspamd_env.MAP_MAP then
  map_map = rspamd_config:add_map ({
    url = rspamd_env.MAP_MAP,
    type = 'map',
  })
end

if rspamd_env.REGEXP_MAP then
  regexp_map = rspamd_config:add_map ({
    url = rspamd_env.REGEXP_MAP,
    type = 'regexp',
  })
end

rspamd_config:register_symbol({
  name = 'RADIX_KV',
  score = 1.0,
  callback = function()
    if not radix_map then return true, 'map not loaded' end
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
    if not map_map then return true, 'map not loaded' end
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
    if not regexp_map then return true, 'map not loaded' end
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

local simple_ext_map = lua_maps.map_add_from_ucl({
  external = true,
  backend = "http://127.0.0.1:18080/map-simple",
  method = "body",
  encode = "json",
}, '', 'external map')
rspamd_config:register_symbol({
  name = 'EXTERNAL_MAP',
  score = 1.0,
  callback = function(task)
    local function cb(res, data, code)
      if res then
        task:insert_result('EXTERNAL_MAP', 1.0, string.format('+%s', data))
      else
        task:insert_result('EXTERNAL_MAP', 1.0, string.format('-%s:%s', code, data))
      end
    end
    simple_ext_map:get_key({
      key = "value",
    }, cb, task)
  end,
})
