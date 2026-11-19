--[[
A map of two HTTP URLs served by dummy_http.py:
  /map-novalidators has no ETag, Last-Modified or Expires, so every check of
                    it reports a change and the whole map is reread
  /map-expiring     has all of them and expires a few seconds after a fetch

The symbol tells which of the two the scanner has.
]]

local dummy_http_port = tonumber(rspamd_env and rspamd_env.PORT_DUMMY_HTTP) or 18080

local test_map = rspamd_config:add_map({
  url = {
    string.format('http://127.0.0.1:%d/map-novalidators', dummy_http_port),
    string.format('http://127.0.0.1:%d/map-expiring', dummy_http_port),
  },
  description = 'two HTTP URLs with a different expiry',
  type = 'set',
})

rspamd_config:register_symbol({
  name = 'HTTP_MAP_EXPIRY',
  score = 1.0,
  callback = function()
    local has_novalidators = test_map:get_key('novalidators.example.com')
    local has_expiring = test_map:get_key('expiring.example.com')

    if has_novalidators and has_expiring then
      return true, 'both'
    end

    return true, string.format('novalidators=%s expiring=%s',
        has_novalidators and 'yes' or 'no', has_expiring and 'yes' or 'no')
  end
})
