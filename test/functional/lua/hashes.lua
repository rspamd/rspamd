rspamd_config:register_symbol({
  name = 'TEST_HASHES',
  score = 1.0,
  callback = function()
    local hash = require 'rspamd_cryptobox_hash'
    local logger = require 'rspamd_logger'

    local worry = {}
    local test_data = {
      {
        ['str'] = 'asdf.qwerty.123',
        ['hex'] = 'bf22dd95750034b9af93f0e4e5954aca3506bbcdbc051d91bd9af2d1a8fc294e848626b1c1751e58b44c4d3ea69dec5efa5a214dc59c77b1a9ca3bde3babac9d',
      },
      {
        ['specific'] = 'md5',
        ['str'] = 'asdf.qwerty.123',
        ['hex'] = 'cf25ddc406c50de0c13de2b79d127646',
      },
      {
        ['init'] = 'asdf.qwerty.123',
        ['str'] = 'asdf.qwerty.123',
        ['hex'] = 'bf22dd95750034b9af93f0e4e5954aca3506bbcdbc051d91bd9af2d1a8fc294e848626b1c1751e58b44c4d3ea69dec5efa5a214dc59c77b1a9ca3bde3babac9d',
        ['reset'] = true,
      },
      {
        ['init'] = 'asdf.qwerty.123',
        ['str'] = 'asdf.qwerty.123',
        ['hex'] = 'e445046aa21a705dcce1343795630f88bc0196a0070011fdce789d5a2a349a8f85349834ade555ca21439f65fdc4dbcf82dcff7fcc559ef11c508507515c1532',
      },
      {
        ['init'] = 'asdf.qwerty.123',
        ['specific'] = 'md5',
        ['str'] = 'asdf.qwerty.123',
        ['hex'] = '9ef941c4d050e43b1e665300f4fbe054',
      },
      {
        ['init'] = 'asdf.qwerty.123',
        ['specific'] = 'md5',
        ['str'] = 'asdf.qwerty.123',
        ['hex'] = 'cf25ddc406c50de0c13de2b79d127646',
        ['reset'] = true,
      },
    }

    for _, t in ipairs(test_data) do
      local h
      if not t['specific'] then
        h = hash.create(t['init'])
      else
        h = hash.create_specific(t['specific'], t['init'])
      end
      if t['reset'] then
        h:reset()
      end
      h:update(t['str'])
      if not (h:hex() == t['hex']) then
        t['error'] = 'sum mismatch: ' .. h:hex()
        table.insert(worry, logger.slog('%1', t))
      end
    end

    if (#worry == 0) then
      return true, "no worry"
    else
      return true, table.concat(worry, ",")
    end
  end
})
