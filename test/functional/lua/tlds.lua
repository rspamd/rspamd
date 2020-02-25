rspamd_config:register_symbol({
  name = 'TEST_TLD',
  score = 1.0,
  callback = function()
    local prefixes = {
      '',
      'example.'
    }
    local test_domains = {
      'example.ac',
      'example.b.br',
      'example.co',
      'example.com',
      'example.co.za',
      'example.in.net',
      'example.star.kawasaki.jp',
      'example.net',
      'example.net.in',
      'example.star.nom.br',
      'example.org',
      'example.org.ac',
      'example.ru.com',
      'example.za.net',
      'example.za.org',
      'org.org.za',
    }
    local worry = {}
    local rspamd_mempool = require 'rspamd_mempool'
    local rspamd_url = require 'rspamd_url'
    local rspamd_util = require 'rspamd_util'
    local pool = rspamd_mempool.create()
    for _, d in ipairs(test_domains) do
      (function()
        for _, p in ipairs(prefixes) do
          local test = rspamd_util.get_tld(p .. d)
          if (test ~= d) then
            local opt = string.format('util.get_tld:p=%s;d=%s;got=%s', p, d, test)
            table.insert(worry, opt)
            return
          end
          local u = rspamd_url.create(pool, p .. d)
          test = u:get_tld()
          if (test ~= d) then
            local opt = string.format('url.create:p=%s;d=%s;got=%s', p, d, test)
            table.insert(worry, opt)
            return
          end
        end
      end)()
    end
    if (#worry == 0) then
      return true, 1.0, "no worry"
    else
      return true, 1.0, worry
    end
  end
})
