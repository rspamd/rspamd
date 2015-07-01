-- URL parser tests

context("URL check functions", function()
  local mpool = require("rspamd_mempool")
  local url = require("rspamd_url")
  local logger = require("rspamd_logger")
  local ffi = require("ffi")
  ffi.cdef[[
  void rspamd_url_init (const char *tld_file);
  unsigned ottery_rand_range(unsigned top);
  ]]
  
  local test_dir = string.gsub(debug.getinfo(1).source, "^@(.+/)[^/]+$", "%1")

  ffi.C.rspamd_url_init(string.format('%s/%s', test_dir, "test_tld.dat"))

  test("Extract urls from text", function()
    local pool = mpool.create()
    local cases = {
      {"test.com text", {"test.com", nil}},
      {"test.com. text", {"test.com", nil}},
      {"mailto:A.User@example.com text", {"example.com", "A.User"}},
      {"http://Тест.Рф:18 text", {"тест.рф", nil}},
      {"http://user:password@тест2.РФ:18 text", {"тест2.рф", "user"}},
      {"somebody@example.com", {"example.com", "somebody"}},
      {"https://127.0.0.1/abc text", {"127.0.0.1", nil}},
      {"https://127.0.0.1 text", {"127.0.0.1", nil}},
      {"https://[::1]:1", {"::1", nil}},
      {"https://user:password@[::1]:1", {"::1", nil}},
      {"https://user:password@[::1]", {"::1", nil}},
      {"https://user:password@[::1]/1", {"::1", nil}},
    }

    for _,c in ipairs(cases) do
      local res = url.create(pool, c[1])
      
      assert_not_nil(res, "cannot parse " .. c[1])
      local t = res:to_table()
      --local s = logger.slog("%1 -> %2", c[1], t)
      --print(s)
      assert_not_nil(t, "cannot convert to table " .. c[1])
      assert_equal(c[2][1], t['host'])
      
      if c[2][2] then
        assert_equal(c[2][2], t['user'])
      end
    end
    pool:destroy()
  end)
  
  -- Some cases from https://code.google.com/p/google-url/source/browse/trunk/src/url_canon_unittest.cc
  test("Parse urls", function()
    local pool = mpool.create()
    -- input, parseable, {host, port, user, password, path, query, part}
    local cases = {
      {"http://www.google.com/foo?bar=baz#", true, {
        host = 'www.google.com', path = 'foo', query = 'bar=baz', tld = 'google.com'
      }},
      {"http://[www.google.com]/", false},
      {"ht\ttp:@www.google.com:80/;p?#", false},
      {"http://user:pass@/", false},
      {"http://foo:-80/", false},
      {"http:////////user:@google.com:99?foo", true, {
        host = 'google.com', user = 'user', port = 99, query = 'foo'
      }},
      {"http://%25DOMAIN:foobar@foodomain.com/", true, {
        host = 'foodomain.com', user = '%25DOMAIN'
      }}
    }
    
    for _,c in ipairs(cases) do
      local res = url.create(pool, c[1])
      
      if c[2] then
        assert_not_nil(res, "cannot parse " .. c[1])
        
        local uf = res:to_table()
        
        for k,v in pairs(c[3]) do
          assert_not_nil(uf[k], k .. ' is missing in url, must be ' .. v)
          assert_equal(uf[k], v, 'expected ' .. v .. ' for ' .. k .. ' but got ' .. uf[k])
        end
        for k,v in pairs(uf) do
          if k ~= 'url' and k ~= 'protocol' and k ~= 'tld' then
            assert_not_nil(c[3][k], k .. ' should be absent but it is ' .. v .. ' in: ' .. c[1])
          end
        end
      else
        assert_nil(res, "should not parse " .. c[1] .. ' parsed to: ' .. tostring(res))
      end
    end
  end
  )
end)