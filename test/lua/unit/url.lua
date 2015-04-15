-- URL parser tests

context("URL check functions", function()
  local mpool = require("rspamd_mempool")
  local url = require("rspamd_url")
  local logger = require("rspamd_logger")
  local ffi = require("ffi")
  ffi.cdef[[
  void rspamd_url_init (const char *tld_file);
  ]]

  test("Extract urls from text", function()
    local pool = mpool.create()
    local cases = {
      {"test.com text", {"test.com", nil}},
      {"mailto:A.User@example.com text", {"example.com", "A.User"}},
      {"http://Тест.Рф:18 text", {"тест.рф", nil}},
      {"http://user:password@тест2.РФ:18 text", {"тест2.рф", "user"}},
      {"somebody@example.com", {"example.com", "somebody"}},
    }
    
    local test_dir = string.gsub(debug.getinfo(1).source, "^@(.+/)[^/]+$", "%1")
    
    ffi.C.rspamd_url_init(string.format('%s/%s', test_dir, "test_tld.dat"))
    
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
end)