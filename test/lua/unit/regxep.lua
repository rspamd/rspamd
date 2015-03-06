context("Regexp unit tests", function()
  local re = require("rspamd_regexp")
  
  test("Regexp creation", function()
    assert_not_nil(re.create_cached('/test$/m'))
    assert_not_nil(re.create_cached('^test$', 'm'))
    assert_not_nil(re.create_cached('m,test,m'))
    assert_not_nil(re.create_cached('m|test|m'))
  end)
  test("Regexp match", function()
    local cases = {
      {'/test$/m', '123test', true},
      {'/^test$/m', '123test', false},
      {'m,test,', 'test', true},
      {'m,test,', 'test123', false},
      {'/test/i', 'TeSt123', true},
      {'/тест/i', 'ТесТ', true},
    }
    
    for _,c in ipairs(cases) do
      local r = re.create_cached(c[1])
      assert_not_nil(r)
      local res = r:match(c[2])
      
      assert_equal(res, c[3], string.format("'%s' doesn't match with '%s'",
        c[2], c[1]))
    end
  end)
  end
)