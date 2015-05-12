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
      {'m{https?://[^/?\\s]+?:\\d+(?<!:80)(?<!:443)(?<!:8080)(?:/|\\s|$)}', '', false},
      {'/test/i', 'TeSt123', true},
      {'/ТесТ/iu', 'тест', true},
      -- Raw regexp
      {'/\\S<[-\\w\\.]+\\@[-\\w\\.]+>/r', 'some<example@example.com>', true},
      -- Cyrillic utf8 letter
      {'/\\S<[-\\w\\.]+\\@[-\\w\\.]+>/r', 'some<example@exаmple.com>', false},
    }
    
    for _,c in ipairs(cases) do
      local r = re.create_cached(c[1])
      assert_not_nil(r, "cannot parse " .. c[1])
      local res = r:match(c[2])
      
      assert_equal(res, c[3], string.format("'%s' doesn't match with '%s'",
        c[2], c[1]))
    end
  end)
  
  test("Regexp split", function()
    local cases = {
      {'\\s', 'one two', {'one', 'two'}}, -- trivial
      {'\\s', 'one   two', {'one', 'two'}}, -- multiple delimiters
      {'\\s', '  one   two  ', {'one', 'two'}}, -- multiple delimiters
      {'\\s', '  one   ', {'one', 'two'}}, -- multiple delimiters
      {'[:,]', ',,,:::one,two,,', {'one', 'two'}}, -- multiple delimiters
    }
  
    for _,c in ipairs(cases) do
      local r = re.create_cached(c[1])
      assert_not_nil(r, "cannot parse " .. c[1])
      
      local res = r:split(c[2])
      assert_not_nil(res, "cannot split " .. c[2])
      
      for i,r in ipairs(res) do
        assert_equal(r, c[3][i])
      end
    end
  end)
  
  end
)