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
      {'/Тест/iu', 'тест', true},
      {'/test$/m', '123test', true},
      {'/^test$/m', '123test', false},
      {'m,test,', 'test', true},
      {'m,test,', 'test123', false},
      {'m{https?://[^/?\\s]+?:\\d+(?<!:80)(?<!:443)(?<!:8080)(?:/|\\s|$)}', '', false},
      {'/test/i', 'TeSt123', true},
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
  
  test("Regexp capture", function()
    local cases = {
      {'Body=(\\S+)(?: Fuz1=(\\S+))?(?: Fuz2=(\\S+))?', 
        'mc-filter4 1120; Body=1 Fuz1=2 Fuz2=3', 
        {'Body=1 Fuz1=2 Fuz2=3', '1', '2', '3'}},
      {'Body=(\\S+)(?: Fuz1=(\\S+))?(?: Fuz2=(\\S+))?', 
      'mc-filter4 1120; Body=1 Fuz1=2', {'Body=1 Fuz1=2', '1', '2'}},
      {'Body=(\\S+)(?: Fuz1=(\\S+))?(?: Fuz2=(\\S+))?', 
      'mc-filter4 1120; Body=1 Fuz1=2 mc-filter4 1120; Body=1 Fuz1=2 Fuz2=3', 
      {'Body=1 Fuz1=2', '1', '2'}, {'Body=1 Fuz1=2 Fuz2=3', '1', '2', '3'}},
    }
    for _,c in ipairs(cases) do
      local r = re.create_cached(c[1])
      assert_not_nil(r, "cannot parse " .. c[1])
      local res = r:search(c[2], false, true)
      
      assert_not_nil(res, "cannot find pattern")
      
      for k = 3, table.maxn(c) do
        for n,m in ipairs(c[k]) do
          assert_equal(res[k - 2][n], c[k][n], string.format("'%s' doesn't match with '%s'",
            c[k][n], res[k - 2][n]))
        end
      end
    end
  end)
  
  test("Regexp split", function()
    local cases = {
      {'\\s', 'one', {'one'}}, -- one arg
      {'\\s', 'one two', {'one', 'two'}}, -- trivial
      {'/,/i', '1,2', {'1', '2'}}, -- trivial
      {'\\s', 'one   two', {'one', 'two'}}, -- multiple delimiters
      {'\\s', '  one   two  ', {'one', 'two'}}, -- multiple delimiters
      {'\\s', '  one   ', {'one'}}, -- multiple delimiters
      {'[:,]', ',,,:::one,two,,', {'one', 'two'}}, -- multiple delimiters
      {'[\\|\\s]', '16265 | 1.1.1.0/22 | TR | ripencc | 2014-02-28', 
        {'16265', '1.1.1.0/22', 'TR', 'ripencc', '2014-02-28'}}, -- practical
      {'|', '16265 | 1.1.1.0/22 | TR | ripencc | 2014-02-28', {}} -- bad re
    }
  
    for _,c in ipairs(cases) do
      local r = re.create_cached(c[1])
      assert_not_nil(r, "cannot parse " .. c[1])
      
      local res = r:split(c[2])
      assert_not_nil(res, "cannot split " .. c[2])
      
      for i,r in ipairs(c[3]) do
        assert_equal(res[i], r)
      end
    end
  end)
  
  end
)