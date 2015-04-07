-- Trie search tests

context("Trie search functions", function()
  local t = require "rspamd_trie"
  
  test("Trie search", function()
    local patterns = {
      'test',
      'est',
      'he',
      'she',
      'str\0ing'
    }
    
    local trie = t.create(patterns)
    assert_not_nil(trie, "cannot create trie")
    
    local cases = {
      {'test', true, {{4, 0}, {4, 1}}},
      {'she test test', true, {{3, 3}, {3, 2}, {8, 0}, {8, 1}, {13, 0}, {13, 1}}},
      {'non-existent', false},
      {'str\0ing test', true, {{7, 4}, {12, 0}, {12, 1}}},
    }
    
    local function comparetables(t1, t2)
      if #t1 ~= #t2 then return false end
      for i=1,#t1 do
        if type(t1[i]) ~= type(t2[i]) then return false
        elseif type(t1[i]) == 'table' then
          if not comparetables(t1[i], t2[i]) then return false end
        elseif t1[i] ~= t2[i] then 
          return false 
        end
      end
      return true
    end
    
    for _,c in ipairs(cases) do
      local res = {}
      local function cb(idx, pos)
        table.insert(res, {pos, idx})
        
        return 0
      end
      
      ret = trie:search_text(c[1], cb)
      
      assert_equal(c[2], ret, tostring(c[2]) .. ' while matching ' .. c[1])
      
      if ret then
        local cmp = comparetables(res, c[3])
        assert_true(cmp, 'valid results for case: ' .. c[1])
      end
    end
    
  end)
end)