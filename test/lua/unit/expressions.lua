-- Expressions unit tests

context("Rspamd expressions", function()
  local rspamd_expression = require "rspamd_expression"
  local rspamd_mempool = require "rspamd_mempool"
  local rspamd_regexp = require "rspamd_regexp"
  local split_re = rspamd_regexp.create('/\\s+|\\)|\\(/')
  
  local function parse_func(str)
    -- extract token till the first space character
    local token = str
    local t = split_re:split(str)
    if t then
      token = t[1]
    end
    -- Return token name
    return token
  end
  
  test("Expression creation function", function()
    local function process_func(token, task)
      -- Do something using token and task
    end
    
    local pool = rspamd_mempool.create()
    
    local cases = {
       {'A & B | !C', 'C ! A B & |'},
       {'A & (B | !C)', 'A B C ! | &'},
       {'A & B &', nil},
       -- Unbalanced braces
       {'(((A))', nil},
       -- Balanced braces
       {'(((A)))', 'A'},
       -- Plus and comparision operators
       {'A + B + C + D > 2', '2 A B C D +(4) >'},
       -- Plus and logic operators
       {'((A + B + C + D) > 2) & D', 'D 2 A B C D +(4) > &'},
       -- Associativity
       {'A | B | C & D & E', 'A B C D E &(3) |(3)'},
       -- More associativity
       {'1 | 0 & 0 | 0', '1 0 0 & 0 |(3)'},
       -- Extra space
       {'A & B | ! C', 'C ! A B & |'},
    }
    for _,c in ipairs(cases) do
      local expr,err = rspamd_expression.create(c[1], 
        {parse_func, process_func}, pool)
      
      if not c[2] then
        assert_nil(expr, "Should not be able to parse " .. c[1])
      else
        assert_not_nil(expr, "Cannot parse " .. c[1])
        assert_equal(expr:to_string(), c[2], string.format("Evaluated expr to '%s', expected: '%s'",
            expr:to_string(), c[2]))
      end
    end
    -- Expression is destroyed when the corresponding pool is destroyed
    pool:destroy()
  end)
  test("Expression process function", function()
    local function process_func(token, input)
    
      --print(token)
      local t = input[token]
      
      if t then return 1 end
      return 0
    end
    
    local pool = rspamd_mempool.create()
    local atoms = {
      A = true,
      B = false,
      C = true,
      D = false,
      E = true,
      F = false,
    }
    local cases = {
       {'A & B | !C', 0},
       {'A & (!B | C)', 1},
       {'A + B + C + D + E + F >= 2', 1},
       {'((A + B + C + D) > 1) & F', 0},
       {'(A + B + C + D) > 1 && F || E', 1},
       {'(A + B + C + D) > 100 && F || !E', 0},
       {'F && ((A + B + C + D) > 1)', 0},
       {'!!C', 1},
    }
    for _,c in ipairs(cases) do
      local expr,err = rspamd_expression.create(c[1], 
        {parse_func, process_func}, pool)

      assert_not_nil(expr, "Cannot parse " .. c[1])
      --print(expr)
      res = expr:process(atoms)
      assert_equal(res, c[2], string.format("Processed expr '%s' returned '%d', expected: '%d'",
        expr:to_string(), res, c[2]))
    end
    
    pool:destroy()
  end)
end)