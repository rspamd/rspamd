-- Expressions unit tests

context("Rspamd expressions", function()
  local rspamd_expression = require "rspamd_expression"
  local rspamd_mempool = require "rspamd_mempool"
  local _ = require "fun"
  
  local function parse_func(str)
    -- extract token till the first space character
    local token = table.join('', take_while(function(s) return s ~= ' ' end, str))
    -- Return token name
    return token
  end
  
  test("Expression creation function", function()
    local function process_func(token, task)
      -- Do something using token and task
    end
    
    local pool = rspamd_mempool.create()
    
    local cases = {
       {'A & B | !C', 'A B & C ! |'}
    }
    for _,c in ipairs(cases) do
      local expr,err = rspamd_expression.create(c[1], 
        {parse_func, process_func}, pool)
      
      if c[2] then
        assert_not_null(expr, "Cannot parse " .. c[1] ": " .. err)
      else
        assert_equal(expr:to_string(), c[2], string.format("Evaluated expr to '%s', expected: '%s'",
            expr:to_string(), c[2]))
      end
    end
    -- Expression is destroyed when the corresponding pool is destroyed
    pool:destroy()
  end)
end)