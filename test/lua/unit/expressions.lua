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

  local atoms = {
    A = 1.0,
    B = 0,
    C = 1,
    D = 0,
    E = 1,
    F = 0,
    G = 0,
    H = 0,
    I = 0,
    J = 0,
    K = 0,
  }
  local function process_func(token, input)

    --print(token)
    local t = input[token]

    return t
  end

  local pool = rspamd_mempool.create()

  local cases = {
    {'A & (!B | C)', '(A) (B) ! (C) | &'},
    {'A & B | !C', '(C) ! (A) (B) & |'},
    {'A & (B | !C)', '(A) (B) (C) ! | &'},
    {'A & B &', nil},
    -- Unbalanced braces
    {'(((A))', nil},
    -- Balanced braces
    {'(((A)))', '(A)'},
    -- Plus and comparison operators
    {'A + B + C + D > 2', '(A) (B) (C) (D) +(4) 2 >'},
    -- Plus and logic operators
    {'((A + B + C + D) > 2) & D', '(D) (A) (B) (C) (D) +(4) 2 > &'},
    -- Associativity
    {'A | B | C & D & E', '(A) (B) (C) (D) (E) &(3) |(3)'},
    -- More associativity
    {'1 | 0 & 0 | 0', '(1) (0) (0) (0) & |(3)'},
    {'(A) & (B) & ((C) | (D) | (E) | (F))', '(A) (B) (C) (D) (E) (F) |(4) &(3)' },
    -- Extra space
    {'A & B | ! C', '(C) ! (A) (B) & |'},
    -- False minus
    {'A + B + -C', '(A) (B) (-C) +(3)'},
  }
  for _,c in ipairs(cases) do
    test("Expression creation function: " .. c[1], function()
      local expr,err = rspamd_expression.create(c[1],
          {parse_func, process_func}, pool)

      if not c[2] then
        assert_nil(expr, "Should not be able to parse " .. c[1])
      else
        assert_not_nil(expr, "Cannot parse " .. c[1] .. '; error: ' .. (err or 'wut??'))
        assert_equal(expr:to_string(), c[2], string.format("Evaluated expr to '%s', expected: '%s'",
            expr:to_string(), c[2]))
      end
    end)
  end
  -- Expression is destroyed when the corresponding pool is destroyed
  cases = {
    {'(E) && ((B + B + B + B) >= 1)', 0},
    {'A & B | !C', 0},
    {'A & (!B | C)', 1},
    {'A + B + C + D + E + F >= 2', 1},
    {'((A + B + C + D) > 1) & F', 0},
    {'(A + B + C + D) > 1 && F || E', 1},
    {'(A + B + C + D) > 100 && F || !E', 0},
    {'F && ((A + B + C + D) > 1)', 0},
    {'(E) && ((B + B + B + B) >= 1)', 0},
    {'!!C', 1},
    {'(B) & (D) & ((G) | (H) | (I) | (A))', 0},
    {'A & C & (!D || !C || !E)', 1},
    {'A & C & !(D || C || E)', 0},
    {'A + B + C', 2},
    {'A * 2.0 + B + C', 3},
    {'A * 2.0 + B - C', 1},
    {'A / 2.0 + B - C', -0.5},
  }
  for _,c in ipairs(cases) do
    test("Expression process function: " .. c[1], function()
      local expr,err = rspamd_expression.create(c[1],
          {parse_func, process_func}, pool)

      assert_not_nil(expr, "Cannot parse " .. c[1] .. '; error: ' .. (err or 'wut??'))
      --print(expr)
      res = expr:process(atoms)
      assert_equal(res, c[2], string.format("Processed expr '%s'{%s} returned '%d', expected: '%d'",
          expr:to_string(), c[1], res, c[2]))
    end)
  end
end)
