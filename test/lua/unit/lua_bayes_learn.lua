context("Lua bayes learn - autolearn", function()
  local lua_bayes_learn = require "lua_bayes_learn"

  local function make_task(spam_learns, ham_learns)
    local learns = { spam_learns = spam_learns, ham_learns = ham_learns }
    return {
      get_queue_id = function() return 'queue_id' end,
      get_from_ip = function() return nil end,
      get_mempool = function()
        return {
          get_variable = function(_, name) return learns[name] end,
        }
      end,
    }
  end

  local function autolearn(opts)
    return lua_bayes_learn.autolearn(make_task(3, 0), {
      spam_threshold = 6.0,
      ham_threshold = -0.5,
      check_balance = opts.check_balance,
      min_balance = opts.min_balance,
      balance = opts.balance,
      logging = { enabled = false },
      verdict_source = {
        extractor = function() return 'spam', 10.0 end,
      },
    })
  end

  test("a legacy minimum balance applies to the current call", function()
    local res, reason = autolearn({ check_balance = true })
    assert_nil(res)
    assert_equal('spam balance check failed', reason)

    res = autolearn({ check_balance = true, min_balance = 0.25 })
    assert_equal('spam', res)

    res, reason = autolearn({ check_balance = true })
    assert_nil(res)
    assert_equal('spam balance check failed', reason)
  end)

  test("legacy check_balance is independent across calls", function()
    local res = autolearn({ check_balance = false })
    assert_equal('spam', res)

    res = autolearn({ check_balance = true })
    assert_nil(res)

    res = autolearn({})
    assert_equal('spam', res)
  end)

  test("explicit nested balance settings take precedence over legacy keys", function()
    local res = autolearn({ check_balance = true, balance = { enabled = false } })
    assert_equal('spam', res)

    res = autolearn({ check_balance = true, min_balance = 0.25, balance = { min_balance = 0.9 } })
    assert_nil(res)
  end)
end)
