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

  test("legacy check_balance and min_balance options are honoured", function()
    local conf = {
      spam_threshold = 6.0,
      ham_threshold = -0.5,
      check_balance = true,
      logging = { enabled = false },
      verdict_source = {
        extractor = function() return 'spam', 10.0 end,
      },
    }
    local res, reason = lua_bayes_learn.autolearn(make_task(3, 0), conf)
    assert_nil(res)
    assert_equal('spam balance check failed', reason)

    conf.min_balance = 0.25
    res = lua_bayes_learn.autolearn(make_task(3, 0), conf)
    assert_equal('spam', res)
  end)
end)
