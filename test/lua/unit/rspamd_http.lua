context("Lua HTTP request arguments", function()
  local rspamd_http = require "rspamd_http"
  local rspamd_task = require "rspamd_task"

  local _, task = rspamd_task.load_from_string('Subject: test\n\ntest\n', rspamd_config)

  local function request(params)
    params.url = 'http://127.0.0.1/'
    params.task = task
    params.callback = function() end

    return rspamd_http.request(params)
  end

  local function registry_size()
    local n = 0

    for _ in pairs(debug.getregistry()) do
      n = n + 1
    end

    return n
  end

  test("an unknown method is refused", function()
    assert_error(request, { method = 'FOO' })
  end)

  test("a method that is not a string is refused", function()
    assert_error(request, { method = 1 })
  end)

  test("a refused request releases its callback", function()
    for _, params in ipairs({ { method = 'FOO' }, { body = true } }) do
      -- The first call takes the registry slot that the next ones reuse
      pcall(request, params)
      local before = registry_size()

      for _ = 1, 10 do
        pcall(request, params)
      end

      assert_equal(before, registry_size())
    end
  end)
end)
