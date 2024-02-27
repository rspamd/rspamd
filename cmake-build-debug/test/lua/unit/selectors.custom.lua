local msg
context("Selectors test", function()
  local rspamd_task = require "rspamd_task"
  local logger = require "rspamd_logger"
  local lua_selectors = require "lua_selectors"
  local test_helper = require "rspamd_test_helper"
  local cfg = rspamd_config
  local task

  test_helper.init_url_parser()

  before(function()
    local res
    res,task = rspamd_task.load_from_string(msg, cfg)
    if not res then
      assert_true(false, "failed to load message")
    end
  end)

  local function check_selector(selector_string)
    local sels = lua_selectors.parse_selector(cfg, selector_string)
    local elts = lua_selectors.process_selectors(task, sels)
    return elts
  end

  test("custom selector", function()
    lua_selectors.register_extractor(rspamd_config, "get_something", {
      get_value = function(task, args) -- mandatory field
        return 'simple value','string' -- result + type
      end,
      description = 'Sample extractor' -- optional
    })

    local elts = check_selector('get_something')
    assert_not_nil(elts)
    assert_rspamd_table_eq({actual = elts, expect = {'simple value'}})
  end)

  test("custom transform", function()
    lua_selectors.register_extractor(rspamd_config, "get_something", {
      get_value = function(task, args) -- mandatory field
        return 'simple value','string' -- result + type
      end,
      description = 'Sample extractor' -- optional
    })

    lua_selectors.register_transform(rspamd_config, "append_string", {
      types = {['string'] = true}, -- accepted types
      process = function(input, type, args)
        return input .. table.concat(args or {}),'string' -- result + type
      end,
      map_type = 'string', -- can be used in map like invocation, always return 'string' type
      description = 'Adds all arguments to the input string'
    })

    local elts = check_selector('get_something.append_string(" and a simple tail")')
    assert_not_nil(elts)
    assert_rspamd_table_eq({actual = elts, expect = {'simple value and a simple tail'}})

    local elts = check_selector('get_something.append_string(" and", " a", " simple", " nail")')
    assert_not_nil(elts)
    assert_rspamd_table_eq({actual = elts, expect = {'simple value and a simple nail'}})
  end)
end)


--[=========[ *******************  message  ******************* ]=========]
msg = [[
From: <whoknows@nowhere.com>
To: <nobody@example.com>, <no-one@example.com>
Date: Wed, 19 Sep 2018 14:36:51 +0100 (BST)
Subject: Test subject
Content-Type: multipart/alternative;
    boundary="_000_6be055295eab48a5af7ad4022f33e2d0_"

--_000_6be055295eab48a5af7ad4022f33e2d0_
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: base64

Hello world
]]
