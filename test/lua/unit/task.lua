context("Task processing", function()
  local ffi = require("ffi")
  local rspamd_util = require("rspamd_util")
  local logger = require("rspamd_logger")
  local test_dir = string.gsub(debug.getinfo(1).source, "^@(.+/)[^/]+$", "%1")
    
  local tld_file = string.format('%s/%s', test_dir, "test_tld.dat")
  local config = {
    options = {
      filters = {'spf', 'dkim', 'regexp'},
      url_tld = tld_file,
      dns = {
        nameserver = {'8.8.8.8'}
      },
    },
    logging = {
      type = 'console',
      level = 'info'
    },
    metric = {
      name = 'default',
      actions = {
        reject = 100500,
      },
      unknown_weight = 1
    }
  }
  
  test("Process a simple task", function()
    local cfg = rspamd_util.config_from_ucl(config)
    assert_not_nil(cfg)
    
    local msg = [[
From: <>
To: <nobody@example.com>
Subject: test
Content-Type: text/plain

Test.
]]
    local obj = rspamd_util.process_message(cfg, msg)
    print(logger.slog("result: %1", obj))
  end)
end)