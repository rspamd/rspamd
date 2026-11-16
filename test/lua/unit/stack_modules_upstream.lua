-- add_watcher with the table form of events

context("Upstream list add_watcher", function()
  local upstream_list = require "rspamd_upstream_list"

  test("table of events is accepted", function()
    local ups = upstream_list.create('127.0.0.1,127.0.0.2', 11333)
    assert_not_nil(ups)
    ups:add_watcher({'online', 'offline'}, function(what, up, cur_errors) end)
  end)

  test("string event is accepted", function()
    local ups = upstream_list.create('127.0.0.1,127.0.0.2', 11333)
    assert_not_nil(ups)
    ups:add_watcher('success', function(what, up, cur_errors) end)
  end)
end)
