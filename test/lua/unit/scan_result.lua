context('terminal export metadata', function()
  local ucl = require 'ucl'
  local metadata = require('lua_scan_result').get_terminal_metadata

  test('preserves unavailable content without reading a message', function()
    local task = {
      get_uuid = function() return 'task-uuid' end,
      get_terminal_event = function()
        return {
          event_id = 'transaction', decision_stage = 'data',
          action = 'reject', policy = 'sender', reason = 'blocked sender',
          sender = 'sender@example.org', recipients = { 'rcpt@example.org' },
          partial_score = 3, early_time = 0.125,
          has_headers = false, has_body = false, has_mime = false,
        }
      end,
    }
    setmetatable(task, { __index = function(_, name) error('unexpected task accessor: ' .. name) end })
    local result = metadata(task)
    assert_equal(result.from, 'sender@example.org')
    assert_equal(result.uuid, 'task-uuid')
    assert_equal(result.event_id, 'transaction')
    assert_equal(result.score, 3)
    assert_equal(result.scan_time, 125)
    assert_equal(result.size, ucl.null)
    assert_equal(result.subject, ucl.null)
    assert_equal(result.header_from, ucl.null)
    assert_false(result.has_body)
    assert_nil(result.message)
  end)

  test('ordinary tasks have no terminal metadata', function()
    assert_nil(metadata({ get_terminal_event = function() return nil end }))
  end)
end)
