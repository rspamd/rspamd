-- Regression test for the asynchronous proxy milter error path.
--
-- In milter_slow_upstream.conf every master request times out, and the retry
-- cannot select another upstream. The proxy has to answer each message with
-- exactly one TEMPFAIL from the backend error handler and keep the milter
-- connection usable. Previously the session was released from that callback,
-- which freed the milter session and dropped the queued reply, or touched the
-- freed proxy session when proxy_send_master_message() had already released
-- it.

print('Slow upstream must yield one TEMPFAIL per message on a live connection')

dofile './lib.lua'
dofile './data.lua'

local function expect_tempfail(tag)
  local rc = mt.getreply(conn)
  if rc ~= SMFIR_TEMPFAIL then
    error(string.format('%s: expected SMFIR_TEMPFAIL (%d), got %s',
                        tag, SMFIR_TEMPFAIL, tostring(rc)))
  end
  print(string.format('%s: got SMFIR_TEMPFAIL', tag))
end

-- Two transactions on the same connection: the first reply must be the only
-- one for the first message, and the transport must survive it.
setup()
send_message(innocuous_msg, innocuous_hdrs, 'slow-upstream-1',
             'sender@example.org', {'rcpt@example.org'})
expect_tempfail('first message')
send_message(innocuous_msg, innocuous_hdrs, 'slow-upstream-2',
             'sender@example.org', {'rcpt@example.org'})
expect_tempfail('second message on the same connection')
teardown()

-- A fresh connection proves the proxy worker is still accepting.
setup()
send_message(innocuous_msg, innocuous_hdrs, 'slow-upstream-3',
             'sender@example.org', {'rcpt@example.org'})
expect_tempfail('message on a new connection')
teardown()

print('All messages got exactly one TEMPFAIL; proxy worker survived')
