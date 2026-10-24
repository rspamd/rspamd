-- Regression test for the proxy milter error path.
--
-- The proxy in milter_dead_upstream.conf has no default upstream, so
-- proxy_send_master_message() cannot find a backend and takes its error path
-- on every message. That is the same err: block reached in production when
-- every upstream is in backoff ("cannot select upstream"). Before the fix that
-- error path dropped the last reference to the proxy session, whose destructor
-- freed the milter session and closed the socket while the caller and the
-- milter library were still using it. The result was a use-after-free: the
-- proxy worker either segfaulted or stopped heart-beating/accepting
-- (CLOSE_WAIT backlog).
--
-- After the fix the MTA must receive TEMPFAIL and the worker must stay alive
-- for a second, independent transaction.

print('Dead upstream must yield TEMPFAIL and must not kill the proxy worker')

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

-- First message exercises the failing error path; the second one proves the
-- milter connection is still usable after the TEMPFAIL.
setup()
send_message(innocuous_msg, innocuous_hdrs, 'dead-upstream-1',
             'sender@example.org', {'rcpt@example.org'})
expect_tempfail('first message')
send_message(innocuous_msg, innocuous_hdrs, 'dead-upstream-1b',
             'sender@example.org', {'rcpt@example.org'})
expect_tempfail('second message on the same connection')
teardown()

-- Second message on a fresh connection proves the proxy worker is still
-- accepting and processing milter connections after the error.
setup()
send_message(innocuous_msg, innocuous_hdrs, 'dead-upstream-2',
             'sender@example.org', {'rcpt@example.org'})
expect_tempfail('second message')
teardown()

print('Both messages got TEMPFAIL; proxy worker survived')
