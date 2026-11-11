-- Keeps every scan pending for longer than the proxy upstream timeout in
-- milter_slow_upstream.conf, so that the proxy gives up on the master request
-- asynchronously, from the backend error handler.
rspamd_config:register_symbol({
  name = 'SLOW_SCAN',
  score = 0.0,
  callback = function(task)
    task:add_timer(3.0, function() end)
  end
})
