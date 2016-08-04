rspamd_config:register_symbol({
  name = 'TEST_RCPT',
  score = 1.0,
  callback = function(task)
    local l = {}
    local rcpts = task:get_recipients(1)
    for _, r in ipairs(rcpts) do
      table.insert(l, r['addr'])
    end
    table.sort(l)
    local t = table.concat(l, ",")
    return true, t
  end
})
