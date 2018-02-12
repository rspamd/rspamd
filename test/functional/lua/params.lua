rspamd_config.TEST_RCPT = {
  callback = function(task)
    local l = {}
    local rcpts = task:get_recipients(1)
    if not rcpts then return end
    for _, r in ipairs(rcpts) do
      table.insert(l, r['addr'])
    end
    table.sort(l)
    local t = table.concat(l, ",")
    return true, t
  end
}

rspamd_config.TEST_HELO = {
  callback = function(task)
    local helo = task:get_helo()
    if not helo then return end
    return true, helo
  end
}

rspamd_config.TEST_HOSTNAME = {
  callback = function(task)
    local h = task:get_hostname()
    if not h then return end
    return true, h
  end
}

rspamd_config.TEST_SMTP_FROM = {
  callback = function(task)
    local f = task:get_from('smtp')
    if not (f and f[1] and f[1].addr) then return end
    return true, f[1].addr
  end
}

rspamd_config.TEST_MTA_TAG = {
  callback = function(task)
    local h = task:get_request_header('MTA-Tag')
    if not h then return end
    return true, tostring(h)
  end
}

rspamd_config.TEST_USER = {
  callback = function(task)
    local u = task:get_user()
    if not u then return end
    return true, u
  end
}

rspamd_config.TEST_QUEUEID = {
  callback = function(task)
    local q = task:get_queue_id()
    if not q then return end
    return true, q
  end
}

rspamd_config.TEST_IPADDR = {
  callback = function(task)
    local i = task:get_from_ip()
    if not (i and i:is_valid()) then return end
    return true, tostring(i)
  end
}

rspamd_config.FORCE_DEFER = {
  callback = function(task)
    local f = task:get_from('smtp')
    if not (f and f[1] and f[1].addr) then return end
    if f[1].addr == "defer@example.org" then
      task:set_pre_result('soft reject', 'Try much later')
      return true
    end
  end
}
