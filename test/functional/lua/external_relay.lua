rspamd_config:register_symbol({
  name = 'EXTERNAL_RELAY_TEST',
  score = 0.0,
  callback = function(task)
    local from_ip = string.format('IP=%s', task:get_from_ip() or 'NIL')
    local hostname = string.format('HOSTNAME=%s', task:get_hostname() or 'NIL')
    local helo = string.format('HELO=%s', task:get_helo() or 'NIL')
    return true, from_ip, hostname, helo
  end
})
