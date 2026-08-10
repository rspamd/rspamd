--[[
Records what the fuzzy storage has actually received in the command extensions
so that the functional tests can assert on what the scanner has, or has not,
sent. Only check commands are recorded and the file always holds the last one.
]] --

local FUZZY_CHECK = 0

rspamd_config:add_on_load(function(_, _, worker)
  if not worker or worker:get_name() ~= 'fuzzy' then
    return
  end

  local tmpdir = os.getenv('RSPAMD_TMPDIR')

  if not tmpdir then
    return
  end

  local path = tmpdir .. '/fuzzy_extensions.log'

  worker:add_fuzzy_pre_handler(function(_, cmd, _, _, ext)
    if cmd ~= FUZZY_CHECK then
      return
    end

    local out = {}

    if ext.ip then
      table.insert(out, 'ip=' .. tostring(ext.ip))
    end

    if ext.domain then
      table.insert(out, 'domain=' .. ext.domain)
    end

    if ext.sender then
      for _, k in ipairs({ 'spf', 'dkim', 'dmarc', 'ptr', 'rcpts' }) do
        table.insert(out, string.format('%s=%s', k, ext.sender[k] or 'absent'))
      end

      table.insert(out, 'ptr_generic=' .. tostring(ext.sender.ptr_generic))
      table.insert(out, 'tls=' .. tostring(ext.sender.tls))
    end

    local f = io.open(path, 'w')

    if f then
      if #out == 0 then
        f:write('extensions=none\n')
      else
        f:write(table.concat(out, ' ') .. '\n')
      end

      f:close()
    end
  end)
end)
