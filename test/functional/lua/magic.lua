rspamd_config.MAGIC_SYM = {
  callback = function(task)
    local parts = task:get_parts()

    for i,p in ipairs(parts) do
      local ext = p:get_detected_ext()

      if ext then
        task:insert_result('MAGIC_SYM_' .. ext:upper() .. '_' .. tostring(i), 1.0)
      end
    end
  end,
  type = 'callback'
}