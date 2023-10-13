rspamd_config.SINGLE_SHORT_PART = {
  callback = function(task)
    local parts = task:get_parts()
    if #parts ~= 1 then return end
    local text = parts[1]:get_text()
    if not text then return end
    if text:get_length() >= 64 then return end
    return true
  end,
  score = 0.0,
}
