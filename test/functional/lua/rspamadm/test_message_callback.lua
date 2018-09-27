function message_callback(task)
  local parts = task:get_text_parts()
  print("n parts = " .. tostring(#parts))
  return 1,2,4,6
end
