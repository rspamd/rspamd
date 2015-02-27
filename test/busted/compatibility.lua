return {
  getfenv = getfenv or function(f)
    f = (type(f) == 'function' and f or debug.getinfo(f + 1, 'f').func)
    local name, value
    local up = 0

    repeat
      up = up + 1
      name, value = debug.getupvalue(f, up)
    until name == '_ENV' or name == nil

    return value
  end,

  setfenv = setfenv or function(f, t)
    f = (type(f) == 'function' and f or debug.getinfo(f + 1, 'f').func)
    local name
    local up = 0

    repeat
      up = up + 1
      name = debug.getupvalue(f, up)
    until name == '_ENV' or name == nil

    if name then
      debug.upvaluejoin(f, up, function() return name end, 1)
      debug.setupvalue(f, up, t)
    end

    if f ~= 0 then return f end
  end,

  unpack = table.unpack or unpack,

  osexit = function(code, close)
    if close and _VERSION == 'Lua 5.1' then
      -- From Lua 5.1 manual:
      -- > The userdata itself is freed only in the next
      -- > garbage-collection cycle.
      -- Call collectgarbage() while collectgarbage('count')
      -- changes + 3 times, at least 3 times,
      -- at max 100 times (to prevent infinite loop).
      local times_const = 0
      for i = 1, 100 do
        local count_before = collectgarbage("count")
        collectgarbage()
        local count_after = collectgarbage("count")
        if count_after == count_before then
          times_const = times_const + 1
          if times_const > 3 then
            break
          end
        else
          times_const = 0
        end
      end
    end
    os.exit(code, close)
  end,
}
