local rspamd_regexp = require 'rspamd_regexp'

local E = {}

local buffer = {}
local matches = {}

if type(arg) ~= 'table' then
  io.stderr:write('Syntax: rspamdgrep <pattern> [sources]\n')
  os.exit(1)
end

local pattern = table.remove(arg, 1)
local re = rspamd_regexp.create(pattern)
if not re then
  io.stderr:write("Couldn't compile regex: " .. pattern .. '\n')
  os.exit(1)
end

if not arg[1] then
  arg = {'stdin'}
end

for _, n in ipairs(arg) do
  local h, err
  if string.match(n, '%.xz$') then
    h, err = io.popen('xzcat ' .. n, 'r')
  elseif string.match(n, '%.bz2$') then
    h, err = io.popen('bzcat ' .. n, 'r')
  elseif string.match(n, '%.gz$') then
    h, err = io.popen('zcat ' .. n, 'r')
  elseif n == 'stdin' then
    h = io.input()
  else
    h, err = io.open(n, 'r')
  end
  if not h then
    if err then
      io.stderr:write("Couldn't open file (" .. n .. '): ' .. err .. '\n')
    else
      io.stderr:write("Couldn't open file (" .. n .. '): no error')
    end
  else
    for line in h:lines() do
      local hash = string.match(line, '^%d+-%d+-%d+ %d+:%d+:%d+ #%d+%(%a+%) <(%x+)>')
      if hash then
        if matches[hash] then
          table.insert(matches[hash], line)
        else
          if buffer[hash] then
            table.insert(buffer[hash], line)
          else
            buffer[hash] = {line}
          end
        end
      end
      if re:match(line) then
        if not hash then
          print('*** orphaned ***')
          print(line)
          print()
        else
          if matches[hash] then
            table.insert(matches[hash], line)
          else
            local old = buffer[hash] or E
            table.insert(old, line)
            matches[hash] = old
          end
        end
      end
      local is_end = string.match(line, '^%d+-%d+-%d+ %d+:%d+:%d+ #%d+%(%a+%) <%x+>; task; rspamd_protocol_http_reply:')
      if is_end then
        buffer[hash] = nil
        if matches[hash] then
          for _, v in ipairs(matches[hash]) do
            print(v)
          end
          print()
          matches[hash] = nil
        end
      end
    end
  end
end
for _, v in pairs(matches) do
  print('*** partial ***')
  for _, vv in ipairs(v) do
    print(vv)
  end
  print()
end
