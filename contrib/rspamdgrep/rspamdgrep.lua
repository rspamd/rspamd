local rspamd_regexp = require 'rspamd_regexp'
local rspamd_logger = require 'rspamd_logger'

local BUF_SIZE = 10240
local E = {}

local buffer = {}
local matches = {}
local count = 0

if type(arg) ~= 'table' then
  io.stderr:write('No files specified for search\n')
  os.exit(1)
end

local pattern = table.remove(arg, 1)
local re = rspamd_regexp.create(pattern)
if not re then
  io.stderr:write("Couldn't compile regex: " .. pattern .. '\n')
  os.exit(1)
end

for _, n in ipairs(arg) do
  local h, err
  if string.match(n, '%.xz$') then
    h, err = io.popen('xzcat ' .. n, 'r')
  elseif string.match(n, '%.bz2$') then
    h, err = io.popen('bzcat ' .. n, 'r')
  elseif string.match(n, '%.gz$') then
    h, err = io.popen('zcat ' .. n, 'r')
  elseif string.match(n, '%.log$') then
    h, err = io.open(n, 'r')
  else
    io.stderr:write("Couldn't identify log format: " .. n .. '\n')
  end
  if not h then
    if err then
      io.stderr:write("Couldn't open file (" .. n .. '): ' .. err .. '\n')
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
          count = count + 1
          if count >= BUF_SIZE then
            local k = next(buffer)
            buffer[k] = nil
            count = count - 1
          end
        end
      end
      if re:match(line) then
        if not hash then
          hash = 'orphaned'
        end
        if matches[hash] then
          table.insert(matches[hash], line)
        else
          local old = buffer[hash] or E
          table.insert(old, line)
          matches[hash] = old
        end
      end
      local is_end = string.match(line, '^%d+-%d+-%d+ %d+:%d+:%d+ #%d+%(%a+%) <%x+>; task; rspamd_protocol_http_reply:')
      if is_end then
        buffer[hash] = nil
      end
    end
  end
end

for k, v in pairs(matches) do
  for _, vv in ipairs(v) do
    print(vv)
  end
  print()
end
