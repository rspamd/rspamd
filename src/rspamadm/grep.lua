return function(_, res)

  local rspamd_regexp = require 'rspamd_regexp'

  local buffer = {}
  local matches = {}

  local pattern = res['pattern']
  local re
  if pattern then
    re = rspamd_regexp.create(pattern)
    if not re then
      io.stderr:write("Couldn't compile regex: " .. pattern .. '\n')
      os.exit(1)
    end
  end

  local plainm = true
  if res['luapat'] then
    plainm = false
  end
  local orphans = res['orphans']
  local search_str = res['string']
  local sensitive = res['sensitive']
  local partial = res['partial']
  if search_str and not sensitive then
    search_str = string.lower(search_str)
  end
  local inputs = res['inputs']

  for _, n in ipairs(inputs) do
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
        io.stderr:write("Couldn't open file (" .. n .. '): no error\n')
      end
    else
      for line in h:lines() do
        local hash = string.match(line, '<(%x+)>')
        local already_matching = false
        if hash then
          if matches[hash] then
            table.insert(matches[hash], line)
            already_matching = true
          else
            if buffer[hash] then
              table.insert(buffer[hash], line)
            else
              buffer[hash] = {line}
            end
          end
        end
        local ismatch = false
        if re then
          ismatch = re:match(line)
        elseif sensitive and search_str then
          ismatch = string.find(line, search_str, 1, plainm)
        elseif search_str then
          local lwr = string.lower(line)
          ismatch = string.find(lwr, search_str, 1, plainm)
        end
        if ismatch then
          if not hash then
            if orphans then
              print('*** orphaned ***')
              print(line)
              print()
            end
          elseif not already_matching then
            matches[hash] = buffer[hash]
          end
        end
        local is_end = string.match(line, '<%x+>; task; rspamd_protocol_http_reply:')
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
      if partial then
        for k, v in pairs(matches) do
          print('*** partial ***')
          for _, vv in ipairs(v) do
            print(vv)
          end
          print()
          matches[k] = nil
        end
      else
        matches = {}
      end
    end
  end
end
