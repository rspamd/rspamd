--[[
Copyright (c) 2018, Vsevolod Stakhov <vsevolod@highsecure.ru>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
]]--

local argparse = require "argparse"


-- Define command line options
local parser = argparse()
    :name "rspamadm grep"
    :description "Search for patterns in rspamd logs"
    :help_description_margin(30)
parser:mutex(
    parser:option "-s --string"
          :description('Plain string to search (case-insensitive)')
          :argname "<str>",
    parser:option "-p --pattern"
          :description('Pattern to search for (regex)')
          :argname "<re>"
)
parser:flag "-l --lua"
      :description('Use Lua patterns in string search')

parser:argument "input":args "*"
      :description('Process specified inputs')
      :default("stdin")
parser:flag "-S --sensitive"
      :description('Enable case-sensitivity in string search')
parser:flag "-o --orphans"
      :description('Print orphaned logs')
parser:flag "-P --partial"
      :description('Print partial logs')

local function handler(args)

  local rspamd_regexp = require 'rspamd_regexp'
  local res = parser:parse(args)

  if not res['string'] and not res['pattern'] then
    parser:error('string or pattern options must be specified')
  end

  if res['string'] and res['pattern'] then
    parser:error('string and pattern options are mutually exclusive')
  end

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
  if res['lua'] then
    plainm = false
  end
  local orphans = res['orphans']
  local search_str = res['string']
  local sensitive = res['sensitive']
  local partial = res['partial']
  if search_str and not sensitive then
    search_str = string.lower(search_str)
  end
  local inputs = res['input'] or {'stdin'}

  for _, n in ipairs(inputs) do
    local h, err
    if string.match(n, '%.xz$') then
      h, err = io.popen('xzcat ' .. n, 'r')
    elseif string.match(n, '%.bz2$') then
      h, err = io.popen('bzcat ' .. n, 'r')
    elseif string.match(n, '%.gz$') then
      h, err = io.popen('zcat ' .. n, 'r')
    elseif string.match(n, '%.zst$') then
      h, err = io.popen('zstdcat ' .. n, 'r')
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

return {
  handler = handler,
  description = parser._description,
  name = 'grep'
}