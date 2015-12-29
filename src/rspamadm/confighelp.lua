local util = require "rspamd_util"
local opts = {}
local known_attrs = {
  data = 1,
  example = 1,
  type = 1
}

--.USE "getopt"

local function print_help(key, value, tabs)
  print(string.format('%sOption: %s', tabs, key))

  if not opts['short'] then
    if value['data'] then
      print(string.format('%s\tDescription: %s', tabs, value['data']))
    end
    if value['type'] then
      print(string.format('%s\tType: %s', tabs, value['type']))
    end

    if not opts['no-examples'] and value['example'] then
      print(string.format('%s\tExample: %s', tabs, value['example']))
    end
  end
  print('')

  for k, v in pairs(value) do
    if not known_attrs[k] then
      -- We need to go deeper
      print_help(k, v, tabs .. '\t')
    end
  end
end

return function(args, res)
  opts = getopt(args, '')

  for k,v in pairs(res) do
    print_help(k, v, '');
  end
end
