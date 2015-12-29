local util = require "rspamd_util"
local opts = {}
local known_attrs = {
  data = 1,
  example = 1,
  type = 1
}

--.USE "getopt"
--.USE "ansicolors"


local function maybe_print_color(key)
  if opts['color'] then
    return ansicolors.white .. key .. ansicolors.reset
  else
    return key
  end
end

local function print_help(key, value, tabs)
  print(string.format('%sConfiguration element: %s', tabs, maybe_print_color(key)))

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
    print_help(k, v, '')
    print('')
  end
end
