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

local function sort_values(tbl, opts)
  local res = {}
  for k, v in pairs(tbl) do
    table.insert(res, { key = k, value = v })
  end

  -- Sort order
  local order = {
    options = 1,
    dns = 2,
    upstream = 3,
    logging = 4,
    metric = 5,
    composite = 6,
    classifier = 7,
    modules = 8,
    lua = 9,
    worker = 10,
    workers = 11,
  }

  table.sort(res, function(a, b)
    local oa = order[a['key']]
    local ob = order[b['key']]

    if oa and ob then
      return oa < ob
    elseif oa then
      return -1 < 0
    elseif ob then
      return 1 < 0
    else
      return a['key'] < b['key']
    end

  end)

  return res
end

local function print_help(key, value, tabs)
  print(string.format('%sConfiguration element: %s', tabs, maybe_print_color(key)))

  if not opts['short'] then
    if value['data'] then
      print(string.format('%s\tDescription: %s', tabs, value['data']))
    end
    if not opts['no-examples'] and value['example'] then
      print(string.format('%s\tExample: %s', tabs, value['example']))
    end
    if value['type'] then
      print(string.format('%s\tType: %s', tabs, value['type']))
      if value['type'] == 'object' then
        print('')
      end
    end
  end

  local sorted = sort_values(value)
  for i, v in ipairs(sorted) do
    if not known_attrs[v['key']] then
      -- We need to go deeper
      print_help(v['key'], v['value'], tabs .. '\t')
    end
  end
end

return function(args, res)
  opts = getopt(args, '')

  local sorted = sort_values(res)

  for i,v in ipairs(sorted) do
    print_help(v['key'], v['value'], '')
    print('')
  end
end
