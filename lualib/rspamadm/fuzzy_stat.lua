local util = require "rspamd_util"
local opts = {}

local argparse = require "argparse"
local parser = argparse()
    :name "rspamadm confighelp"
    :description "Shows help for the specified configuration options"
    :help_description_margin(32)
parser:flag "--no-ips"
      :description "No IPs stats"
parser:flag "--no-keys"
      :description "No keys stats"
parser:flag "--short"
      :description "Short output mode"
parser:flag "-n --number"
      :description "Disable numbers humanization"
parser:option "-s --sort"
      :description "Sort order"
      :convert {
        matched = "matched",
        errors = "errors",
        ip = "ip"
      }

local function add_data(target, src)
  for k,v in pairs(src) do
    if k ~= 'ips' then
      if target[k] then
        target[k] = target[k] + v
      else
        target[k] = v
      end
    else
      if not target['ips'] then target['ips'] = {} end
      -- Iterate over IPs
      for ip,st in pairs(v) do
        if not target['ips'][ip] then target['ips'][ip] = {} end
        add_data(target['ips'][ip], st)
      end
    end
  end
end

local function print_num(num)
  if opts['n'] or opts['number'] then
    return tostring(num)
  else
    return util.humanize_number(num)
  end
end

local function print_stat(st, tabs)
  if st['checked'] then
    print(string.format('%sChecked: %s', tabs, print_num(st['checked'])))
  end
  if st['matched'] then
    print(string.format('%sMatched: %s', tabs, print_num(st['matched'])))
  end
  if st['errors'] then
    print(string.format('%sErrors: %s', tabs, print_num(st['errors'])))
  end
  if st['added'] then
    print(string.format('%sAdded: %s', tabs, print_num(st['added'])))
  end
  if st['deleted'] then
    print(string.format('%sDeleted: %s', tabs, print_num(st['deleted'])))
  end
end

-- Sort by checked
local function sort_ips(tbl, _opts)
  local res = {}
  for k,v in pairs(tbl) do
    table.insert(res, {ip = k, data = v})
  end

  local function sort_order(elt)
    local key = 'checked'
    local _res = 0

    if _opts['sort'] then
      if _opts['sort'] == 'matched' then
        key = 'matched'
      elseif _opts['sort'] == 'errors' then
        key = 'errors'
      elseif _opts['sort'] == 'ip' then
        return elt['ip']
      end
    end

    if elt['data'][key] then
      _res = elt['data'][key]
    end

    return _res
  end

  table.sort(res, function(a, b)
    return sort_order(a) > sort_order(b)
  end)

  return res
end

local function add_result(dst, src, k)
  if type(src) == 'table' then
    if type(dst) == 'number' then
      -- Convert dst to table
      dst = {dst}
    elseif type(dst) == 'nil' then
      dst = {}
    end

    for i,v in ipairs(src) do
      if dst[i] and k ~= 'fuzzy_stored' then
        dst[i] = dst[i] + v
      else
        dst[i] = v
      end
    end
  else
    if type(dst) == 'table' then
      if k ~= 'fuzzy_stored' then
        dst[1] = dst[1] + src
      else
        dst[1] = src
      end
    else
      if dst and k ~= 'fuzzy_stored' then
        dst = dst + src
      else
        dst = src
      end
    end
  end

  return dst
end

local function print_result(r)
  local function num_to_epoch(num)
    if num == 1 then
      return 'v0.6'
    elseif num == 2 then
      return 'v0.8'
    elseif num == 3 then
      return 'v0.9'
    elseif num == 4 then
      return 'v1.0+'
    elseif num == 5 then
      return 'v1.7+'
    end
    return '???'
  end
  if type(r) == 'table' then
    local res = {}
    for i,num in ipairs(r) do
      res[i] = string.format('(%s: %s)', num_to_epoch(i), print_num(num))
    end

    return table.concat(res, ', ')
  end

  return print_num(r)
end

return function(args, res)
  local res_ips = {}
  local res_databases = {}
  local wrk = res['workers']
  opts = parser:parse(args)

  if wrk then
    for _,pr in pairs(wrk) do
      -- processes cycle
      if pr['data'] then
        local id = pr['id']

        if id then
          local res_db = res_databases[id]
          if not res_db then
            res_db = {
              keys = {}
            }
            res_databases[id] = res_db
          end

          -- General stats
          for k,v in pairs(pr['data']) do
            if k ~= 'keys' and k ~= 'errors_ips' then
              res_db[k] = add_result(res_db[k], v, k)
            elseif k == 'errors_ips' then
              -- Errors ips
              if not res_db['errors_ips'] then
                res_db['errors_ips'] = {}
              end
              for ip,nerrors in pairs(v) do
                if not res_db['errors_ips'][ip] then
                  res_db['errors_ips'][ip] = nerrors
                else
                  res_db['errors_ips'][ip] = nerrors + res_db['errors_ips'][ip]
                end
              end
            end
          end

          if pr['data']['keys'] then
            local res_keys = res_db['keys']
            if not res_keys then
              res_keys = {}
              res_db['keys'] = res_keys
            end
            -- Go through keys in input
            for k,elts in pairs(pr['data']['keys']) do
              -- keys cycle
              if not res_keys[k] then
                res_keys[k] = {}
              end

              add_data(res_keys[k], elts)

              if elts['ips'] then
                for ip,v in pairs(elts['ips']) do
                  if not res_ips[ip] then
                    res_ips[ip] = {}
                  end
                  add_data(res_ips[ip], v)
                end
              end
            end
          end
        end
      end
    end
  end

  -- General stats
  for db,st in pairs(res_databases) do
    print(string.format('Statistics for storage %s', db))

    for k,v in pairs(st) do
      if k ~= 'keys' and k ~= 'errors_ips' then
        print(string.format('%s: %s', k, print_result(v)))
      end
    end
    print('')

    local res_keys = st['keys']
    if res_keys and not opts['no-keys'] and not opts['short'] then
      print('Keys statistics:')
      for k,_st in pairs(res_keys) do
        print(string.format('Key id: %s', k))
        print_stat(_st, '\t')

        if _st['ips'] and not opts['no-ips'] then
          print('')
          print('\tIPs stat:')
          local sorted_ips = sort_ips(_st['ips'], opts)

          for _,v in ipairs(sorted_ips) do
            print(string.format('\t%s', v['ip']))
            print_stat(v['data'], '\t\t')
            print('')
          end
        end

        print('')
      end
    end
    if st['errors_ips'] and not opts['no-ips'] and not opts['short'] then
      print('')
      print('Errors IPs statistics:')
      table.sort(st['errors_ips'], function(a, b)
        return a > b
      end)
      for i, v in pairs(st['errors_ips']) do
        print(string.format('%s: %s', i, print_result(v)))
      end
      print('')
    end
  end

  if not opts['no-ips'] and not opts['short'] then
    print('')
    print('IPs statistics:')

    local sorted_ips = sort_ips(res_ips, opts)
    for _, v in ipairs(sorted_ips) do
      print(string.format('%s', v['ip']))
      print_stat(v['data'], '\t')
      print('')
    end
  end
end

