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

local function print_stat(st, tabs)
  if st['checked'] then
    print(string.format('%sChecked: %8d', tabs, tonumber(st['checked'])))
  end
  if st['matched'] then
    print(string.format('%sMatched: %8d', tabs, tonumber(st['matched'])))
  end
  if st['errors'] then
    print(string.format('%sErrors: %9d', tabs, tonumber(st['errors'])))
  end
  if st['added'] then
    print(string.format('%sAdded: %10d', tabs, tonumber(st['added'])))
  end
  if st['deleted'] then
    print(string.format('%sAdded: %10d', tabs, tonumber(st['deleted'])))
  end
end

-- Sort by checked
local function sort_ips(tbl, opts)
  local res = {}
  for k,v in pairs(tbl) do
    table.insert(res, {ip = k, data = v})
  end

  local function sort_order(elt)
    local key = 'checked'
    local res = 0

    if opts['sort'] then
      if opts['sort'] == 'matched' then
        key = 'matched'
      elseif opts['sort'] == 'errors' then
        key = 'errors'
      elseif opts['sort'] == 'ip' then
        return elt['ip']
      end
    end

    if elt['data'][key] then
      res = elt['data'][key]
    end

    return res
  end

  table.sort(res, function(a, b)
    return sort_order(a) > sort_order(b)
  end)

  return res
end

local function add_result(dst, src)
  if type(src) == 'table' then
    if type(dst) == 'number' then
      -- Convert dst to table
      dst = {dst}
    elseif type(dst) == 'nil' then
      dst = {}
    end

    for i,v in ipairs(src) do
      if dst[i] then
        dst[i] = dst[i] + v
      else
        dst[i] = v
      end
    end
  else
    if type(dst) == 'table' then
      dst[1] = dst[1] + src
    else
      if dst then
        dst = dst + src
      else
        dst = src
      end
    end
  end

  return dst
end

local function print_result(r)
  if type(r) == 'table' then
    return table.concat(r, ', ')
  end

  return tostring(r)
end

--.USE "getopt"

return function(args, res)
  local res_ips = {}
  local res_databases = {}
  local wrk = res['workers']
  local opts = getopt(args, '')

  if wrk then
    for i,pr in pairs(wrk) do
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
            if k ~= 'keys' then
              res_db[k] = add_result(res_databases[k], v)
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
      if k ~= 'keys' then
        print(string.format('%s: %s', k, print_result(v)))
      end
    end
    print('')

    local res_keys = st['keys']
    if res_keys and not opts['no-keys'] and not opts['short'] then
      print('Keys statistics:')
      for k,st in pairs(res_keys) do
        print(string.format('Key id: %s', k))
        print_stat(st, '\t')

        if st['ips'] and not opts['no-ips'] then
          print('')
          print('\tIPs stat:')
          local sorted_ips = sort_ips(st['ips'], opts)

          for i,v in ipairs(sorted_ips) do
            print(string.format('\t%s', v['ip']))
            print_stat(v['data'], '\t\t')
            print('')
          end
        end

        print('')
      end
    end

  end

  if not opts['no-ips'] and not opts['short'] then
    print('')
    print('IPs statistics:')

    local sorted_ips = sort_ips(res_ips, opts)
    for i, v in ipairs(sorted_ips) do
      print(string.format('%s', v['ip']))
      print_stat(v['data'], '\t')
      print('')
    end
  end
end

