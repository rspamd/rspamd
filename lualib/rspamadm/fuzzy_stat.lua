local rspamd_util = require "rspamd_util"
local lua_util = require "lua_util"
local opts = {}

local argparse = require "argparse"
local parser = argparse()
    :name "rspamadm control fuzzystat"
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
parser:option "--sort"
      :description "Sort order"
      :convert {
  checked = "checked",
  matched = "matched",
  errors = "errors",
  name = "name"
}

local function add_data(target, src)
  for k, v in pairs(src) do
    if type(v) == 'number' then
      if target[k] then
        target[k] = target[k] + v
      else
        target[k] = v
      end
    elseif k == 'ips' then
      if not target['ips'] then
        target['ips'] = {}
      end
      -- Iterate over IPs
      for ip, st in pairs(v) do
        if not target['ips'][ip] then
          target['ips'][ip] = {}
        end
        add_data(target['ips'][ip], st)
      end
    elseif k == 'flags' then
      if not target['flags'] then
        target['flags'] = {}
      end
      -- Iterate over Flags
      for flag, st in pairs(v) do
        if not target['flags'][flag] then
          target['flags'][flag] = {}
        end
        add_data(target['flags'][flag], st)
      end
    elseif k == 'keypair' then
      if type(v.extensions) == 'table' then
        if type(v.extensions.name) == 'string' then
          target.name = v.extensions.name
        end
        if type(v.extensions.email) == 'string' then
          target.email = v.extensions.email
        end
        if type(v.extensions.ratelimit) == 'table' then
          if not target.ratelimit then
            target.ratelimit = {}
          end
          -- Passed as {burst = x, rate = y}
          target.ratelimit.limit = v.extensions.ratelimit
        end
      end
    elseif k == 'ratelimit' then
      if not target.ratelimit then
        target.ratelimit = {}
      end
      -- Ratelimit is passed as {cur = count, last = time}
      target.ratelimit.cur = v
    end
  end
end

local function print_num(num)
  if num then
    if opts['n'] or opts['number'] then
      return tostring(num)
    else
      return rspamd_util.humanize_number(num)
    end
  else
    return 'na'
  end
end

local function print_stat(st, tabs)
  if st['checked'] then
    if st.checked_per_hour then
      print(string.format('%sChecked: %s (%s per hour in average)', tabs,
          print_num(st['checked']), print_num(st['checked_per_hour'])))
    else
      print(string.format('%sChecked: %s', tabs, print_num(st['checked'])))
    end
  end
  if st['matched'] then
    if st.checked and st.checked > 0 and st.checked <= st.matched then
      local percentage = st.matched / st.checked * 100.0
      if st.matched_per_hour then
        print(string.format('%sMatched: %s - %s percent (%s per hour in average)', tabs,
            print_num(st['matched']), percentage, print_num(st['matched_per_hour'])))
      else
        print(string.format('%sMatched: %s - %s percent', tabs, print_num(st['matched']), percentage))
      end
    else
      if st.matched_per_hour then
        print(string.format('%sMatched: %s (%s per hour in average)', tabs,
            print_num(st['matched']), print_num(st['matched_per_hour'])))
      else
        print(string.format('%sMatched: %s', tabs, print_num(st['matched'])))
      end
    end
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
local function sort_hash_table(tbl, sort_opts, key_key)
  local res = {}
  for k, v in pairs(tbl) do
    table.insert(res, { [key_key] = k, data = v })
  end

  local function sort_order(elt)
    local key = 'checked'
    local sort_res = 0

    if sort_opts['sort'] then
      if sort_opts['sort'] == 'matched' then
        key = 'matched'
      elseif sort_opts['sort'] == 'errors' then
        key = 'errors'
      elseif sort_opts['sort'] == 'name' then
        return elt[key_key]
      end
    end

    if elt.data[key] then
      sort_res = elt.data[key]
    end

    return sort_res
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
      dst = { dst }
    elseif type(dst) == 'nil' then
      dst = {}
    end

    for i, v in ipairs(src) do
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
    for i, num in ipairs(r) do
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
    for _, pr in pairs(wrk) do
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
          for k, v in pairs(pr['data']) do
            if k ~= 'keys' and k ~= 'errors_ips' then
              res_db[k] = add_result(res_db[k], v, k)
            elseif k == 'errors_ips' then
              -- Errors ips
              if not res_db['errors_ips'] then
                res_db['errors_ips'] = {}
              end
              for ip, nerrors in pairs(v) do
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
            for k, elts in pairs(pr['data']['keys']) do
              -- keys cycle
              if not res_keys[k] then
                res_keys[k] = {}
              end

              add_data(res_keys[k], elts)

              if elts['ips'] then
                for ip, v in pairs(elts['ips']) do
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
  for db, st in pairs(res_databases) do
    print(string.format('Statistics for storage %s', db))

    for k, v in pairs(st) do
      if k ~= 'keys' and k ~= 'errors_ips' then
        print(string.format('%s: %s', k, print_result(v)))
      end
    end
    print('')

    local res_keys = st['keys']
    if res_keys and not opts['no_keys'] and not opts['short'] then
      print('Keys statistics:')
      -- Convert into an array to allow sorting
      local sorted_keys = sort_hash_table(res_keys, opts, 'key')

      for _, key in ipairs(sorted_keys) do
        local key_stat = key.data
        if key_stat.name then
          print(string.format('Key id: %s, name: %s (email: %s)', key.key, key_stat.name,
              key_stat.email or 'unknown'))
        else
          print(string.format('Key id: %s', key.key))
        end

        print_stat(key_stat, '\t')

        if key_stat['ips'] and not opts['no_ips'] then
          print('')
          print('\tIPs stat:')
          local sorted_ips = sort_hash_table(key_stat['ips'], opts, 'ip')

          for _, v in ipairs(sorted_ips) do
            print(string.format('\t%s', v['ip']))
            print_stat(v['data'], '\t\t')
            print('')
          end
        end

        if key_stat.flags then
          print('')
          print('\tFlags stat:')
          for flag, v in pairs(key_stat.flags) do
            print(string.format('\t[%s]:', flag))
            -- Remove irrelevant fields
            v.checked = nil
            print_stat(v, '\t\t')
            print('')
          end
        end

        if key_stat.ratelimit then
          print('')
          print('\tRatelimit stat:')
          print(string.format('\tLimit: %s (%s leak rate)',
              print_num(key_stat.ratelimit.limit.burst), print_num(key_stat.ratelimit.limit.rate)))
          print(string.format('\tCurrent: %s (%s last)',
              print_num(key_stat.ratelimit.cur), os.date('%c', key_stat.ratelimit.last)))
          print('')
        end

        print('')
      end
    end
    if st['errors_ips'] and not opts['no_ips'] and not opts['short'] then
      print('')
      print('Errors IPs statistics:')
      local ip_stat = st['errors_ips']
      local ips = lua_util.keys(ip_stat)
      -- Reverse sort by number of errors
      table.sort(ips, function(a, b)
        return ip_stat[a] > ip_stat[b]
      end)
      for _, ip in ipairs(ips) do
        print(string.format('%s: %s', ip, print_result(ip_stat[ip])))
      end
      print('')
    end
  end

  if not opts['no_ips'] and not opts['short'] then
    print('')
    print('IPs statistics:')

    local sorted_ips = sort_hash_table(res_ips, opts, 'ip')
    for _, v in ipairs(sorted_ips) do
      print(string.format('%s', v['ip']))
      print_stat(v['data'], '\t')
      print('')
    end
  end
end

