--[[
Copyright (c) 2011-2015, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

if confighelp then
  return
end

-- This plugin implements user dynamic settings
-- Settings documentation can be found here:
-- https://rspamd.com/doc/configuration/settings.html

local rspamd_logger = require "rspamd_logger"
local lua_maps = require "lua_maps"
local lua_util = require "lua_util"
local rspamd_ip = require "rspamd_ip"
local rspamd_regexp = require "rspamd_regexp"
local lua_selectors = require "lua_selectors"
local lua_settings = require "lua_settings"
local ucl = require "ucl"
local fun = require "fun"
local rspamd_mempool = require "rspamd_mempool"

local redis_params

local settings = {}
local N = "settings"
local settings_initialized = false
local max_pri = 0
local module_sym_id -- Main module symbol

local function apply_settings(task, to_apply, id, name)
  local cached_name = task:cache_get('settings_name')
  if cached_name then
    local cached_settings = task:cache_get('settings')
    rspamd_logger.warnx(task, "cannot apply settings rule %s (id=%s):" ..
        " settings has been already applied by rule %s (id=%s)",
        name, id, cached_name, cached_settings.id)
    return false
  end

  task:set_settings(to_apply)
  task:cache_set('settings', to_apply)
  task:cache_set('settings_name', name or 'unknown')

  if id then
    task:set_settings_id(id)
  end

  if to_apply['add_headers'] or to_apply['remove_headers'] then
    local rep = {
      add_headers = to_apply['add_headers'] or {},
      remove_headers = to_apply['remove_headers'] or {},
    }
    task:set_rmilter_reply(rep)
  end

  if to_apply.flags and type(to_apply.flags) == 'table' then
    for _,fl in ipairs(to_apply.flags) do
      task:set_flag(fl)
    end
  end

  if to_apply.symbols then
    -- Add symbols, specified in the settings
    if #to_apply.symbols > 0 then
      -- Array like symbols
      for _,val in ipairs(to_apply.symbols) do
        task:insert_result(val, 1.0)
      end
    else
      -- Object like symbols
      for k,v in pairs(to_apply.symbols) do
        if type(v) == 'table' then
          task:insert_result(k, v.score or 1.0, v.options or {})
        elseif tonumber(v) then
          task:insert_result(k, tonumber(v))
        end
      end
    end
  end

  if to_apply.subject then
    task:set_metric_subject(to_apply.subject)
  end

  -- E.g.
  -- messages = { smtp_message = "5.3.1 Go away" }
  if to_apply.messages and type(to_apply.messages) == 'table' then
    fun.each(function(category, message)
      task:append_message(message, category)
    end, to_apply.messages)
  end

  return true
end

-- Checks for overridden settings within query params and returns 3 values:
-- * Apply element
-- * Settings ID element if found
-- * Priority of the settings according to the place where it is found
--
-- If no override has been found, it returns `false`
local function check_query_settings(task)
  -- Try 'settings' attribute
  local settings_id = task:get_settings_id()
  local query_set = task:get_request_header('settings')
  if query_set then

    local parser = ucl.parser()
    local res,err = parser:parse_string(tostring(query_set))
    if res then
      if settings_id then
        rspamd_logger.warnx(task, "both settings-id '%s' and settings headers are presented, ignore settings-id; ",
            tostring(settings_id))
      end
      local settings_obj = parser:get_object()

      -- Treat as low priority
      return settings_obj,nil,1
    else
      rspamd_logger.errx(task, 'Parse error: %s', err)
    end
  end

  local query_maxscore = task:get_request_header('maxscore')
  local nset

  if query_maxscore then
    if settings_id then
      rspamd_logger.infox(task, "both settings id '%s' and maxscore '%s' headers are presented, merge them; " ..
        "settings id has priority",
        tostring(settings_id), tostring(query_maxscore))
    end
    -- We have score limits redefined by request
    local ms = tonumber(tostring(query_maxscore))
    if ms then
      nset = {
        actions = {
          reject = ms
        }
      }

      local query_softscore = task:get_request_header('softscore')
      if query_softscore then
        local ss = tonumber(tostring(query_softscore))
        nset.actions['add header'] = ss
      end

      if not settings_id then
        rspamd_logger.infox(task, 'apply maxscore = %s', nset.actions)
        -- Maxscore is low priority
        return nset, nil, 1
      end
    end
  end

  if settings_id and settings_initialized then
    local cached = lua_settings.settings_by_id(settings_id)

    if cached then
      local elt = cached.settings
      if elt['whitelist'] then
        elt['apply'] = {whitelist = true}
      end

      if elt.apply then
        if nset then
          elt.apply = lua_util.override_defaults(nset, elt.apply)
        end
        return elt.apply, cached, cached.priority or 1
      end
    else
      rspamd_logger.warnx(task, 'no settings id "%s" has been found', settings_id)
      if nset then
        rspamd_logger.infox(task, 'apply maxscore = %s', nset.actions)
        return nset, nil, 1
      end
    end
  else
    if nset then
      rspamd_logger.infox(task, 'apply maxscore = %s', nset.actions)
      return nset, nil, 1
    end
  end

  return false
end

local function check_addr_setting(expected, addr)
  local function check_specific_addr(elt)
    if expected.name then
      if lua_maps.rspamd_maybe_check_map(expected.name, elt.addr) then
        return true
      end
    end
    if expected.user then
      if lua_maps.rspamd_maybe_check_map(expected.user, elt.user) then
        return true
      end
    end
    if expected.domain and elt.domain then
      if lua_maps.rspamd_maybe_check_map(expected.domain, elt.domain) then
        return true
      end
    end
    if expected.regexp then
      if expected.regexp:match(elt.addr) then
        return true
      end
    end
    return false
  end

  for _, e in ipairs(addr) do
    if check_specific_addr(e) then
      return true
    end
  end

  return false
end

local function check_string_setting(expected, str)
  if expected.regexp then
    if expected.regexp:match(str) then
      return true
    end
  elseif expected.check then
    if lua_maps.rspamd_maybe_check_map(expected.check, str) then
      return true
    end
  end
  return false
end

local function check_ip_setting(expected, ip)
  if not expected[2] then
    if lua_maps.rspamd_maybe_check_map(expected[1], ip:to_string()) then
      return true
    end
  else
    if expected[2] ~= 0 then
      local nip = ip:apply_mask(expected[2])
      if nip and nip:to_string() == expected[1]:to_string() then
        return true
      end
    elseif ip:to_string() == expected[1]:to_string() then
      return true
    end
  end

  return false
end

local function check_map_setting(map, input)
  return map:get_key(input)
end

local function priority_to_string(pri)
  if pri then
    if pri >= 3 then
      return "high"
    elseif pri >= 2 then
      return "medium"
    end
  end

  return "low"
end

-- Check limit for a task
local function check_settings(task)
  local function check_specific_setting(rule, matched)
    local res = false

    local function process_atom(atom)
      local elt = rule.checks[atom]

      if elt then
        local input = elt.extract(task)
        if not input then return false end

        if elt.check(input) then
          matched[#matched + 1] = atom
          return 1.0
        end
      else
        rspamd_logger.errx(task, 'error in settings: check %s is not defined!', atom)
      end

      return 0
    end

    res = rule.expression and rule.expression:process(process_atom)

    if res and res > 0 then
      if rule['whitelist'] then
        rule['apply'] = {whitelist = true}
      end

      return rule
    end

    return nil
  end

  -- Check if we have override as query argument
  local query_apply,id_elt,priority = check_query_settings(task)

  local function maybe_apply_query_settings()
    if query_apply then
      if id_elt then
        apply_settings(task, query_apply, id_elt.id, id_elt.name)
        rspamd_logger.infox(task, "applied settings id %s(%s); priority %s",
            id_elt.name, id_elt.id, priority_to_string(priority))
      else
        apply_settings(task, query_apply, nil, 'HTTP query')
        rspamd_logger.infox(task, "applied settings from query; priority %s",
            priority_to_string(priority))
      end
    end
  end

  local min_pri = 1
  if query_apply then
    if priority >= min_pri then
      -- Do not check lower or equal priorities
      min_pri = priority + 1
    end

    if priority > max_pri then
      -- Our internal priorities are lower then a priority from query, so no need to check
      maybe_apply_query_settings()

      return
    end
  end

  -- Do not waste resources
  if not settings_initialized then
    maybe_apply_query_settings()
    return
  end

  -- Match rules according their order
  local applied = false

  for pri = max_pri,min_pri,-1 do
    if not applied and settings[pri] then
      for _,s in ipairs(settings[pri]) do
        local matched = {}

        lua_util.debugm(N, task, "check for settings element %s",
            s.name)
        local result = check_specific_setting(s.rule, matched)
        -- Can use xor here but more complicated for reading
        if result then
          if s.rule['apply'] then
            if s.rule.id then
              -- Extract static settings
              local cached = lua_settings.settings_by_id(s.rule.id)

              if not cached or not cached.settings or not cached.settings.apply then
                rspamd_logger.errx(task, 'unregistered settings id found: %s!', s.rule.id)
              else
                rspamd_logger.infox(task, "<%s> apply static settings %s (id = %s); %s matched; priority %s",
                    task:get_message_id(),
                    cached.name, s.rule.id,
                    table.concat(matched, ','),
                    priority_to_string(pri))
                apply_settings(task, cached.settings.apply, s.rule.id, s.name)
              end

            else
              -- Dynamic settings
              rspamd_logger.infox(task, "<%s> apply settings according to rule %s (%s matched)",
                  task:get_message_id(), s.name, table.concat(matched, ','))
              apply_settings(task, s.rule.apply, nil, s.name)
            end

            applied = true
          end
          if s.rule['symbols'] then
            -- Add symbols, specified in the settings
            fun.each(function(val)
              task:insert_result(val, 1.0)
            end, s.rule['symbols'])
          end
        end
      end
    end
  end

  if not applied then
    maybe_apply_query_settings()
  end

end

local function convert_to_table(chk_elt, out)
  if type(chk_elt) == 'string' then
    return {out}
  end

  return out
end

-- Process IP address: converted to a table {ip, mask}
local function process_ip_condition(ip)
  local out = {}

  if type(ip) == "table" then
    for _,v in ipairs(ip) do
      table.insert(out, process_ip_condition(v))
    end
  elseif type(ip) == "string" then
    local slash = string.find(ip, '/')

    if not slash then
      -- Just a plain IP address
      local res = rspamd_ip.from_string(ip)

      if res:is_valid() then
        out[1] = res
        out[2] = 0
      else
        -- It can still be a map
        out[1] = res
      end
    else
      local res = rspamd_ip.from_string(string.sub(ip, 1, slash - 1))
      local mask = tonumber(string.sub(ip, slash + 1))

      if res:is_valid() then
        out[1] = res
        out[2] = mask
      else
        rspamd_logger.errx(rspamd_config, "bad IP address: " .. ip)
        return nil
      end
    end
  else
    return nil
  end

  return out
end

-- Process email like condition, converted to a table with fields:
-- name - full email (surprise!)
-- user - user part
-- domain - domain part
-- regexp - full email regexp (yes, it sucks)
local function process_email_condition(addr)
  local out = {}
  if type(addr) == "table" then
    for _,v in ipairs(addr) do
      table.insert(out, process_email_condition(v))
    end
  elseif type(addr) == "string" then
    if string.sub(addr, 1, 4) == "map:" then
      -- It is map, don't apply any extra logic
      out['name'] = addr
    else
      local start = string.sub(addr, 1, 1)
      if start == '/' then
        -- It is a regexp
        local re = rspamd_regexp.create(addr)
        if re then
          out['regexp'] = re
        else
          rspamd_logger.errx(rspamd_config, "bad regexp: " .. addr)
          return nil
        end

      elseif start == '@' then
        -- It is a domain if form @domain
        out['domain'] = string.sub(addr, 2)
      else
        -- Check user@domain parts
        local at = string.find(addr, '@')
        if at then
          -- It is full address
          out['name'] = addr
        else
          -- It is a user
          out['user'] = addr
        end
      end
    end
  else
    return nil
  end

  return out
end

-- Convert a plain string condition to a table:
-- check - string to match
-- regexp - regexp to match
local function process_string_condition(addr)
  local out = {}
  if type(addr) == "table" then
    for _,v in ipairs(addr) do
      table.insert(out, process_string_condition(v))
    end
  elseif type(addr) == "string" then
    if string.sub(addr, 1, 4) == "map:" then
      -- It is map, don't apply any extra logic
      out['check'] = addr
    else
      local start = string.sub(addr, 1, 1)
      if start == '/' then
        -- It is a regexp
        local re = rspamd_regexp.create(addr)
        if re then
          out['regexp'] = re
        else
          rspamd_logger.errx(rspamd_config, "bad regexp: " .. addr)
          return nil
        end

      else
        out['check'] = addr
      end
    end
  else
    return nil
  end

  return out
end

local function get_priority (elt)
  local pri_tonum = function(p)
    if p then
      if type(p) == "number" then
        return tonumber(p)
      elseif type(p) == "string" then
        if p == "high" then
          return 3
        elseif p == "medium" then
          return 2
        end

      end

    end

    return 1
  end

  return pri_tonum(elt['priority'])
end

-- Used to create a checking closure: if value matches expected somehow, return true
local function gen_check_closure(expected, check_func)
  return function(value)
    if not value then return false end

    if type(value) == 'function' then
      value = value()
    end

    if value then

      if not check_func then
        check_func = function(a, b) return a == b end
      end

      local ret
      if type(expected) == 'table' then
        ret = fun.any(function(d)
          return check_func(d, value)
        end, expected)
      else
        ret = check_func(expected, value)
      end
      if ret then
        return true
      end
    end

    return false
  end
end

-- Process settings based on their priority
local function process_settings_table(tbl, allow_ids, mempool, is_static)

  -- Check the setting element internal data
  local process_setting_elt = function(name, elt)

    lua_util.debugm(N, rspamd_config, 'process settings "%s"', name)

    local out = {}

    local checks = {}
    if elt.ip then
      local ips_table = process_ip_condition(elt['ip'])

      if ips_table then
        lua_util.debugm(N, rspamd_config, 'added ip condition to "%s": %s',
            name, ips_table)
        checks.ip = {
          check = gen_check_closure(convert_to_table(elt.ip, ips_table), check_ip_setting),
          extract = function(task)
            local ip = task:get_from_ip()
            if ip and ip:is_valid() then return ip end
            return nil
          end,
        }
      end
    end
    if elt.ip_map then
      local ips_map = lua_maps.map_add_from_ucl(elt.ip_map, 'radix',
          'settings ip map for ' .. name)

      if ips_map then
        lua_util.debugm(N, rspamd_config, 'added ip_map condition to "%s"',
            name)
        checks.ip_map = {
          check = gen_check_closure(ips_map, check_map_setting),
          extract = function(task)
            local ip = task:get_from_ip()
            if ip and ip:is_valid() then return ip end
            return nil
          end,
        }
      end
    end

    if elt.client_ip then
      local client_ips_table = process_ip_condition(elt.client_ip)

      if client_ips_table then
        lua_util.debugm(N, rspamd_config, 'added client_ip condition to "%s": %s',
            name, client_ips_table)
        checks.client_ip = {
          check = gen_check_closure(convert_to_table(elt.client_ip, client_ips_table),
              check_ip_setting),
          extract = function(task)
            local ip = task:get_client_ip()
            if ip:is_valid() then return ip end
            return nil
          end,
        }
      end
    end
    if elt.client_ip_map then
      local ips_map = lua_maps.map_add_from_ucl(elt.ip_map, 'radix',
          'settings client ip map for ' .. name)

      if ips_map then
        lua_util.debugm(N, rspamd_config, 'added client ip_map condition to "%s"',
            name)
        checks.client_ip_map = {
          check = gen_check_closure(ips_map, check_map_setting),
          extract = function(task)
            local ip = task:get_client_ip()
            if ip and ip:is_valid() then return ip end
            return nil
          end,
        }
      end
    end

    if elt.from then
      local from_condition = process_email_condition(elt.from)

      if from_condition then
        lua_util.debugm(N, rspamd_config, 'added from condition to "%s": %s',
            name, from_condition)
        checks.from = {
          check = gen_check_closure(convert_to_table(elt.from, from_condition),
              check_addr_setting),
          extract = function(task)
            return task:get_from(1)
          end,
        }
      end
    end

    if elt.rcpt then
      local rcpt_condition = process_email_condition(elt.rcpt)
      if rcpt_condition then
        lua_util.debugm(N, rspamd_config, 'added rcpt condition to "%s": %s',
            name, rcpt_condition)
        checks.rcpt = {
          check = gen_check_closure(convert_to_table(elt.rcpt, rcpt_condition),
              check_addr_setting),
          extract = function(task)
            return task:get_recipients(1)
          end,
        }
      end
    end

    if elt.from_mime then
      local from_mime_condition = process_email_condition(elt.from_mime)

      if from_mime_condition then
        lua_util.debugm(N, rspamd_config, 'added from_mime condition to "%s": %s',
            name, from_mime_condition)
        checks.from_mime = {
          check = gen_check_closure(convert_to_table(elt.from_mime, from_mime_condition),
              check_addr_setting),
          extract = function(task)
            return task:get_from(2)
          end,
        }
      end
    end

    if elt.rcpt_mime then
      local rcpt_mime_condition = process_email_condition(elt.rcpt_mime)
      if rcpt_mime_condition then
        lua_util.debugm(N, rspamd_config, 'added rcpt mime condition to "%s": %s',
            name, rcpt_mime_condition)
        checks.rcpt_mime = {
          check = gen_check_closure(convert_to_table(elt.rcpt_mime, rcpt_mime_condition),
              check_addr_setting),
          extract = function(task)
            return task:get_recipients(2)
          end,
        }
      end
    end

    if elt.user then
      local user_condition = process_email_condition(elt.user)
      if user_condition then
        lua_util.debugm(N, rspamd_config, 'added user condition to "%s": %s',
            name, user_condition)
        checks.user = {
          check = gen_check_closure(convert_to_table(elt.user, user_condition),
              check_addr_setting),
          extract = function(task)
            local uname = task:get_user()
            local user = {}
            if uname then
              user[1] = {}
              local localpart, domainpart = string.gmatch(uname, "(.+)@(.+)")()
              if localpart then
                user[1]["user"] = localpart
                user[1]["domain"] = domainpart
                user[1]["addr"] = uname
              else
                user[1]["user"] = uname
                user[1]["addr"] = uname
              end

              return user
            end

            return nil
          end,
        }
      end
    end

    if elt.hostname then
      local hostname_condition = process_string_condition(elt.hostname)
      if hostname_condition then
        lua_util.debugm(N, rspamd_config, 'added hostname condition to "%s": %s',
            name, hostname_condition)
        checks.hostname = {
          check = gen_check_closure(convert_to_table(elt.hostname, hostname_condition),
              check_string_setting),
          extract = function(task)
            return task:get_hostname() or ''
          end,
        }
      end
    end

    if elt.authenticated then
      lua_util.debugm(N, rspamd_config, 'added authenticated condition to "%s"',
          name)
      checks.authenticated = {
        check = function(value) if value then return true end return false end,
        extract = function(task)
          return task:get_user()
        end
      }
    end

    if elt['local'] then
      lua_util.debugm(N, rspamd_config, 'added local condition to "%s"',
          name)
      checks['local'] = {
        check = function(value) if value then return true end return false end,
        extract = function(task)
          local ip = task:get_from_ip()
          if not ip or not ip:is_valid() then
            return nil
          end

          if ip:is_local() then
            return true
          else
            return nil
          end
        end
      }
    end

    local aliases = {}
    -- This function is used to convert compound condition with
    -- generic type and specific part (e.g. `header`, `Content-Transfer-Encoding`)
    -- to a set of usable check elements:
    -- `generic:specific` - most common part
    -- `generic:<order>` - e.g. `header:1` for the first header
    -- `generic:safe` - replace unsafe stuff with safe + lowercase
    -- also aliases entry is set to avoid implicit expression
    local function process_compound_condition(cond, generic, specific)
      local full_key = generic .. ':' .. specific
      checks[full_key] = cond

      -- Try numeric key
      for i=1,1000 do
        local num_key = generic .. ':' .. tostring(i)
        if not checks[num_key]  then
          checks[num_key] = cond
          aliases[num_key] = true
          break
        end
      end

      local safe_key = generic .. ':' ..
          specific:gsub('[:%-+&|><]', '_')
                  :gsub('%(', '[')
                  :gsub('%)', ']')
                  :lower()

      if not checks[safe_key] then
        checks[safe_key] = cond
        aliases[safe_key] = true
      end

      return safe_key
    end
    -- Headers are tricky:
    -- We create an closure with extraction function depending on header name
    -- We also inserts it into `checks` table as an atom in form header:<hname>
    -- Check function depends on the input:
    -- * for something that looks like `header = "/bar/"` we create a regexp
    -- * for something that looks like `header = true` we just check the existence
    local function process_header_elt(table_element, extractor_func)
      if elt[table_element] then
        for k, v in pairs(elt[table_element]) do
          if type(v) == 'string' then
            local re = rspamd_regexp.create(v)
            if re then
              local cond = {
                check = function(values)
                  return fun.any(function(c) return re:match(c) end, values)
                end,
                extract = extractor_func(k),
              }
              local skey = process_compound_condition(cond, table_element,
                  k)
              lua_util.debugm(N, rspamd_config, 'added %s condition to "%s": %s =~ %s',
                  skey, name, k, v)
            end
          elseif type(v) == 'boolean' then
            local cond = {
              check = function(values)
                if #values == 0 then return (not v) end
                return v
              end,
              extract = extractor_func(k),
            }

            local skey = process_compound_condition(cond, table_element,
                k)
            lua_util.debugm(N, rspamd_config, 'added %s condition to "%s": %s == %s',
                skey, name, k, v)
          else
            rspamd_logger.errx(rspamd_config, 'invalid %s %s = %s', table_element, k, v)
          end
        end
      end
    end

    process_header_elt('request_header', function(hname)
      return function(task)
        local rh = task:get_request_header(hname)
        if rh then return {rh} end
        return {}
      end
    end)
    process_header_elt('header', function(hname)
      return function(task)
        local rh = task:get_header_full(hname)
        if rh then
          return fun.totable(fun.map(function(h) return h.decoded end, rh))
        end
        return {}
      end
    end)

    if elt.selector then
      local sel = lua_selectors.create_selector_closure(rspamd_config, elt.selector,
          elt.delimiter or "")

      if sel then
        local cond = {
          check = function(values)
            return fun.any(function(c)
              return c
            end, values)
          end,
          extract = sel,
        }
        local skey = process_compound_condition(cond, 'selector', elt.selector)
        lua_util.debugm(N, rspamd_config, 'added selector condition to "%s": %s',
            name, skey)
      end

    end

    -- Special, special case!
    local inverse = false
    if elt.inverse then
      lua_util.debugm(N, rspamd_config, 'added inverse condition to "%s"',
          name)
      inverse = true
    end

    -- Count checks and create Rspamd expression from a set of rules
    local nchecks = 0
    for _,_ in pairs(checks) do nchecks = nchecks + 1 end

    if nchecks > 0 then
      -- Now we can deal with the expression!
      if not elt.expression then
        -- Artificial & expression to deal with the legacy parts
        -- Here we get all keys and concatenate them with '&&'
        local s = ' && '
        -- By De Morgan laws
        if inverse then s = ' || ' end
        -- Exclude aliases and join all checks by key
        local expr_str = table.concat(lua_util.keys(fun.filter(
            function(k, _) return not aliases[k] end,
            checks)), s)

        if inverse then
          expr_str = string.format('!(%s)', expr_str)
        end

        elt.expression = expr_str
        lua_util.debugm(N, rspamd_config, 'added implicit settings expression for %s: %s',
            name, expr_str)
      end

      -- Parse expression's sanity
      local function parse_atom(str)
        local atom = table.concat(fun.totable(fun.take_while(function(c)
          if string.find(', \t()><+!|&\n', c) then
            return false
          end
          return true
        end, fun.iter(str))), '')

        if checks[atom] then
          return atom
        end

        rspamd_logger.errx(rspamd_config,
            'use of undefined element "%s" when parsing settings expression, known checks: %s',
            atom, table.concat(fun.totable(fun.map(function(k, _) return k end, checks)), ','))

        return nil
      end

      local rspamd_expression = require "rspamd_expression"
      out.expression = rspamd_expression.create(elt.expression, parse_atom,
          mempool)
      out.checks = checks

      if not out.expression then
        rspamd_logger.errx(rspamd_config, 'cannot parse expression %s for %s',
            elt.expression, name)
      else
        lua_util.debugm(N, rspamd_config, 'registered settings %s with %s checks',
            name, nchecks)
      end
    else
      lua_util.debugm(N, rspamd_config, 'registered settings %s with no checks',
          name)
    end

    -- Process symbols part/apply part
    if elt['symbols'] then
      lua_util.debugm(N, rspamd_config, 'added symbols condition to "%s": %s',
          name, elt.symbols)
      out['symbols'] = elt['symbols']
    end


    if elt['apply'] then
      -- Just insert all metric results to the action key
      out['apply'] = elt['apply']
    elseif elt['whitelist'] or elt['want_spam'] then
      out['whitelist'] = true
    else
      rspamd_logger.errx(rspamd_config, "no actions in settings: " .. name)
      return nil
    end

    if allow_ids then
      if not elt.id then
        elt.id = name
      end

      if elt['id'] then
        -- We are here from a postload script
        out.id = lua_settings.register_settings_id(elt.id, out, true)
        lua_util.debugm(N, rspamd_config,
            'added settings id to "%s": %s -> %s',
            name, elt.id, out.id)
      end

      if not is_static then
        -- If we apply that from map
        -- In fact, it is useless and evil but who cares...
        if elt.apply and elt.apply.symbols then
          -- Register virtual symbols
          for k,v in pairs(elt.apply.symbols) do
            local rtb = {
              type = 'virtual',
              parent = module_sym_id,
            }
            if type(k) == 'number' and type(v) == 'string' then
              rtb.name = v
            elseif type(k) == 'string' then
              rtb.name = k
            end
            if out.id then
              rtb.allowed_ids = tostring(elt.id)
            end
            rspamd_config:register_symbol(rtb)
          end
        end
      end
    else
      if elt['id'] then
        rspamd_logger.errx(rspamd_config,
            'cannot set static IDs from dynamic settings, please read the docs')
      end
    end

    return out
  end

  settings_initialized = false
  -- filter trash in the input
  local ft = fun.filter(
    function(_, elt)
      if type(elt) == "table" then
        return true
      end
      return false
    end, tbl)

  -- clear all settings
  max_pri = 0
  local nrules = 0
  for k in pairs(settings) do settings[k]={} end
  -- fill new settings by priority
  fun.for_each(function(k, v)
    local pri = get_priority(v)
    if pri > max_pri then max_pri = pri end
    if not settings[pri] then
      settings[pri] = {}
    end
    local s = process_setting_elt(k, v)
    if s then
      table.insert(settings[pri], {name = k, rule = s})
      nrules = nrules + 1
    end
  end, ft)
  -- sort settings with equal priorities in alphabetical order
  for pri,_ in pairs(settings) do
    table.sort(settings[pri], function(a,b) return a.name < b.name end)
  end

  settings_initialized = true
  lua_settings.load_all_settings(true)
  rspamd_logger.infox(rspamd_config, 'loaded %1 elements of settings', nrules)

  return true
end

-- Parse settings map from the ucl line
local settings_map_pool
local function process_settings_map(map_text)
  local parser = ucl.parser()
  local res,err

  if type(map_text) == 'string' then
    res,err = parser:parse_string(map_text)
  else
    res,err = parser:parse_text(map_text)
  end

  if not res then
    rspamd_logger.warnx(rspamd_config, 'cannot parse settings map: ' .. err)
  else
    if settings_map_pool then
      settings_map_pool:destroy()
    end

    settings_map_pool = rspamd_mempool.create()
    local obj = parser:get_object()
    if obj['settings'] then
      process_settings_table(obj['settings'], false,
          settings_map_pool, false)
    else
      process_settings_table(obj, false, settings_map_pool,
          false)
    end
  end

  return res
end

local function gen_redis_callback(handler, id)
  return function(task)
    local key = handler(task)

    local function redis_settings_cb(err, data)
      if not err and type(data) == 'table' then
        for _, d in ipairs(data) do
          if type(d) == 'string' then
            local parser = ucl.parser()
            local res,ucl_err = parser:parse_string(d)
            if not res then
              rspamd_logger.warnx(rspamd_config, 'cannot parse settings from redis: %s',
                ucl_err)
            else
              local obj = parser:get_object()
              rspamd_logger.infox(task, "<%1> apply settings according to redis rule %2",
                task:get_message_id(), id)
              apply_settings(task, obj, nil, 'redis')
              break
            end
          end
        end
      elseif err then
        rspamd_logger.errx(task, 'Redis error: %1', err)
      end
    end

    if not key then
      lua_util.debugm(N, task, 'handler number %s returned nil', id)
      return
    end

    local keys
    if type(key) == 'table' then
      keys = key
    else
      keys = {key}
    end
    key = keys[1]

    local ret,_,_ = rspamd_redis_make_request(task,
      redis_params, -- connect params
      key, -- hash key
      false, -- is write
      redis_settings_cb, --callback
      'MGET', -- command
      keys -- arguments
    )
    if not ret then
      rspamd_logger.errx(task, 'Redis MGET failed: %s', ret)
    end
  end
end

local redis_section = rspamd_config:get_all_opt("settings_redis")
local redis_key_handlers = {}

if redis_section then
  redis_params = rspamd_parse_redis_server('settings_redis')
  if redis_params then
    local handlers = redis_section.handlers

    for id,h in pairs(handlers) do
      local chunk,err = load(h)

      if not chunk then
        rspamd_logger.errx(rspamd_config, 'Cannot load handler from string: %s',
            tostring(err))
      else
        local res,func = pcall(chunk)
        if not res then
          rspamd_logger.errx(rspamd_config, 'Cannot add handler from string: %s',
            tostring(func))
        else
          redis_key_handlers[id] = func
        end
      end
    end
  end

  fun.each(function(id, h)
    rspamd_config:register_symbol({
      name = 'REDIS_SETTINGS' .. tostring(id),
      type = 'prefilter',
      callback = gen_redis_callback(h, id),
      priority = 10,
      flags = 'empty,nostat',
    })
  end, redis_key_handlers)
end

module_sym_id = rspamd_config:register_symbol({
  name = 'SETTINGS_CHECK',
  type = 'prefilter',
  callback = check_settings,
  priority = 10,
  flags = 'empty,nostat,explicit_disable,ignore_passthrough',
})

local set_section = rspamd_config:get_all_opt("settings")

if set_section and set_section[1] and type(set_section[1]) == "string" then
  -- Just a map of ucl
  local map_attrs = {
    url = set_section[1],
    description = "settings map",
    callback = process_settings_map,
    opaque_data = true
  }
  if not rspamd_config:add_map(map_attrs) then
    rspamd_logger.errx(rspamd_config, 'cannot load settings from %1', set_section)
  end
elseif set_section and type(set_section) == "table" then
  settings_map_pool = rspamd_mempool.create()
  -- We need to check this table and register static symbols first
  -- Postponed settings init is needed to ensure that all symbols have been
  -- registered BEFORE settings plugin. Otherwise, we can have inconsistent settings expressions
  fun.each(function(_, elt)
    if elt.apply and elt.apply.symbols then
      -- Register virtual symbols
      for k,v in pairs(elt.apply.symbols) do
        local rtb = {
          type = 'virtual',
          parent = module_sym_id,
        }
        if type(k) == 'number' and type(v) == 'string' then
          rtb.name = v
        elseif type(k) == 'string' then
          rtb.name = k
        end
        rspamd_config:register_symbol(rtb)
      end
    end
  end,
      -- Include only settings, exclude all maps
      fun.filter(
          function(_, elt)
            if type(elt) == "table" then
              return true
            end
            return false
          end, set_section)
  )
  rspamd_config:add_post_init(function ()
    process_settings_table(set_section, true, settings_map_pool, true)
  end, 100)
end

rspamd_config:add_config_unload(function()
  if settings_map_pool then
    settings_map_pool:destroy()
  end
end)
