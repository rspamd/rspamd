--[[
Copyright (c) 2026, Vsevolod Stakhov <vsevolod@rspamd.com>

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
local rspamd_regexp = require "rspamd_regexp"
local rspamd_ip = require "rspamd_ip"
local log_utils = require "lua_log_utils"
local ansicolors = require "ansicolors"

local parser = argparse()
  :name "rspamadm mapstats"
  :description "Count Rspamd multimap matches by parsing log files"
  :help_description_margin(32)

parser:argument "log"
  :description "Log file or directory to read (stdin if omitted)"
  :args "?"
  :default ""
parser:option "-c --config"
  :description "Path to config file"
  :argname "<file>"
  :default(rspamd_paths and rspamd_paths["CONFDIR"] and
    (rspamd_paths["CONFDIR"] .. "/" .. "rspamd.conf") or
    "/etc/rspamd/rspamd.conf")
parser:option "--start"
  :description "Starting time for log parsing"
  :argname "<time>"
  :default ""
parser:option "--end"
  :description "Ending time for log parsing"
  :argname "<time>"
parser:option "-n --num-logs"
  :description "Number of recent logfiles to analyze"
  :argname "<n>"
  :convert(tonumber)
parser:option "-x --exclude-logs"
  :description "Number of latest logs to exclude"
  :argname "<n>"
  :default "0"
  :convert(tonumber)

local re_non_file_url = rspamd_regexp.create('/^.*(?<!file):\\/\\//')
local re_regexp_line = rspamd_regexp.create('/^\\/(.+)\\/(\\S?)(?:\\s+(\\d+\\.?\\d*))?$/')
local re_plain_line = rspamd_regexp.create('/^(\\S+)(?:\\s+(\\d+\\.?\\d*))?$/')
local re_sym_with_opts = rspamd_regexp.create('/([^(]+)\\([.0-9]+\\)\\{([^;]+);\\}/')

local function get_multimap_config(config_path)
  local _r, err = rspamd_config:load_ucl(config_path)
  if not _r then
    io.stderr:write(string.format("Cannot load config %s: %s\n", config_path, err))
    os.exit(1)
  end
  _r, err = rspamd_config:parse_rcl({ 'logging', 'worker' })
  if not _r then
    io.stderr:write(string.format("Cannot parse config %s: %s\n", config_path, err))
    os.exit(1)
  end

  local multimap_opts = rspamd_config:get_all_opt('multimap')
  if not multimap_opts then
    io.stderr:write("No multimap configuration found.\n")
    os.exit(1)
  end

  return multimap_opts
end

local function validate_regex_flags(flags, map_file, line_num)
  if flags and #flags > 0 then
    local bad = flags:match('[^imsxurOL]')
    if bad then
      io.stderr:write(string.format(
        "Invalid regex flag in %s at line %d: '%s' (supported: imsxurOL)\n",
        map_file, line_num, flags))
      return false
    end
  end
  return true
end

local function get_map(symbol_cfg, map_file)
  local fh, err = io.open(map_file, 'r')
  if not fh then
    io.stderr:write(string.format("Cannot open map file %s: %s\n", map_file, err or 'unknown'))
    return {}
  end

  local entries = {}
  local line_num = 0
  local is_regexp = symbol_cfg.regexp and true or false

  for line in fh:lines() do
    line_num = line_num + 1

    local trimmed = line:match('^%s*(.-)%s*$')
    if trimmed == '' or trimmed:match('^#') then
      table.insert(entries, {
        line_num = line_num,
        is_comment = true,
        content = line,
      })
    else
      -- Extract inline comment before regex parsing to avoid
      -- rspamd_regexp capture truncation on unmatched optional groups
      local comment = nil
      local body = trimmed
      if is_regexp then
        -- For regexes, comment must come after the closing / and optional flags/score
        -- Find the last # that's preceded by whitespace (outside the regex pattern)
        local close_slash = trimmed:find('/', 2)
        if close_slash then
          local after = trimmed:sub(close_slash + 1)
          local cmt_pos = after:find('%s+#%s*')
          if cmt_pos then
            -- Find actual position of # in after
            local hash_pos = after:find('#', cmt_pos)
            if hash_pos then
              comment = after:sub(hash_pos + 1):match('^%s*(.*)')
              body = trimmed:sub(1, close_slash) .. after:sub(1, cmt_pos - 1)
            end
          end
        end
      else
        local pre, cmt = trimmed:match('^(.-)%s+#%s*(.*)$')
        if pre and cmt then
          comment = cmt
          body = pre
        end
      end

      if is_regexp then
        local results = re_regexp_line:search(body, false, true)
        if not results or #results == 0 then
          io.stderr:write(string.format("Syntax error in %s at line %d\n", map_file, line_num))
          fh:close()
          return {}
        end
        local caps = results[1]
        if not caps or #caps < 2 then
          io.stderr:write(string.format("Syntax error in %s at line %d\n", map_file, line_num))
          fh:close()
          return {}
        end

        local pattern = tostring(caps[2])
        local flags = caps[3] and tostring(caps[3]) or ''
        local result = caps[4] and tostring(caps[4]) or nil

        if not validate_regex_flags(flags, map_file, line_num) then
          fh:close()
          return {}
        end

        -- Compile with rspamd_regexp (handles all rspamd flags natively)
        local re_pattern = '/' .. pattern .. '/' .. flags
        local compiled = rspamd_regexp.create(re_pattern)
        if not compiled then
          io.stderr:write(string.format("Invalid regex in %s at line %d\n", map_file, line_num))
          fh:close()
          return {}
        end

        table.insert(entries, {
          line_num = line_num,
          pattern = pattern,
          flag = flags,
          compiled = compiled,
          result = result,
          comment = comment,
          count = 0,
        })
      else
        local results = re_plain_line:search(body, false, true)
        if not results or #results == 0 then
          io.stderr:write(string.format("Syntax error in %s at line %d\n", map_file, line_num))
          fh:close()
          return {}
        end
        local caps = results[1]
        if not caps or #caps < 2 then
          io.stderr:write(string.format("Syntax error in %s at line %d\n", map_file, line_num))
          fh:close()
          return {}
        end

        local pattern = tostring(caps[2])
        local result = caps[3] and tostring(caps[3]) or nil

        table.insert(entries, {
          line_num = line_num,
          pattern = pattern,
          result = result,
          comment = comment,
          count = 0,
        })
      end
    end
  end

  fh:close()
  return entries
end

local function ip_within(ip_obj, cidr_str)
  -- Extract mask from CIDR notation before parsing
  local ip_part, mask_str = cidr_str:match('^(.+)/(%d+)$')
  if ip_part then
    local cidr_ip = rspamd_ip.from_string(ip_part)
    if not cidr_ip or not cidr_ip:is_valid() then
      return false
    end
    local mask = tonumber(mask_str)
    -- apply_mask returns a new IP object with the mask applied
    local ip_masked = ip_obj:apply_mask(mask)
    local cidr_masked = cidr_ip:apply_mask(mask)
    if not ip_masked or not cidr_masked then
      return false
    end
    return ip_masked == cidr_masked
  else
    local cidr_ip = rspamd_ip.from_string(cidr_str)
    if not cidr_ip or not cidr_ip:is_valid() then
      return false
    end
    return ip_obj == cidr_ip
  end
end

local function handler(args)
  local res = parser:parse(args)

  local multimap = get_multimap_config(res['config'])

  local map = {}
  local symbols_search = {}
  local unmatched = {}

  for symbol, cfg in pairs(multimap) do
    if type(cfg) ~= 'table' then
      goto continue_sym
    end

    local maps_list = cfg['map']
    if not maps_list then
      goto continue_sym
    end

    if type(maps_list) ~= 'table' then
      maps_list = { maps_list }
    elseif maps_list[1] == nil then
      -- It's a single map object, not an array
      maps_list = { maps_list }
    end

    map[symbol] = {
      type = cfg['type'] or 'string',
      is_regexp = cfg['regexp'] and true or false,
      maps = {},
    }

    local has_valid_maps = false
    for _, map_source in ipairs(maps_list) do
      if type(map_source) == 'table' then
        map_source = map_source['url'] or map_source['name'] or ''
      end
      if type(map_source) ~= 'string' then
        goto continue_map
      end

      -- Skip non-file maps
      if re_non_file_url:match(map_source) then
        io.write(string.format("%s: %s %s\n",
          ansicolors.bright .. symbol .. ansicolors.reset, map_source,
          ansicolors.yellow .. "[SKIPPED]" .. ansicolors.reset))
        goto continue_map
      end

      -- Strip file:// prefix
      local file_path = map_source:gsub('^fallback%+', ''):gsub('^file://', '')

      local entries = get_map(cfg, file_path)
      if #entries == 0 then
        io.write(string.format("%s: %s %s\n",
          ansicolors.bright .. symbol .. ansicolors.reset, map_source,
          ansicolors.red .. "[FAILED]" .. ansicolors.reset))
        goto continue_map
      end

      local entry_count = 0
      for _, e in ipairs(entries) do
        if not e.is_comment then
          entry_count = entry_count + 1
        end
      end
      io.write(string.format("%s: %s %s - %d entries\n",
        ansicolors.bright .. symbol .. ansicolors.reset, map_source,
        ansicolors.green .. "[OK]" .. ansicolors.reset, entry_count))

      table.insert(map[symbol].maps, {
        source = map_source,
        entries = entries,
      })
      has_valid_maps = true

      ::continue_map::
    end

    if has_valid_maps then
      table.insert(symbols_search, symbol)
    end

    ::continue_sym::
  end

  if #symbols_search == 0 then
    io.stderr:write("No file-based multimap symbols found. Nothing to analyze.\n")
    os.exit(1)
  end

  io.write("====== maps added =====\n")

  -- Process logs
  local function process_callback(ts, act, score, symbols_str, scan_time)
    if symbols_str == '' then
      return
    end

    local symbols_raw = {}
    for sym in symbols_str:gmatch('[^,]+') do
      table.insert(symbols_raw, sym)
    end

    for _, s in ipairs(symbols_search) do
      for _, sym in ipairs(symbols_raw) do
        if not sym:find(s, 1, true) then
          goto continue_inner
        end

        local results = re_sym_with_opts:search(sym, false, true)
        if not results or #results == 0 then
          unmatched[sym] = (unmatched[sym] or 0) + 1
          goto continue_inner
        end
        local caps = results[1]
        if not caps or #caps < 3 then
          unmatched[sym] = (unmatched[sym] or 0) + 1
          goto continue_inner
        end

        local sym_name = tostring(caps[2])
        local sym_opt = tostring(caps[3])

        if sym_name ~= s then
          goto continue_inner
        end

        local ip_obj
        if map[sym_name].type == 'ip' then
          ip_obj = rspamd_ip.from_string(sym_opt)
          if not ip_obj or not ip_obj:is_valid() then
            io.stderr:write(string.format("Invalid IP address in symbol %s: %s\n", sym_name, sym_opt))
            goto continue_inner
          end
        end

        local matched = false
        for _, map_entry in ipairs(map[sym_name].maps) do
          for _, entry in ipairs(map_entry.entries) do
            if entry.is_comment then
              goto continue_entry
            end

            if map[sym_name].type == 'ip' then
              if ip_obj and ip_within(ip_obj, entry.pattern) then
                entry.count = entry.count + 1
                matched = true
                break
              end
            elseif map[sym_name].is_regexp then
              if entry.compiled:match(sym_opt) then
                entry.count = entry.count + 1
                matched = true
                break
              end
            else
              if sym_opt == entry.pattern then
                entry.count = entry.count + 1
                matched = true
                break
              end
            end

            ::continue_entry::
          end
          if matched then break end
        end

        if not matched then
          unmatched[sym] = (unmatched[sym] or 0) + 1
        end

        ::continue_inner::
      end
    end
  end

  log_utils.process_logs(res['log'], res['start'] or '', res['end'], process_callback, {
    num_logs = res['num_logs'],
    exclude_logs = res['exclude_logs'],
  })

  -- Output results
  for _, symbol in ipairs(symbols_search) do
    io.write(string.format("%s:\n", ansicolors.bright .. symbol .. ansicolors.reset))
    io.write(string.format("    type=%s\n", map[symbol].type))

    for _, map_entry in ipairs(map[symbol].maps) do
      io.write(string.format("\nMap: %s\n", map_entry.source))
      io.write("Pattern\t\t\tMatches\t\tComment\n")
      io.write(string.rep('-', 80) .. '\n')

      for _, entry in ipairs(map_entry.entries) do
        if entry.is_comment then
          io.write(entry.content .. '\n')
        else
          if map[symbol].is_regexp then
            io.write(string.format("%-23s", '/' .. entry.pattern .. '/' .. entry.flag))
          else
            io.write(string.format("%-23s", entry.pattern))
          end

          if entry.count and entry.count > 0 then
            io.write(string.format("\t%s",
              ansicolors.green .. tostring(entry.count) .. ansicolors.reset))
          else
            io.write("\t-")
          end

          if entry.comment then
            io.write(string.format("\t\t# %s", entry.comment))
          end

          io.write('\n')
        end
      end
    end

    io.write(string.rep('=', 80) .. '\n')
  end

  -- Unmatched report
  if next(unmatched) then
    io.write(string.format("\n%s\n",
      ansicolors.yellow .. "Symbols with unmatched values:" .. ansicolors.reset))
    io.write(string.rep('-', 80) .. '\n')

    local grouped = {}
    for key, count in pairs(unmatched) do
      local sym_name = key:match('^(%w+)%(')
      if sym_name then
        if not grouped[sym_name] then
          grouped[sym_name] = {}
        end
        table.insert(grouped[sym_name], { full = key, count = count })
      end
    end

    local sorted_groups = {}
    for sym_name in pairs(grouped) do
      table.insert(sorted_groups, sym_name)
    end
    table.sort(sorted_groups)

    for _, symbol in ipairs(sorted_groups) do
      local entries = grouped[symbol]
      table.sort(entries, function(a, b) return a.count > b.count end)

      io.write(string.format("\n%s: %s\n",
        ansicolors.bright .. symbol .. ansicolors.reset,
        ansicolors.yellow .. string.format("%d unmatched value(s)", #entries) .. ansicolors.reset))
      local limit = math.min(#entries, 5)
      for i = 1, limit do
        io.write(string.format("  %dx: %s\n", entries[i].count, entries[i].full))
      end
      if #entries > 5 then
        io.write("  ...\n")
      end
    end
  end
end

return {
  handler = handler,
  description = parser._description,
  name = 'mapstats'
}
