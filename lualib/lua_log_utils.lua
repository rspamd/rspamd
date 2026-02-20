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

local rspamd_regexp = require "rspamd_regexp"
local rspamd_util = require "rspamd_util"

local exports = {}

local isatty = rspamd_util.isatty()

local decompressor = {
  bz2 = 'bzip2 -cd',
  gz  = 'gzip -cd',
  xz  = 'xz -cd',
  zst = 'zstd -cd',
}

local month_map = {
  Jan = 0, Feb = 1, Mar = 2, Apr = 3, May = 4, Jun = 5,
  Jul = 6, Aug = 7, Sep = 8, Oct = 9, Nov = 10, Dec = 11,
}

local spinner_chars = { '/', '-', '\\', '|' }
local spinner_update_time = 0

function exports.spinner()
  if not isatty then
    return
  end
  local now = os.time()
  if (now - spinner_update_time) < 1 then
    return
  end
  spinner_update_time = now
  io.stderr:write(string.format("%s\r", spinner_chars[(now % #spinner_chars) + 1]))
  io.stderr:flush()
end

function exports.reset_spinner()
  spinner_update_time = 0
end

local re_rspamd_fmt = rspamd_regexp.create(
  '^\\d{4}-\\d\\d-\\d\\d \\d\\d:\\d\\d:\\d\\d(?:\\.\\d{3,5})? #\\d+\\(')
local re_syslog_fmt1 = rspamd_regexp.create(
  '^\\w{3} \\s?\\d\\d? \\d\\d:\\d\\d:\\d\\d #\\d+\\(')
local re_syslog_fmt2 = rspamd_regexp.create(
  '^\\w{3} \\s?\\d\\d? \\d\\d:\\d\\d:\\d\\d \\S+ rspamd\\[\\d+\\]')
local re_syslog5424_fmt = rspamd_regexp.create(
  '\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d{1,6})?(?:Z|[-+]\\d{2}:\\d{2}) \\S+ rspamd\\[\\d+\\]')
local re_newsyslog = rspamd_regexp.create(
  '^\\w{3} \\s?\\d\\d? \\d\\d:\\d\\d:\\d\\d \\S+ newsyslog\\[\\d+\\]: logfile turned over$')
local re_journalctl = rspamd_regexp.create(
  '^-- Logs begin at \\w{3} \\d{4}-\\d\\d-\\d\\d \\d\\d:\\d\\d:\\d\\d [A-Z]{3},' ..
  ' end at \\w{3} \\d{4}-\\d\\d-\\d\\d \\d\\d:\\d\\d:\\d\\d [A-Z]{3}\\. --$')

function exports.detect_log_format(line)
  if re_rspamd_fmt:match(line) then
    return 'rspamd'
  elseif re_syslog_fmt1:match(line) or re_syslog_fmt2:match(line) then
    return 'syslog'
  elseif re_syslog5424_fmt:match(line) then
    return 'syslog5424'
  elseif re_newsyslog:match(line) or re_journalctl:match(line) then
    return nil -- skip line
  else
    return false -- unknown
  end
end

function exports.syslog2iso(ts_str)
  local month_s, day, hh, mm, ss = ts_str:match('^(%a+)%s+(%d+)%s+(%d+):(%d+):(%d+)')
  if not month_s then
    return nil
  end
  local mon = month_map[month_s]
  if not mon then
    return nil
  end
  local now = os.time()
  local t = os.date('*t', now)
  local year = t.year
  local epoch = os.time({
    year = year, month = mon + 1, day = tonumber(day),
    hour = tonumber(hh), min = tonumber(mm), sec = tonumber(ss)
  })
  if epoch > now then
    year = year - 1
  end
  return string.format('%04d-%02d-%02d %02d:%02d:%02d',
    year, mon + 1, tonumber(day), tonumber(hh), tonumber(mm), tonumber(ss))
end

function exports.extract_timestamp(line, ts_format)
  if ts_format == 'syslog' then
    local ts_str = line:match('^(%a+%s+%d+%s+%d+:%d+:%d+)')
    if ts_str then
      return exports.syslog2iso(ts_str)
    end
  elseif ts_format == 'syslog5424' then
    local date, time = line:match('^(%d%d%d%d%-%d%d%-%d%d)T(%d%d:%d%d:%d%d)')
    if date and time then
      return date .. ' ' .. time
    end
  else
    local d, t = line:match('^(%d%d%d%d%-%d%d%-%d%d)%s+(%d%d:%d%d:%d%d)')
    if d and t then
      return d .. ' ' .. t
    end
  end
  return nil
end

function exports.normalized_time(s)
  if not s or s == '' then
    return ''
  end
  if s:match('^%d%d[:%d]*$') then
    local t = os.date('*t')
    return string.format('%04d-%02d-%02d %s', t.year, t.month, t.day, s)
  end
  return s
end

local function shell_quote(s)
  return "'" .. s:gsub("'", "'\\''") .. "'"
end

function exports.open_log_file(path)
  local ext = path:match('%.([^%.]+)$')
  local dc = decompressor[ext]
  if dc then
    return io.popen(dc .. ' ' .. shell_quote(path), 'r')
  else
    return io.open(path, 'r')
  end
end

local re_numbered_log = rspamd_regexp.create([[\.\d+(?:\.(?:bz2|gz|xz|zst))?$]])

local function numeric_index(fname)
  local idx = fname:match('%.(%d+)%.')
  if not idx then
    idx = fname:match('%.(%d+)$')
  end
  return tonumber(idx) or 0
end

function exports.get_logfiles_list(dir, num_logs, exclude_logs)
  exclude_logs = exclude_logs or 0

  local all_files = rspamd_util.glob(dir .. '/*')
  if not all_files or #all_files == 0 then
    io.stderr:write(string.format("No files found in directory: %s\n", dir))
    return {}
  end

  local unnumbered = {}
  local numbered = {}

  for _, full_path in ipairs(all_files) do
    local err, st = rspamd_util.stat(full_path)
    if not err and st and st.type == 'regular' then
      local fname = full_path:match('[^/]+$')
      if re_numbered_log:match(fname) then
        table.insert(numbered, fname)
      else
        table.insert(unnumbered, fname)
      end
    end
  end

  table.sort(numbered, function(a, b)
    return numeric_index(a) < numeric_index(b)
  end)

  local logs = {}
  for _, f in ipairs(unnumbered) do
    table.insert(logs, f)
  end
  for _, f in ipairs(numbered) do
    table.insert(logs, f)
  end

  -- Apply exclude_logs and num_logs (splice from exclude_logs+1, take num_logs)
  local start_idx = exclude_logs + 1
  local end_idx = num_logs and (start_idx + num_logs - 1) or #logs
  if end_idx > #logs then
    end_idx = #logs
  end

  local selected = {}
  for i = start_idx, end_idx do
    table.insert(selected, logs[i])
  end

  -- Reverse order (newest last -> oldest first for processing)
  local reversed = {}
  for i = #selected, 1, -1 do
    table.insert(reversed, selected[i])
  end

  io.stderr:write("\nLog files to process:\n")
  for _, f in ipairs(reversed) do
    io.stderr:write(string.format("  %s\n", f))
  end
  io.stderr:write("\n")

  return reversed
end

local re_task_log = rspamd_regexp.create([[rspamd_task_write_log]])
local re_log_line = rspamd_regexp.create(
  '/\\(([^()]+)\\): \\[(NaN|-?\\d+(?:\\.\\d+)?)\\/(-?\\d+(?:\\.\\d+)?)\\]\\s+\\[([^]]+)\\].*time: (\\d+\\.\\d+)ms/')

function exports.iterate_log(handle, start_time, end_time, callback, opts)
  opts = opts or {}
  local search_pattern = opts.search_pattern
  local search_re
  if search_pattern and search_pattern ~= '' then
    search_re = rspamd_regexp.create(search_pattern)
  end

  local ts_format = nil
  local enabled = (not search_re)

  for line in handle:lines() do
    if not ts_format then
      local fmt = exports.detect_log_format(line)
      if fmt == false then
        io.stderr:write("Unknown log format\n")
        return
      elseif fmt == nil then
        goto continue
      else
        ts_format = fmt
      end
    end

    if not enabled then
      if search_re and search_re:match(line) then
        enabled = true
      else
        goto continue
      end
    end

    if re_task_log:match(line) then
      exports.spinner()

      local ts = exports.extract_timestamp(line, ts_format)
      if not ts then
        goto continue
      end

      if start_time ~= '' and ts < start_time then
        goto continue
      end
      if end_time and end_time ~= '' and ts > end_time then
        goto continue
      end

      local results = re_log_line:search(line, false, true)
      if not results or #results == 0 then
        goto continue
      end

      local captures = results[1]
      if not captures or #captures < 6 then
        goto continue
      end

      local act = tostring(captures[2])
      local score_str = tostring(captures[3])
      local symbols_str = tostring(captures[5])
      local scan_time_str = tostring(captures[6])

      local score = tonumber(score_str) or 0
      local scan_time = tonumber(scan_time_str) or 0

      callback(ts, act, score, symbols_str, scan_time, line)
    end

    ::continue::
  end
end

function exports.process_logs(log_file, start_time, end_time, callback, opts)
  opts = opts or {}
  local num_logs = opts.num_logs
  local exclude_logs = opts.exclude_logs or 0

  start_time = exports.normalized_time(start_time or '')
  end_time = exports.normalized_time(end_time or '')
  if end_time == '' then end_time = nil end

  if log_file == '-' or log_file == '' then
    exports.iterate_log(io.stdin, start_time, end_time, callback, opts)
  else
    local err, st = rspamd_util.stat(log_file)
    if err then
      io.stderr:write(string.format("Cannot stat %s: %s\n", log_file, err))
      os.exit(1)
    end

    if st.type == 'directory' then
      local logs = exports.get_logfiles_list(log_file, num_logs, exclude_logs)
      for idx, fname in ipairs(logs) do
        local path = log_file .. '/' .. fname
        local h, open_err = exports.open_log_file(path)
        if not h then
          io.stderr:write(string.format("Cannot open %s: %s\n", path, open_err or 'unknown error'))
        else
          if isatty then
            io.stderr:write(string.format("\027[J  Parsing log files: [%d/%d] %s\027[G",
              idx, #logs, fname))
          else
            io.stderr:write(string.format("  Parsing log files: [%d/%d] %s\n",
              idx, #logs, fname))
          end
          exports.reset_spinner()
          exports.spinner()
          exports.iterate_log(h, start_time, end_time, callback, opts)
          h:close()
        end
      end
      if isatty then
        io.stderr:write("\027[J\027[G")
      end
    else
      local h, open_err = exports.open_log_file(log_file)
      if not h then
        io.stderr:write(string.format("Cannot open %s: %s\n", log_file, open_err or 'unknown error'))
        os.exit(1)
      end
      exports.reset_spinner()
      exports.spinner()
      exports.iterate_log(h, start_time, end_time, callback, opts)
      h:close()
    end
  end
end

return exports
