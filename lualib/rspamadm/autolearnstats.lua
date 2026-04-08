--[[
Copyright (c) 2026, Alexander Moisseev <moiseev@mezonplus.ru>

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
local rspamd_util = require "rspamd_util"
local log_utils = require "lua_log_utils"
local ansicolors = require "ansicolors"

local parser = argparse()
  :name "rspamadm autolearnstats"
  :description "Report Bayes autolearn events from rspamd log"
  :help_description_margin(32)

parser:argument "log"
  :description "Log file or directory to read (stdin if omitted)"
  :args "?"
  :default ""
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

-- Lua-side "can autolearn" log line (lua_bayes_learn.lua)
-- Module is always "lua" regardless of worker type.
-- Captures: req_id, from, verdict, score, op, threshold, mime_rcpts
local re_lua = rspamd_regexp.create(
  '/\\([^)]+\\) (<[0-9a-fA-F]+>); lua; lua_bayes_learn\\.lua:\\d+: ' ..
  'id: <[^>]*>, from: <([^>]*)>: can autolearn (\\w+): score (-?[\\d.]+) ' ..
  '([^\\s,]+) (-?[\\d.]+), mime_rcpts: <([^>]*)>/')

-- C-side "autolearn confirmed" line (rspamd_stat_check_autolearn).
-- Module is "proxy" for rspamd_proxy worker, "task" for normal worker.
-- Matched only against the success messages, which start with "<MSG-ID>: autolearn",
-- to avoid false positives from error messages emitted by the same function.
-- Captures: req_id
local re_confirmed = rspamd_regexp.create(
  '/\\([^)]+\\) (<[0-9a-fA-F]+>); \\w+; rspamd_stat_check_autolearn: <[^>]*>: autolearn /')

-- Task result line for sender IP extraction (rspamd_task_write_log)
-- Module is "proxy" for rspamd_proxy worker, "task" for normal worker.
-- Captures: req_id, ip
local re_ip = rspamd_regexp.create(
  '/\\([^)]+\\) (<[0-9a-fA-F]+>); \\w+; rspamd_task_write_log: ' ..
  'id: [^,]+,(?:\\s*qid: [^,]+,)?\\s*ip: ([^,\\s]+),/')

-- Color support: only when stdout is a TTY
local isatty = rspamd_util.isatty()

-- lua_bayes_learn.lua only logs "can autolearn" for spam, junk, and ham.
local verdict_colors = {
  spam = ansicolors.red,
  junk = ansicolors.yellow,
  ham  = ansicolors.green,
}

local function get_verdict_color(verdict)
  return verdict_colors[verdict] or ansicolors.white
end

local function colored(s, color)
  if not isatty or not color or color == '' then return s end
  return color .. s .. ansicolors.reset
end

local function pad(s, n)
  local len = #s
  if len >= n then return s end
  return s .. string.rep(' ', n - len)
end

local function iterate_bayes_log(handle, start_time, end_time, candidates, learned, ips)
  local ts_format = nil

  for line in handle:lines() do
    log_utils.spinner()

    if not ts_format then
      local fmt = log_utils.detect_log_format(line)
      if fmt == false then
        io.stderr:write("Unknown log format\n")
        return
      elseif fmt == nil then
        goto continue
      else
        ts_format = fmt
      end
    end

    -- "can autolearn" line: collect candidate with full metadata
    local r = re_lua:search(line, false, true)
    if r and r[1] then
      local caps = r[1]
      local ts = log_utils.extract_timestamp(line, ts_format)
      if ts then
        if start_time ~= '' and ts < start_time then goto continue end
        if end_time and ts > end_time then goto continue end
        local req_id = tostring(caps[2])
        if candidates[req_id] then
          io.stderr:write(string.format(
            "Warning: duplicate req_id %s, overwriting earlier entry\n", req_id))
        end
        candidates[req_id] = {
          ts      = ts,
          from    = tostring(caps[3]),
          verdict = tostring(caps[4]),
          score   = tostring(caps[5]),
          op      = tostring(caps[6]),
          thr     = tostring(caps[7]),
          rcpts   = tostring(caps[8]),
        }
      end
      goto continue
    end

    -- "autolearn confirmed" line: mark request as actually learned
    r = re_confirmed:search(line, false, true)
    if r and r[1] then
      learned[tostring(r[1][2])] = true
      goto continue
    end

    -- Task result line: extract sender IP.
    -- No time-window filter here: only IPs for req_ids present in candidates
    -- (which are already time-filtered) will be used in the output.
    r = re_ip:search(line, false, true)
    if r and r[1] then
      ips[tostring(r[1][2])] = tostring(r[1][3])
    end

    ::continue::
  end
end

local function process_logs(log_file, start_time, end_time, candidates, learned, ips, opts)
  opts = opts or {}
  local num_logs = opts.num_logs
  local exclude_logs = opts.exclude_logs or 0

  start_time = log_utils.normalized_time(start_time or '')
  end_time = log_utils.normalized_time(end_time or '')
  if end_time == '' then end_time = nil end

  if not log_file or log_file == '-' or log_file == '' then
    iterate_bayes_log(io.stdin, start_time, end_time, candidates, learned, ips)
    return
  end

  local err, st = rspamd_util.stat(log_file)
  if err then
    io.stderr:write(string.format("Cannot stat %s: %s\n", log_file, err))
    os.exit(1)
  end

  if st.type == 'directory' then
    local logs = log_utils.get_logfiles_list(log_file, num_logs, exclude_logs)
    for idx, fname in ipairs(logs) do
      local path = log_file .. '/' .. fname
      local h, open_err = log_utils.open_log_file(path)
      if not h then
        io.stderr:write(string.format("Cannot open %s: %s\n", path, open_err or 'unknown'))
      else
        if isatty then
          io.stderr:write(string.format("\027[J  Parsing log files: [%d/%d] %s\027[G",
            idx, #logs, fname))
        else
          io.stderr:write(string.format("  Parsing log files: [%d/%d] %s\n",
            idx, #logs, fname))
        end
        log_utils.reset_spinner()
        iterate_bayes_log(h, start_time, end_time, candidates, learned, ips)
        h:close()
      end
    end
    if isatty then io.stderr:write("\027[J\027[G") end
  else
    local h, open_err = log_utils.open_log_file(log_file)
    if not h then
      io.stderr:write(string.format("Cannot open %s: %s\n", log_file, open_err or 'unknown'))
      os.exit(1)
    end
    log_utils.reset_spinner()
    iterate_bayes_log(h, start_time, end_time, candidates, learned, ips)
    h:close()
  end
end

local function handler(args)
  local res = parser:parse(args)

  local candidates = {}
  local learned = {}
  local ips = {}

  -- res['end'] uses bracket syntax because 'end' is a Lua reserved keyword.
  process_logs(
    res['log'],
    res['start'] or '',
    res['end'] or '',
    candidates, learned, ips,
    {
      num_logs     = res['num_logs'],
      exclude_logs = res['exclude_logs'] or 0,
    }
  )

  local sorted = {}
  for req_id, c in pairs(candidates) do
    table.insert(sorted, { req_id = req_id, c = c })
  end
  table.sort(sorted, function(a, b) return a.c.ts < b.c.ts end)

  -- Compute column widths from actual data (plain values, no ANSI codes)
  local col = {
    verdict = #'Verd',
    score   = #'Score',
    ts      = 19,       -- timestamp format is always 19 chars
    tid     = #'Task',
    ip      = #'IP',
    from    = #'From',
    rcpts   = #'Recipients',
  }
  for _, entry in ipairs(sorted) do
    local c = entry.c
    col.verdict = math.max(col.verdict, #c.verdict)
    col.score   = math.max(col.score,   #(c.score .. c.op .. c.thr))
    col.tid     = math.max(col.tid,     #entry.req_id - 2) -- strip < >
    col.ip      = math.max(col.ip,      #(ips[entry.req_id] or '-'))
    col.from    = math.max(col.from,    #c.from)
    col.rcpts   = math.max(col.rcpts,   #c.rcpts)
  end

  local sep = '  '

  if #sorted == 0 then
    io.write('No autolearn candidates found.\n')
    return
  end

  local sep_width = 3 + #sep + col.verdict + #sep + col.score + #sep +
    col.ts + #sep + col.tid + #sep + col.ip + #sep + col.from + #sep + col.rcpts

  -- Header: [L]  Verd  Score  Timestamp  Task  IP  From  Recipients
  io.write(string.format("%-3s" .. sep .. "%-" .. col.verdict .. "s" .. sep ..
    "%-" .. col.score .. "s" .. sep .. "%-" .. col.ts .. "s" .. sep ..
    "%-" .. col.tid .. "s" .. sep .. "%-" .. col.ip .. "s" .. sep ..
    "%-" .. col.from .. "s" .. sep .. "%-" .. col.rcpts .. "s\n",
    '', 'Verd', 'Score', 'Timestamp', 'Task', 'IP', 'From', 'Recipients'))
  io.write(string.rep('-', sep_width) .. '\n')

  local n_learned = 0
  local class_stats = {}

  for _, entry in ipairs(sorted) do
    local req_id = entry.req_id
    local c = entry.c
    local tid     = req_id:gsub('[<>]', '')
    local score_str = c.score .. c.op .. c.thr
    local from_ip = ips[req_id] or '-'
    local is_learned = learned[req_id]
    local vcolor = get_verdict_color(c.verdict)

    if not class_stats[c.verdict] then
      class_stats[c.verdict] = { candidates = 0, learned = 0 }
    end
    class_stats[c.verdict].candidates = class_stats[c.verdict].candidates + 1
    if is_learned then
      n_learned = n_learned + 1
      class_stats[c.verdict].learned = class_stats[c.verdict].learned + 1
    end

    local marker = is_learned and '[L]' or '   '
    io.write(
      colored(pad(marker,    3),           is_learned and ansicolors.green or '') .. sep ..
      colored(pad(c.verdict, col.verdict), vcolor) .. sep ..
      pad(score_str, col.score) .. sep ..
      pad(c.ts,     col.ts)      .. sep ..
      pad(tid,      col.tid)     .. sep ..
      pad(from_ip,  col.ip)     .. sep ..
      pad(c.from,   col.from)   .. sep ..
      c.rcpts .. '\n'
    )
  end

  if #sorted > 0 then
    io.write(string.format("\nTotal autolearn candidates: %d  Learned: %d\n",
      #sorted, n_learned))

    local sorted_classes = {}
    for cls in pairs(class_stats) do
      table.insert(sorted_classes, cls)
    end
    table.sort(sorted_classes)

    local cls_label_w = 0
    for _, cls in ipairs(sorted_classes) do
      cls_label_w = math.max(cls_label_w, #cls)
    end
    for _, cls in ipairs(sorted_classes) do
      local s = class_stats[cls]
      io.write(colored(
        string.format("  %-" .. cls_label_w .. "s  %d candidates  /  %d learned\n",
          cls, s.candidates, s.learned),
        get_verdict_color(cls)))
    end
  end
end

return {
  handler = handler,
  description = parser._description,
  name = 'autolearnstats'
}
