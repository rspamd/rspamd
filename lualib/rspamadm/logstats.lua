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
local ucl = require "ucl"
local log_utils = require "lua_log_utils"

local parser = argparse()
  :name "rspamadm logstats"
  :description "Analyze Rspamd rules by parsing log files"
  :help_description_margin(32)

parser:option "-l --log"
  :description "Log file or directory to read (stdin by default)"
  :argname "<file>"
  :default ""
parser:option "-r --reject-score"
  :description "Reject threshold"
  :argname "<score>"
  :default "15.0"
  :convert(tonumber)
parser:option "-j --junk-score"
  :description "Junk score threshold"
  :argname "<score>"
  :default "6.0"
  :convert(tonumber)
parser:option "-s --symbol"
  :description "Check specified symbol (regexp, '.*' by default)"
  :argname "<sym>"
  :count "*"
parser:option "-S --symbol-bidir"
  :description "Bidirectional symbol (splits into SYM_SPAM/SYM_HAM)"
  :argname "<sym>"
  :count "*"
parser:option "-X --exclude"
  :description "Exclude log lines if symbol fires"
  :argname "<sym>"
  :count "*"
parser:option "--ignore"
  :description "Ignore symbol in correlations"
  :argname "<sym>"
  :count "*"
parser:option "-g --group"
  :description "Group symbols (comma-separated)"
  :argname "<syms>"
  :count "*"
parser:option "--mult"
  :description "Multiply symbol score (sym=number)"
  :argname "<sym=num>"
  :count "*"
parser:option "-a --alpha-score"
  :description "Ignore score threshold"
  :argname "<score>"
  :default "0.1"
  :convert(tonumber)
parser:flag "-c --correlations"
  :description "Enable correlations report"
parser:option "--nrelated"
  :description "Number of related symbols to show"
  :argname "<n>"
  :default "10"
  :convert(tonumber)
parser:option "--search-pattern"
  :description "Do not process input until pattern is found"
  :argname "<pattern>"
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
parser:flag "--json"
  :description "Print JSON output"

local function is_ignored(sym, ignored_list)
  for _, ex in ipairs(ignored_list) do
    local re = rspamd_regexp.create('^' .. ex .. '$')
    if re and re:match(sym) then
      return true
    end
  end
  return false
end

local function gen_related(htb, target_sym, nrelated)
  local sorted = {}
  for sym, count in pairs(htb) do
    if sym ~= target_sym then
      table.insert(sorted, { sym, count })
    end
  end
  table.sort(sorted, function(a, b) return a[2] > b[2] end)

  local result = {}
  for i = 1, math.min(#sorted, nrelated) do
    result[i] = sorted[i]
  end
  return result
end

local function stringify_related(ar, total)
  local parts = {}
  for _, elt in ipairs(ar) do
    table.insert(parts, string.format("\t%s(%d: %.1f%%)",
      elt[1], elt[2], elt[2] / (total * 1.0) * 100.0))
  end
  return table.concat(parts, "\n")
end

local function parse_mult_options(mult_list)
  local result = {}
  for _, m in ipairs(mult_list) do
    local sym, num = m:match('^([^=]+)=(.+)$')
    if sym and num then
      result[sym] = tonumber(num) or 1.0
    end
  end
  return result
end

local re_sym_parse = rspamd_regexp.create('/^([^(]+)(\\(([^)]+)\\))?/')

local function process_related(symbols, target, source, groups, symbols_ignored,
                               symbols_mult, diff_alpha, bidir_match)
  for _, s in ipairs(symbols) do
    local results = re_sym_parse:search(s, false, true)
    if not results or #results == 0 then
      goto continue
    end
    local caps = results[1]
    if not caps or #caps < 2 then
      goto continue
    end

    local sym_name = tostring(caps[2])
    local sym_score = 0

    if groups[sym_name] then
      sym_name = groups[sym_name]
    end

    if source == sym_name then
      goto continue
    end

    if is_ignored(sym_name, symbols_ignored) then
      goto continue
    end

    if caps[4] then
      sym_score = (tonumber(tostring(caps[4])) or 0) * (symbols_mult[sym_name] or 1.0)
      if math.abs(sym_score) < diff_alpha then
        goto continue
      end
      local bm = bidir_match[sym_name]
      if bm then
        if sym_score >= 0 then
          sym_name = bm.spam
        else
          sym_name = bm.ham
        end
      end
    end

    target[sym_name] = (target[sym_name] or 0) + 1

    ::continue::
  end
end

local function handler(args)
  local res = parser:parse(args)

  local reject_score = res['reject_score']
  local junk_score = res['junk_score']
  local symbols_search = res['symbol'] or {}
  local symbols_bidir = res['symbol_bidir'] or {}
  local symbols_exclude = res['exclude'] or {}
  local symbols_ignored = res['ignore'] or {}
  local symbols_groups = res['group'] or {}
  local symbols_mult = parse_mult_options(res['mult'] or {})
  local diff_alpha = res['alpha_score']
  local correlations = res['correlations']
  local nrelated = res['nrelated']
  local json_output = res['json']

  local bidir_match = {}
  for _, s in ipairs(symbols_bidir) do
    bidir_match[s] = {
      spam = s .. '_SPAM',
      ham = s .. '_HAM',
    }
    local found = false
    for _, existing in ipairs(symbols_search) do
      if existing == s then found = true; break end
    end
    if not found then
      table.insert(symbols_search, s)
    end
  end

  local groups = {}
  local group_id = 0
  for _, g in ipairs(symbols_groups) do
    local syms = {}
    for sym in g:gmatch('[^,]+') do
      table.insert(syms, sym)
    end
    local group_name = 'group' .. group_id
    group_id = group_id + 1
    for _, s in ipairs(syms) do
      groups[s] = group_name
      local found = false
      for _, existing in ipairs(symbols_search) do
        if existing == s then found = true; break end
      end
      if not found then
        table.insert(symbols_search, s)
      end
    end
  end

  if #symbols_search == 0 then
    symbols_search = { '.*' }
  end

  -- Compile search patterns
  local search_res = {}
  for _, s in ipairs(symbols_search) do
    local re = rspamd_regexp.create(s)
    if re then
      table.insert(search_res, { pattern = s, re = re })
    end
  end

  -- Compile exclude patterns
  local exclude_res = {}
  for _, ex in ipairs(symbols_exclude) do
    local re = rspamd_regexp.create('^' .. ex)
    if re then
      table.insert(exclude_res, re)
    end
  end

  local total = 0
  local total_spam = 0
  local total_junk = 0
  local sym_res = {}
  local actions = {}
  local timeStamp = {}
  local scanTime = { max = 0, total = 0 }

  local function process_callback(ts, act, score, symbols_str, scan_time)
    -- Split symbols: split on ,  but accounting for {options} blocks
    local symbols_raw = {}
    local tmp = symbols_str
    -- Split handling {}-enclosed options
    while tmp and #tmp > 0 do
      local sym_part, rest = tmp:match('^([^,{]+%b{})(.*)')
      if not sym_part then
        sym_part, rest = tmp:match('^([^,]+)(.*)')
      end
      if sym_part then
        table.insert(symbols_raw, sym_part)
        if rest and rest:sub(1, 1) == ',' then
          rest = rest:sub(2)
        end
        tmp = rest
      else
        break
      end
    end

    -- Check excludes
    for _, sym in ipairs(symbols_raw) do
      for _, ex_re in ipairs(exclude_res) do
        if ex_re:match(sym) then
          return
        end
      end
    end

    -- Update timestamps
    if not timeStamp['end'] or ts > timeStamp['end'] then
      timeStamp['end'] = ts
    end
    if not timeStamp['start'] or ts < timeStamp['start'] then
      timeStamp['start'] = ts
    end

    -- Update scan times
    if not scanTime['min'] or scan_time < scanTime['min'] then
      scanTime['min'] = scan_time
    end
    if scan_time > scanTime['max'] then
      scanTime['max'] = scan_time
    end
    scanTime['total'] = scanTime['total'] + scan_time

    actions[act] = (actions[act] or 0) + 1
    total = total + 1

    local is_spam = false
    local is_junk = false
    if score >= reject_score then
      total_spam = total_spam + 1
      is_spam = true
    elseif score >= junk_score then
      total_junk = total_junk + 1
      is_junk = true
    end

    local sym_names = {}

    for _, sr in ipairs(search_res) do
      for _, sym in ipairs(symbols_raw) do
        if sr.re:match(sym) then
          local results = re_sym_parse:search(sym, false, true)
          if not results or #results == 0 then
            goto continue_sym
          end
          local caps = results[1]
          if not caps or #caps < 2 then
            goto continue_sym
          end

          local sym_name = tostring(caps[2])
          local sym_score = 0
          local orig_name = sym_name

          if caps[4] then
            sym_score = (tonumber(tostring(caps[4])) or 0) * (symbols_mult[sym_name] or 1.0)
            if math.abs(sym_score) < diff_alpha then
              goto continue_sym
            end
            local bm = bidir_match[sym_name]
            if bm then
              if sym_score >= 0 then
                sym_name = bm.spam
              else
                sym_name = bm.ham
              end
            end
          end

          -- Check that original name matches the search pattern
          local match_re = rspamd_regexp.create('^' .. sr.pattern)
          if match_re and not match_re:match(orig_name) then
            goto continue_sym
          end

          if groups[sr.pattern] then
            sym_name = groups[sr.pattern]
          end

          table.insert(sym_names, sym_name)

          if not sym_res[sym_name] then
            sym_res[sym_name] = {
              hits = 0,
              spam_hits = 0,
              junk_hits = 0,
              spam_change = 0,
              junk_change = 0,
              weight = 0,
              corr = {},
              symbols_met_spam = {},
              symbols_met_ham = {},
              symbols_met_junk = {},
            }
          end

          local r = sym_res[sym_name]
          r.hits = r.hits + 1
          r.weight = r.weight + sym_score

          if is_spam then
            r.spam_hits = r.spam_hits + 1
            if correlations then
              process_related(symbols_raw, r.symbols_met_spam, sym_name,
                groups, symbols_ignored, symbols_mult, diff_alpha, bidir_match)
            end
          elseif is_junk then
            r.junk_hits = r.junk_hits + 1
            if correlations then
              process_related(symbols_raw, r.symbols_met_junk, sym_name,
                groups, symbols_ignored, symbols_mult, diff_alpha, bidir_match)
            end
          else
            if correlations then
              process_related(symbols_raw, r.symbols_met_ham, sym_name,
                groups, symbols_ignored, symbols_mult, diff_alpha, bidir_match)
            end
          end

          if sym_score ~= 0 then
            local score_without = score - sym_score
            if sym_score > 0 then
              if is_spam and score_without < reject_score then
                r.spam_change = r.spam_change + 1
              end
              if is_junk and score_without < junk_score then
                r.junk_change = r.junk_change + 1
              end
            else
              if not is_spam and score_without >= reject_score then
                r.spam_change = r.spam_change + 1
              end
              if not is_junk and score_without >= junk_score then
                r.junk_change = r.junk_change + 1
              end
            end
          end
          ::continue_sym::
        end
      end
    end

    if correlations then
      for _, sym in ipairs(sym_names) do
        if not is_ignored(sym, symbols_ignored) then
          local r = sym_res[sym]
          for _, corr_sym in ipairs(sym_names) do
            if corr_sym ~= sym then
              r.corr[corr_sym] = (r.corr[corr_sym] or 0) + 1
            end
          end
        end
      end
    end
  end

  log_utils.process_logs(res['log'], res['start'] or '', res['end'], process_callback, {
    search_pattern = res['search_pattern'],
    num_logs = res['num_logs'],
    exclude_logs = res['exclude_logs'],
  })

  local total_ham = total - (total_spam + total_junk)

  if json_output then
    local result = {}
    result.total = total
    if timeStamp['start'] then
      result.start = timeStamp['start']
    end
    if timeStamp['end'] then
      result['end'] = timeStamp['end']
    end
    result.actions = actions
    result.symbols = {}

    if total > 0 then
      for s, r in pairs(sym_res) do
        if r.hits > 0 then
          local th = r.hits
          local sh = r.spam_hits
          local jh = r.junk_hits
          local hh = th - sh - jh
          local htp = (total_ham ~= 0) and (hh * 100.0 / total_ham) or 0
          local stp = (total_spam ~= 0) and (sh * 100.0 / total_spam) or 0
          local jtp = (total_junk ~= 0) and (jh * 100.0 / total_junk) or 0

          local sym_data = {
            avg_weight = r.weight / th,
            hits = th,
            hits_percentage = th / total,
            spam_hits = sh,
            spam_to_total = sh / th,
            spam_percentage = stp / 100.0,
            ham_hits = hh,
            ham_to_total = hh / th,
            ham_percentage = htp / 100.0,
            junk_hits = jh,
            junk_to_total = jh / th,
            junk_percentage = jtp / 100.0,
          }

          if r.weight ~= 0 then
            sym_data.spam_change = r.spam_change
            sym_data.junk_change = r.junk_change
          end

          if correlations then
            local corr_data = {}
            for cs, hits in pairs(r.corr) do
              local corr_prob = hits / total
              local sym_prob = r.hits / total
              corr_data[cs] = corr_prob / sym_prob
            end
            sym_data.correllations = corr_data
          end

          result.symbols[s] = sym_data
        end
      end
    end

    io.write(ucl.to_format(result, 'json'))
    io.write('\n')
  else
    -- Human-readable output
    if total > 0 then
      for s, r in pairs(sym_res) do
        if r.hits > 0 then
          local th = r.hits
          local sh = r.spam_hits
          local jh = r.junk_hits
          local hh = th - sh - jh
          local htp = (total_ham ~= 0) and (hh * 100.0 / total_ham) or 0
          local stp = (total_spam ~= 0) and (sh * 100.0 / total_spam) or 0
          local jtp = (total_junk ~= 0) and (jh * 100.0 / total_junk) or 0

          io.write(string.format(
            "%s   avg. weight %.3f, hits %d(%.3f%%):\n" ..
            "  Ham  %7.3f%%, %6d/%-6d (%7.3f%%)\n" ..
            "  Spam %7.3f%%, %6d/%-6d (%7.3f%%)\n" ..
            "  Junk %7.3f%%, %6d/%-6d (%7.3f%%)\n",
            s, r.weight / th, th, (th / total * 100),
            (hh / th * 100), hh, total_ham, htp,
            (sh / th * 100), sh, total_spam, stp,
            (jh / th * 100), jh, total_junk, jtp))

          local schp = (total_spam > 0) and (r.spam_change / total_spam * 100.0) or 0
          local jchp = (total_junk > 0) and (r.junk_change / total_junk * 100.0) or 0

          if r.weight ~= 0 then
            if r.weight > 0 then
              io.write(string.format(
                "\nSpam changes (ham/junk -> spam): %6d/%-6d (%7.3f%%)\n" ..
                "Spam  changes / total spam hits: %6d/%-6d (%7.3f%%)\n" ..
                "Junk changes      (ham -> junk): %6d/%-6d (%7.3f%%)\n" ..
                "Junk  changes / total junk hits: %6d/%-6d (%7.3f%%)\n",
                r.spam_change, th, (r.spam_change / th * 100),
                r.spam_change, total_spam, schp,
                r.junk_change, th, (r.junk_change / th * 100),
                r.junk_change, total_junk, jchp))
            else
              io.write(string.format(
                "\nSpam changes (spam -> junk/ham): %6d/%-6d (%7.3f%%)\n" ..
                "Spam changes / total spam hits : %6d/%-6d (%7.3f%%)\n" ..
                "Junk changes (junk -> ham)     : %6d/%-6d (%7.3f%%)\n" ..
                "Junk changes / total junk hits : %6d/%-6d (%7.3f%%)\n",
                r.spam_change, th, (r.spam_change / th * 100),
                r.spam_change, total_spam, schp,
                r.junk_change, th, (r.junk_change / th * 100),
                r.junk_change, total_junk, jchp))
            end
          end

          if correlations then
            io.write("Correlations report:\n")
            for cs, _ in pairs(r.corr) do
              local corr_prob = r.hits / total
              local merged_hits = 0
              if r.symbols_met_spam[cs] then
                merged_hits = merged_hits + r.symbols_met_spam[cs]
              end
              if r.symbols_met_junk[cs] then
                merged_hits = merged_hits + r.symbols_met_junk[cs]
              end
              if r.symbols_met_ham[cs] then
                merged_hits = merged_hits + r.symbols_met_ham[cs]
              end
              if merged_hits > 0 then
                io.write(string.format("Probability of %s when %s fires: %.3f\n",
                  cs, s, ((merged_hits / total) / corr_prob)))
              end
            end

            local spam_related = gen_related(r.symbols_met_spam, s, nrelated)
            local junk_related = gen_related(r.symbols_met_junk, s, nrelated)
            local ham_related = gen_related(r.symbols_met_ham, s, nrelated)

            io.write("Related symbols report:\n")
            io.write(string.format("Top related in spam:\n %s\n",
              stringify_related(spam_related, r.spam_hits)))
            io.write(string.format("Top related in junk:\n %s\n",
              stringify_related(junk_related, r.junk_hits)))
            io.write(string.format("Top related in ham:\n %s\n",
              stringify_related(ham_related, r.hits - r.spam_hits - r.junk_hits)))
          end
        else
          io.write(string.format("Symbol %s has not been met\n", s))
        end

        io.write(string.rep('-', 80) .. '\n')
      end
    end

    io.write(string.format("\n=== Summary %s\nMessages scanned: %d",
      string.rep('=', 68), total))
    if timeStamp['start'] then
      io.write(string.format(" [ %s / %s ]\n", timeStamp['start'], timeStamp['end']))
    else
      io.write('\n')
    end
    io.write('\n')
    local sorted_actions = {}
    for a, _ in pairs(actions) do
      table.insert(sorted_actions, a)
    end
    table.sort(sorted_actions)
    for _, a in ipairs(sorted_actions) do
      io.write(string.format("%11s: %6.2f%%, %d\n", a, 100 * actions[a] / total, actions[a]))
    end
    io.write('\n')
    if scanTime['min'] then
      io.write(string.format("scan time min/avg/max = %.2f/%.2f/%.2f s\n",
        scanTime['min'] / 1000,
        (total > 0) and (scanTime['total'] / total / 1000) or 0,
        scanTime['max'] / 1000))
    end
    io.write(string.rep('=', 80) .. '\n')
  end
end

return {
  handler = handler,
  description = parser._description,
  name = 'logstats'
}
