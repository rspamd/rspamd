local lua_util = require "lua_util"
local rspamd_util = require "rspamd_util"
local fun = require "fun"

local utility = {}

function utility.get_all_symbols(logs, ignore_symbols)
  -- Returns a list of all symbols

  local symbols_set = {}

  for _, line in pairs(logs) do
    line = lua_util.rspamd_str_split(line, " ")
    for i=4,(#line-2) do
      line[i] = line[i]:gsub("%s+", "")
      if not symbols_set[line[i]] then
        symbols_set[line[i]] = true
      end
    end
  end

  local all_symbols = {}

  for symbol, _ in pairs(symbols_set) do
    if not ignore_symbols[symbol] then
      all_symbols[#all_symbols + 1] = symbol
    end
  end

  table.sort(all_symbols)

  return all_symbols
end

function utility.read_log_file(file)

  local lines = {}

  file = assert(io.open(file, "r"))

  for line in file:lines() do
    lines[#lines + 1] = line
  end

  io.close(file)

  return lines
end

function utility.get_all_logs(dir_path)
  -- Reads all log files in the directory and returns a list of logs.

  if dir_path:sub(#dir_path, #dir_path) == "/" then
    dir_path = dir_path:sub(1, #dir_path -1)
  end

  local files = rspamd_util.glob(dir_path .. "/*.log")
  local all_logs = {}

  for _, file in pairs(files) do
    local logs = utility.read_log_file(file)
    for _, log_line in pairs(logs) do
      all_logs[#all_logs + 1] = log_line
    end
  end

  return all_logs
end

function utility.get_all_symbol_scores(conf, ignore_symbols)
  local counters = conf:get_symbols_counters()

  return fun.tomap(fun.map(function(elt)
    return elt['symbol'],elt['weight']
  end, fun.filter(function(elt)
    return not ignore_symbols[elt['symbol']]
  end, counters)))
end

function utility.generate_statistics_from_logs(logs, threshold)

  -- Returns file_stats table and list of symbol_stats table.

  local file_stats = {
    no_of_emails = 0,
    no_of_spam = 0,
    no_of_ham = 0,
    spam_percent = 0,
    ham_percent = 0,
    true_positives = 0,
    true_negatives = 0,
    false_negative_rate = 0,
    false_positive_rate = 0,
    overall_accuracy = 0,
    fscore = 0,
    avg_scan_time = 0,
    slowest_file = nil,
    slowest = 0
  }

  local all_symbols_stats = {}
  local all_fps = {}
  local all_fns = {}

  local false_positives = 0
  local false_negatives = 0
  local true_positives = 0
  local true_negatives = 0
  local no_of_emails = 0
  local no_of_spam = 0
  local no_of_ham = 0

  for _, log in pairs(logs) do
    log = lua_util.rspamd_str_trim(log)
    log = lua_util.rspamd_str_split(log, " ")

    local is_spam = (log[1] == "SPAM")
    local score = tonumber(log[2])

    no_of_emails = no_of_emails + 1

    if is_spam then
      no_of_spam = no_of_spam + 1
    else
      no_of_ham = no_of_ham + 1
    end

    if is_spam and (score >= threshold) then
      true_positives = true_positives + 1
    elseif is_spam and (score < threshold) then
      false_negatives = false_negatives + 1
      table.insert(all_fns, log[#log])
    elseif not is_spam and (score >= threshold) then
      false_positives = false_positives + 1
      table.insert(all_fps, log[#log])
    else
      true_negatives = true_negatives + 1
    end

    for i=4, (#log-2) do
      if all_symbols_stats[log[i]] == nil then
        all_symbols_stats[log[i]] = {
          name = log[i],
          no_of_hits = 0,
          spam_hits = 0,
          ham_hits = 0,
          spam_overall = 0
        }
      end

      all_symbols_stats[log[i]].no_of_hits =
      all_symbols_stats[log[i]].no_of_hits + 1

      if is_spam then
        all_symbols_stats[log[i]].spam_hits =
        all_symbols_stats[log[i]].spam_hits + 1
      else
        all_symbols_stats[log[i]].ham_hits =
        all_symbols_stats[log[i]].ham_hits + 1
      end

      -- Find slowest message
      if (tonumber(log[#log-1]) > tonumber(file_stats.slowest)) then
          file_stats.slowest = tostring(tonumber(log[#log-1]))
          file_stats.slowest_file = log[#log]
      end
    end
  end

  -- Calculating file stats

  file_stats.no_of_ham = no_of_ham
  file_stats.no_of_spam = no_of_spam
  file_stats.no_of_emails = no_of_emails
  file_stats.true_positives = true_positives
  file_stats.true_negatives = true_negatives

  if no_of_emails > 0 then
    file_stats.spam_percent = no_of_spam * 100 / no_of_emails
    file_stats.ham_percent = no_of_ham * 100 / no_of_emails
    file_stats.overall_accuracy = (true_positives + true_negatives) * 100 /
        no_of_emails
  end

  if no_of_ham > 0 then
    file_stats.false_positive_rate = false_positives * 100 / no_of_ham
  end

  if no_of_spam > 0 then
    file_stats.false_negative_rate = false_negatives * 100 / no_of_spam
  end

  file_stats.fscore = 2 * true_positives / (2
      * true_positives
      + false_positives
      + false_negatives)

  -- Calculating symbol stats

  for _, symbol_stats in pairs(all_symbols_stats) do
    symbol_stats.spam_percent = symbol_stats.spam_hits * 100 / no_of_spam
    symbol_stats.ham_percent = symbol_stats.ham_hits * 100 / no_of_ham
    symbol_stats.overall = symbol_stats.no_of_hits * 100 / no_of_emails
    symbol_stats.spam_overall = symbol_stats.spam_percent /
        (symbol_stats.spam_percent + symbol_stats.ham_percent)
  end

  return file_stats, all_symbols_stats, all_fps, all_fns
end

return utility
