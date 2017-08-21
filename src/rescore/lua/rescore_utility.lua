local json = require "json"

local utility = {}

function utility.round(num, places)
   return string.format("%." .. (places or 0) .. "f", num)
end

function utility.string_split(str, delimiter)   
   local t={}; i = 1
   for s in string.gmatch(str, "([^"..delimiter.."]+)") do
      t[i] = s
      i = i + 1
   end

   return t
end

function utility.print_table(_table)
   for key, value in pairs(_table) do
      print(key, value)
   end
end

function utility.get_all_symbols(logs)
   -- Returns a list of all symbols
   
   local symbols_set = {}
   local cnt = 0
   
   for _, line in pairs(logs) do
      line = utility.string_split(line, " ")
      for i=4,#line do
	 line[i] = line[i]:gsub("%s+", "")
	 if not symbols_set[line[i]] then
	    symbols_set[line[i]] = true
	 end
      end
   end

   local all_symbols = {}
   
   for symbol, value in pairs(symbols_set) do
      all_symbols[#all_symbols + 1] = symbol
   end

   table.sort(all_symbols)
   
   return all_symbols
end

function utility.list_directory(dir_path)

   local files = {}
   local i = 0
   
   -- finds all files, ignores dot files.
   local f = io.popen(string.format('find %s -type f \\( ! -iname ".*" \\)', dir_path))
   
   for file in f:lines() do
      i = i + 1
      files[i] = file
   end

   return files
end

function utility.read_log_file(file)

   local lines = {}

   local file = assert(io.open(file, "r"))

   for line in file:lines() do
      lines[#lines + 1] = line
   end

   io.close(file)

   return lines
end
   
function utility.get_all_logs(dir_path)
   -- Reads all log files in the directory and returns a list of logs.

   local files = utility.list_directory(dir_path)
   local all_logs = {}
   local i = 0

   for _, file in pairs(files) do
      local logs = utility.read_log_file(file)
      for _, log_line in pairs(logs) do
	 all_logs[#all_logs + 1] = log_line
      end      
   end

   return all_logs
end

function utility.get_all_symbol_scores()

   local output = assert(io.popen("rspamc counters -j --compact"))
   output = output:read("*all")
   output = json.decode(output)

   symbol_scores = {}
   
   for _, symbol_info in pairs(output) do
      symbol_scores[symbol_info.symbol] = symbol_info.weight
   end

   return symbol_scores
end

function utility.trim(str)

   return (str:gsub("^%s*(.-)%s*$", "%1"))

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
      fscore = 0
   }

   local all_symbols_stats = {}

   local false_positives = 0
   local false_negatives = 0
   local true_positives = 0
   local true_negatives = 0
   local no_of_emails = 0
   local no_of_spam = 0
   local no_of_ham = 0

   for _, log in pairs(logs) do
      log = utility.trim(log)
      log = utility.string_split(log, " ")
      
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
      elseif not is_spam and (score >= threshold) then
	 false_positives = false_positives + 1
      else
	 true_negatives = true_negatives + 1
      end

      for i=4, #log do	 
	 if all_symbols_stats[log[i]] == nil then
	    all_symbols_stats[log[i]] =
	       {
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
      end
   end

   -- Calculating file stats
   
   file_stats.no_of_ham = no_of_ham
   file_stats.no_of_spam = no_of_spam
   file_stats.no_of_emails = no_of_emails
   file_stats.true_positives = true_postives
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
   
   for symbol, symbol_stats in pairs(all_symbols_stats) do
      symbol_stats.spam_percent = symbol_stats.spam_hits * 100 / no_of_spam
      symbol_stats.ham_percent = symbol_stats.ham_hits * 100 / no_of_ham
      symbol_stats.overall = symbol_stats.no_of_hits * 100 / no_of_emails
      symbol_stats.spam_overall = symbol_stats.spam_percent /
	 (symbol_stats.spam_percent + symbol_stats.ham_percent)
   end
   
   return file_stats, all_symbols_stats
end

return utility
