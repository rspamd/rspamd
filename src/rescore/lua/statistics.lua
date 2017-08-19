local utility = require "utility"
local argparse = require "argparse"

function generate_statistics(logs, threshold)

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
      overall_accuracy = 0
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

function write_statistics(file_stats, all_symbol_stats, threshold)

   local file_stat_format = [[
Number of emails: %d
Number of spam: %d
Number of ham: %d
%% of spam: %.2f %%
%% of ham: %.2f %%
False positive rate: %.2f %%
False negative rate: %.2f %%
Overall accuracy: %.2f %%
]]

   io.write("Statistics at threshold: " .. threshold .. "\n")
   
   io.write("File statistics\n\n")
   io.write(string.format(file_stat_format,
	       file_stats.no_of_emails,
	       file_stats.no_of_spam,
	       file_stats.no_of_ham,
	       file_stats.spam_percent,
	       file_stats.ham_percent,
	       file_stats.false_positive_rate,
	       file_stats.false_negative_rate,
	       file_stats.overall_accuracy))

   local symbol_stat_format = "%-35s %-9s %-8s %-8s %-5s\n"
   io.write("\nSymbol statistics\n")
   io.write(string.format(symbol_stat_format,
			  "NAME",
			  "OVERALL",
			  "SPAM %",
			  "HAM %",
			  "SO"))
   
   for symbol, symbol_stats in pairs(all_symbol_stats) do
      io.write(string.format(symbol_stat_format,
			     symbol_stats.name,
			     utility.round(symbol_stats.overall, 2),
			     utility.round(symbol_stats.spam_percent, 2),
			     utility.round(symbol_stats.ham_percent, 2),
			     utility.round(symbol_stats.spam_overall, 2)))
   end

end			     

local parser = argparse() {
   name = "statistics",
   description = "Generate statistics from log files"
			  }
parser:argument("path", "Path to log file")
parser:option("-t --threshold", "Threshold for spam [Default: 10]", 10, tonumber)

local args = parser:parse()

local logs = utility.read_log_file(args.path)

file_stats, all_symbol_stats = generate_statistics(logs, args.threshold)

write_statistics(file_stats, all_symbol_stats, args.threshold)
