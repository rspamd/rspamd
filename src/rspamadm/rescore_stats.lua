local rescore_utility = require "rescore_utility"
local argparse = require "argparse"

local function write_statistics(file_stats, all_symbol_stats, threshold)

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
			     rescore_utility.round(symbol_stats.overall, 2),
			     rescore_utility.round(symbol_stats.spam_percent, 2),
			     rescore_utility.round(symbol_stats.ham_percent, 2),
			     rescore_utility.round(symbol_stats.spam_overall, 2)))
   end

end			     

local parser = argparse() {
   name = "statistics",
   description = "Generate statistics from log files"
			  }

parser:argument("path", "Path to log file")
parser:option("-t --threshold", "Threshold for spam [Default: 10]", 10, tonumber)

local args = parser:parse()

local logs = rescore_utility.read_log_file(args.path)

file_stats, all_symbol_stats = rescore_utility.generate_statistics_from_logs(logs, args.threshold)

write_statistics(file_stats, all_symbol_stats, args.threshold)
