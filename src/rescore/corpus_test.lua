local argparse = require "argparse"
local json = require "json"
local inspect = require "inspect"

local HAM = "HAM"
local SPAM = "SPAM"

local function scan_email(path, n_parellel, path)
   local rspamc_command = string.format("rspamc -j --compact -n %s %s", n_parellel, path)
   local result = assert(io.popen(rspamc_command))
   result = result:read("*all")
   return result
end   

local function string_split(str, delimiter)   
   local t={}; i = 1
   for s in string.gmatch(str, "([^"..delimiter.."]+)") do
      t[i] = s
      i = i + 1
   end

   return t
end

local function write_results(results, file)
   
   f = io.open(file, 'w')

   for _, result in pairs(results) do
      local log_line = string.format("%s %.2f %s", result.type, result.score, result.action)
     
      for _, sym in pairs(result.symbols) do
	 log_line = log_line .. " " .. sym
      end

      log_line = log_line .. "\r\n"
      
      f:write(log_line)
   end
   
   f:close()
end

local function encoded_json_to_log(result)
   -- Returns table containing score, action, list of symbols
   local filtered_result = {}
   result = json.decode(result)

   filtered_result.score = result.score

   local action = result.action:gsub("%s+", "_")
   filtered_result.action = action

   filtered_result.symbols = {}

   for sym, _ in pairs(result.symbols) do
      table.insert(filtered_result.symbols, sym)
   end
   
   return filtered_result   
end

local function scan_results_to_logs(results, actual_email_type)

   logs = {}
   
   results = string_split(results, "\n")

   for _, result in pairs(results) do
      local result = encoded_json_to_log(result)
      result['type'] = actual_email_type
      table.insert(logs, result)
   end

   return logs
end

local parser = argparse() {
   name = "corpus_test",
   description = "Produces log files for ham and spam corpus"
}

parser:option("-a --ham", "Ham directory", nil)
parser:option("-s --spam", "Spam directory", nil)
parser:option("-o --output", "Log output file", "results.log")
parser:option("-n", "Maximum parellel connections", 10)

local args = parser:parse()

local results = {}

local start_time = os.time()
local no_of_ham = 0
local no_of_spam = 0

if args.ham then
   io.write("Scanning ham corpus...\n")
   local ham_results = scan_email(path, args.n, args.ham)
   ham_results = scan_results_to_logs(ham_results, HAM)

   no_of_ham = #ham_results
   
   for _, result in pairs(ham_results) do
      table.insert(results, result)
   end
end

if args.spam then
   io.write("Scanning spam corpus...\n")
   local spam_results = scan_email(path, args.n, args.spam)
   spam_results = scan_results_to_logs(spam_results, SPAM)

   no_of_spam = #spam_results
   
   for _, result in pairs(spam_results) do
      table.insert(results, result)
   end
end

io.write(string.format("Writing results to %s\n", args.output))
write_results(results, args.output)

io.write("\nStats: \n")
io.write(string.format("Elapsed time: %ds\n", os.time() - start_time))
io.write(string.format("No of ham: %d\n", no_of_ham))
io.write(string.format("No of spam: %d\n", no_of_spam))

