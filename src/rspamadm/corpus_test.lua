local ucl = require "ucl"

local HAM = "HAM"
local SPAM = "SPAM"

local function scan_email(n_parellel, path)

   local rspamc_command = string.format("rspamc -j --compact -n %s %s", n_parellel, path)
   local result = assert(io.popen(rspamc_command))
   result = result:read("*all")
   return result
end   

local function write_results(results, file)
   
   local f = io.open(file, 'w')

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
   local parser = ucl.parser()

   io.write(result)
   
   local is_good, err = parser:parse_string(result)

   if not is_good then
      print(err)
      os.exit()
   end
   
   result = parser:get_object()

   io.write("good 1\n")
   for key, val in pairs(result) do 
      io.write(key)
    end

   io.write("good 2\n")

   filtered_result.score = result.score
   local action = result.action:gsub("%s+", "_")
   filtered_result.action = action

   filtered_result.symbols = {}

   for sym, _ in pairs(result.symbols) do
      table.insert(filtered_result.symbols, sym)
   end
   
   return filtered_result   
end

local function str_split (str, sep)
        
        if sep == nil then
                sep = "%s"
        end

        local results = {}
        local i = 1
        for part in string.gmatch(str, "([^"..sep.."]+)") do
                results[i] = part
                i = i + 1
        end

        return results
end

local function scan_results_to_logs(results, actual_email_type)

   local logs = {}
   
   results = str_split(results, "\n")

   if results[#results] == "" then
      results[#results] = nil
   end
   
   for _, result in pairs(results) do      
      result = encoded_json_to_log(result)
      result['type'] = actual_email_type
      table.insert(logs, result)
   end

   return logs
end

return function (_, res)
   
   local ham_directory = res['ham_directory']
   local spam_directory = res['spam_directory']
   local n_conn = 10
   local output = "results.log"

   local results = {}

   local start_time = os.time()
   local no_of_ham = 0
   local no_of_spam = 0

   if ham_directory then
      io.write("Scanning ham corpus...\n")
      local ham_results = scan_email(n_conn, ham_directory)
      ham_results = scan_results_to_logs(ham_results, HAM)

      no_of_ham = #ham_results
      
      for _, result in pairs(ham_results) do
         table.insert(results, result)
      end
   end

   if spam_directory then
      io.write("Scanning spam corpus...\n")
      local spam_results = scan_email(n_conn, spam_directory)
      spam_results = scan_results_to_logs(spam_results, SPAM)

      no_of_spam = #spam_results
      
      for _, result in pairs(spam_results) do
         table.insert(results, result)
      end
   end

   io.write(string.format("Writing results to %s\n", output))
   write_results(results, output)

   io.write("\nStats: \n")
   io.write(string.format("Elapsed time: %ds\n", os.time() - start_time))
   io.write(string.format("No of ham: %d\n", no_of_ham))
   io.write(string.format("No of spam: %d\n", no_of_spam))

end