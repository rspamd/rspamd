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

return utility
