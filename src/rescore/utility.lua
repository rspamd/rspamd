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
   -- Returns a list of all symbols in ascending order
   
   local symbols_table = {}

   for _, line in pairs(logs) do
      line = utility.string_split(line, " ")
      for i=5,#line do
	 if symbols_table[line[i]] == nil then
	    symbols_table[line[i]] = true
	 end
      end
   end

   local symbols_set = {}
   
   for key, value in pairs(symbols_table) do
      symbols_set[#symbols_set + 1] = key
   end

   table.sort(symbols_set)
   
   return symbols_set   
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

return utility
