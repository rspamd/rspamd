local rspamd_logger = require "rspamd_logger"
local ucl = require "ucl"
local lua_util = require "lua_util"

local HAM = "HAM"
local SPAM = "SPAM"

local function scan_email(n_parellel, path, timeout)

    local rspamc_command = string.format("rspamc -j --compact -n %s -t %.3f %s",
        n_parellel, timeout, path)
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

    local is_good, err = parser:parse_string(result)

    if not is_good then
      io.stderr:write(rspamd_logger.slog("Parser error: %1\n", err))
      return nil
    end

    result = parser:get_object()

    filtered_result.score = result.score
    if not result.action then
      io.stderr:write(rspamd_logger.slog("Bad JSON: %1\n", result))
      return nil
    end
    local action = result.action:gsub("%s+", "_")
    filtered_result.action = action

    filtered_result.symbols = {}

    for sym, _ in pairs(result.symbols) do
        table.insert(filtered_result.symbols, sym)
    end

    return filtered_result   
end

local function scan_results_to_logs(results, actual_email_type)

    local logs = {}

    results = lua_util.rspamd_str_split(results, "\n")

    if results[#results] == "" then
        results[#results] = nil
    end

    for _, result in pairs(results) do      
        result = encoded_json_to_log(result)
        if result then
          result['type'] = actual_email_type
          table.insert(logs, result)
        end
    end

    return logs
end

return function (_, res)

    local ham_directory = res['ham_directory']
    local spam_directory = res['spam_directory']
    local connections = res["connections"]
    local output = res["output_location"]

    local results = {}

    local start_time = os.time()
    local no_of_ham = 0
    local no_of_spam = 0

    if ham_directory then
        io.write("Scanning ham corpus...\n")
        local ham_results = scan_email(connections, ham_directory, res["timeout"])
        ham_results = scan_results_to_logs(ham_results, HAM)

        no_of_ham = #ham_results

        for _, result in pairs(ham_results) do
            table.insert(results, result)
        end
    end

    if spam_directory then
        io.write("Scanning spam corpus...\n")
        local spam_results = scan_email(connections, spam_directory, res.timeout)
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
