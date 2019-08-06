local rspamd_logger = require "rspamd_logger"
local ucl = require "ucl"
local lua_util = require "lua_util"
local argparse = require "argparse"

local parser = argparse()
    :name "rspamadm corpus_test"
    :description "Create logs files from email corpus"
    :help_description_margin(32)

parser:option "-H --ham"
      :description("Ham directory")
      :argname("<dir>")
parser:option "-S --spam"
      :description("Spam directory")
      :argname("<dir>")
parser:option "-n --conns"
      :description("Number of parallel connections")
      :argname("<N>")
      :convert(tonumber)
      :default(10)
parser:option "-o --output"
      :description("Output file")
      :argname("<file>")
      :default('results.log')
parser:option "-t --timeout"
      :description("Timeout for client connections")
      :argname("<sec>")
      :convert(tonumber)
      :default(60)
parser:option "-c --connect"
      :description("Connect to specific host")
      :argname("<host>")
      :default('localhost:11334')
parser:option "-r --rspamc"
      :description("Use specific rspamc path")
      :argname("<path>")
      :default('rspamc')

local HAM = "HAM"
local SPAM = "SPAM"
local opts

local function scan_email(n_parallel, path, timeout)

  local rspamc_command = string.format("%s --connect %s -j --compact -n %s -t %.3f %s",
      opts.rspamc, opts.connect, n_parallel, timeout, path)
  local result = assert(io.popen(rspamc_command))
  result = result:read("*all")
  return result
end

local function write_results(results, file)

  local f = io.open(file, 'w')

  for _, result in pairs(results) do
    local log_line = string.format("%s %.2f %s",
        result.type, result.score, result.action)

    for _, sym in pairs(result.symbols) do
      log_line = log_line .. " " .. sym
    end

    log_line = log_line .. " " .. result.scan_time .. " " .. file .. ':' .. result.filename

    log_line = log_line .. "\r\n"

    f:write(log_line)
  end

  f:close()
end

local function encoded_json_to_log(result)
  -- Returns table containing score, action, list of symbols

  local filtered_result = {}
  local ucl_parser = ucl.parser()

  local is_good, err = ucl_parser:parse_string(result)

  if not is_good then
    rspamd_logger.errx("Parser error: %1", err)
    return nil
  end

  result = ucl_parser:get_object()

  filtered_result.score = result.score
  if not result.action then
    rspamd_logger.errx("Bad JSON: %1", result)
    return nil
  end
  local action = result.action:gsub("%s+", "_")
  filtered_result.action = action

  filtered_result.symbols = {}

  for sym, _ in pairs(result.symbols) do
    table.insert(filtered_result.symbols, sym)
  end

  filtered_result.filename = result.filename
  filtered_result.scan_time = result.scan_time

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

local function handler(args)
  opts = parser:parse(args)
  local ham_directory = opts['ham']
  local spam_directory = opts['spam']
  local connections = opts["conns"]
  local output = opts["output"]

  local results = {}

  local start_time = os.time()
  local no_of_ham = 0
  local no_of_spam = 0

  if ham_directory then
    rspamd_logger.messagex("Scanning ham corpus...")
    local ham_results = scan_email(connections, ham_directory, opts["timeout"])
    ham_results = scan_results_to_logs(ham_results, HAM)

    no_of_ham = #ham_results

    for _, result in pairs(ham_results) do
      table.insert(results, result)
    end
  end

  if spam_directory then
    rspamd_logger.messagex("Scanning spam corpus...")
    local spam_results = scan_email(connections, spam_directory, opts.timeout)
    spam_results = scan_results_to_logs(spam_results, SPAM)

    no_of_spam = #spam_results

    for _, result in pairs(spam_results) do
      table.insert(results, result)
    end
  end

  rspamd_logger.messagex("Writing results to %s", output)
  write_results(results, output)

  rspamd_logger.messagex("Stats: ")
  local elapsed_time = os.time() - start_time
  local total_msgs = no_of_ham + no_of_spam
  rspamd_logger.messagex("Elapsed time: %ss", elapsed_time)
  rspamd_logger.messagex("No of ham: %s", no_of_ham)
  rspamd_logger.messagex("No of spam: %s", no_of_spam)
  rspamd_logger.messagex("Messages/sec: %s", (total_msgs / elapsed_time))
end


return {
  name = 'corpustest',
  aliases = {'corpus_test', 'corpus'},
  handler = handler,
  description = parser._description
}
