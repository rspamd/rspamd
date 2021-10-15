local rspamd_logger = require "rspamd_logger"
local argparse = require "argparse"
local lua_util = require "lua_util"
local ucl = require "ucl"

local parser = argparse()
  :name "rspamadm neural_test"
  :description "Test the neural network with labelled dataset"
  :help_description_margin(32)

parser:option "-c --config"
      :description "Path to config file"
      :argname("<cfg>")
      :default(rspamd_paths["CONFDIR"] .. "/" .. "rspamd.conf")
parser:option "-H --hamdir"
      :description("Ham directory")
      :argname("<dir>")
parser:option "-S --spamdir"
      :description("Spam directory")
      :argname("<dir>")
parser:option "-t --timeout"
      :description("Timeout for client connections")
      :argname("<sec>")
      :convert(tonumber)
      :default(60)
parser:option "-n --conns"
      :description("Number of parallel connections")
      :argname("<N>")
      :convert(tonumber)
      :default(10)
parser:option "-c --connect"
      :description("Connect to specific host")
      :argname("<host>")
      :default('localhost:11334')
parser:option "-r --rspamc"
      :description("Use specific rspamc path")
      :argname("<path>")
      :default('rspamc')
parser:option '--rule'
      :description 'Rule to test'
      :argname('<rule>')


local HAM = "HAM"
local SPAM = "SPAM"

local function load_config(opts)
  local _r,err = rspamd_config:load_ucl(opts['config'])

  if not _r then
    rspamd_logger.errx('cannot parse %s: %s', opts['config'], err)
    os.exit(1)
  end

  _r,err = rspamd_config:parse_rcl({'logging', 'worker'})
  if not _r then
    rspamd_logger.errx('cannot process %s: %s', opts['config'], err)
    os.exit(1)
  end
end


local function scan_email(rspamc_path, host, n_parallel, path, timeout)

  local rspamc_command = string.format("%s --connect %s -j --compact -n %s -t %.3f %s",
      rspamc_path, host, n_parallel, timeout, path)
  local result = assert(io.popen(rspamc_command))
  result = result:read("*all")
  return result
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

local function filter_scan_results(results, actual_email_type)

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

local function get_stats_from_scan_results(results, rules)

  local rule_stats = {}
  for rule,_ in pairs(rules) do 
    rule_stats[rule] = {tp = 0, tn = 0, fp = 0, fn = 0}
  end

  for _,result in ipairs(results) do
    for _,symbol in ipairs(result["symbols"]) do
      for name,rule in pairs(rules) do
        if rule.symbol_spam and rule.symbol_spam == symbol then
          if result.type == HAM then
            rule_stats[name].fp = rule_stats[name].fp + 1
          elseif result.type == SPAM then
            rule_stats[name].tp = rule_stats[name].tp + 1
          end
        elseif rule.symbol_ham and rule.symbol_ham == symbol then
          if result.type == HAM then
            rule_stats[name].tn = rule_stats[name].tn + 1
          elseif result.type == SPAM then
            rule_stats[name].fn = rule_stats[name].fn + 1
          end
        end
      end
    end
  end

  for rule,_ in pairs(rules) do 
    rule_stats[rule].fpr = rule_stats[rule].fp / (rule_stats[rule].fp + rule_stats[rule].tn)
    rule_stats[rule].fnr = rule_stats[rule].fn / (rule_stats[rule].fn + rule_stats[rule].tp)
  end

  return rule_stats
end

local function print_neural_stats(neural_stats)
  for rule, stats in pairs(neural_stats) do
    rspamd_logger.messagex("\nStats for rule: %s", rule)
    rspamd_logger.messagex("False positive rate: %s%%", stats.fpr * 100)
    rspamd_logger.messagex("False negative rate: %s%%", stats.fnr * 100)
  end
end

local function handler(args)
  local opts = parser:parse(args)

  local ham_directory = opts['hamdir']
  local spam_directory = opts['spamdir']
  local connections = opts["conns"]

  load_config(opts)

  local neural_opts = rspamd_config:get_all_opt('neural')

  if opts["rule"] then
    local found = false
    for rule_name, _ in pairs(neural_opts.rules) do
      if string.lower(rule_name) == string.lower(opts["rule"]) then
        found = true
      else
        neural_opts.rules[rule_name] = nil
      end
    end

    if not found then
      rspamd_logger.errx("Couldn't find the rule %s", opts["rule"])
      return
    end
  end

  local results = {}

  if ham_directory then
    rspamd_logger.messagex("Scanning ham corpus...")
    local ham_results = scan_email(opts.rspamc, opts.connect, connections, ham_directory, opts.timeout)
    ham_results = filter_scan_results(ham_results, HAM)

    for _, result in pairs(ham_results) do
      table.insert(results, result)
    end
  end

  if spam_directory then
    rspamd_logger.messagex("Scanning spam corpus...")
    local spam_results = scan_email(opts.rspamc, opts.connect, connections, spam_directory, opts.timeout)
    spam_results = filter_scan_results(spam_results, SPAM)

    for _, result in pairs(spam_results) do
      table.insert(results, result)
    end
  end

  local neural_stats = get_stats_from_scan_results(results, neural_opts.rules)
  print_neural_stats(neural_stats)

end


return {
  name = "neuraltest",
  aliases = {"neural_test"},
  handler = handler,
  description = parser._description
}