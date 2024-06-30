local rspamd_util = require "rspamd_util"
local lua_util = require "lua_util"
local argparse = require "argparse"
local ucl = require "ucl"
local rspamd_logger = require "rspamd_logger"

local parser = argparse()
    :name "rspamadm classifier_test"
    :description "Learn bayes classifier and evaluate its performance"
    :help_description_margin(32)

parser:option "-H --ham"
      :description("Ham directory")
      :argname("<dir>")
parser:option "-S --spam"
      :description("Spam directory")
      :argname("<dir>")
parser:flag "-n --no-learning"
      :description("Do not learn classifier")
parser:option "--nconns"
      :description("Number of parallel connections")
      :argname("<N>")
      :convert(tonumber)
      :default(10)
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
parser:option "-c --cv-fraction"
      :description("Use specific fraction for cross-validation")
      :argname("<fraction>")
      :convert(tonumber)
      :default('0.7')
parser:option "--spam-symbol"
      :description("Use specific spam symbol (instead of BAYES_SPAM)")
      :argname("<symbol>")
      :default('BAYES_SPAM')
parser:option "--ham-symbol"
      :description("Use specific ham symbol (instead of BAYES_HAM)")
      :argname("<symbol>")
      :default('BAYES_HAM')

local opts

-- Utility function to split a table into two parts randomly
local function split_table(t, fraction)
  local shuffled = {}
  for _, v in ipairs(t) do
    local pos = math.random(1, #shuffled + 1)
    table.insert(shuffled, pos, v)
  end
  local split_point = math.floor(#shuffled * tonumber(fraction))
  local part1 = { lua_util.unpack(shuffled, 1, split_point) }
  local part2 = { lua_util.unpack(shuffled, split_point + 1) }
  return part1, part2
end

-- Utility function to get all files in a directory
local function get_files(dir)
  return rspamd_util.glob(dir .. '/*')
end

local function list_to_file(list, fname)
  local out = assert(io.open(fname, "w"))
  for _, v in ipairs(list) do
    out:write(v)
    out:write("\n")
  end
  out:close()
end

-- Function to train the classifier with given files
local function train_classifier(files, command)
  local fname = os.tmpname()
  list_to_file(files, fname)
  local rspamc_command = string.format("%s --connect %s -j --compact -n %s -t %.3f %s --files-list=%s",
      opts.rspamc, opts.connect, opts.nconns, opts.timeout, command, fname)
  local result = assert(io.popen(rspamc_command))
  result = result:read("*all")
  os.remove(fname)
end

-- Function to classify files and return results
local function classify_files(files, known_spam_files, known_ham_files)
  local fname = os.tmpname()
  list_to_file(files, fname)

  local settings_header = string.format('--header Settings=\"{symbols_enabled=[%s, %s]}\"',
      opts.spam_symbol, opts.ham_symbol)
  local rspamc_command = string.format("%s %s --connect %s --compact -n %s -t %.3f --files-list=%s",
      opts.rspamc,
      settings_header,
      opts.connect,
      opts.nconns,
      opts.timeout, fname)
  local result = assert(io.popen(rspamc_command))
  local results = {}
  for line in result:lines() do
    local ucl_parser = ucl.parser()
    local is_good, err = ucl_parser:parse_string(line)
    if not is_good then
      rspamd_logger.errx("Parser error: %1", err)
      os.remove(fname)
      return nil
    end
    local obj = ucl_parser:get_object()
    local file = obj.filename
    local symbols = obj.symbols or {}

    if symbols[opts.spam_symbol] then
      table.insert(results, { result = "spam", file = file })
      if known_ham_files[file] then
        rspamd_logger.message("FP: %s is classified as spam but is known ham", file)
      end
    elseif symbols[opts.ham_symbol] then
      if known_spam_files[file] then
        rspamd_logger.message("FN: %s is classified as ham but is known spam", file)
      end
      table.insert(results, { result = "ham", file = file })
    end
  end

  os.remove(fname)

  return results
end

-- Function to evaluate classifier performance
local function evaluate_results(results, spam_label, ham_label,
                                known_spam_files, known_ham_files, total_cv_files, elapsed)
  local true_positives, false_positives, true_negatives, false_negatives, total = 0, 0, 0, 0, 0
  for _, res in ipairs(results) do
    if res.result == spam_label then
      if known_spam_files[res.file] then
        true_positives = true_positives + 1
      elseif known_ham_files[res.file] then
        false_positives = false_positives + 1
      end
      total = total + 1
    elseif res.result == ham_label then
      if known_spam_files[res.file] then
        false_negatives = false_negatives + 1
      elseif known_ham_files[res.file] then
        true_negatives = true_negatives + 1
      end
      total = total + 1
    end
  end

  local accuracy = (true_positives + true_negatives) / total
  local precision = true_positives / (true_positives + false_positives)
  local recall = true_positives / (true_positives + false_negatives)
  local f1_score = 2 * (precision * recall) / (precision + recall)

  print(string.format("%-20s %-10s", "Metric", "Value"))
  print(string.rep("-", 30))
  print(string.format("%-20s %-10d", "True Positives", true_positives))
  print(string.format("%-20s %-10d", "False Positives", false_positives))
  print(string.format("%-20s %-10d", "True Negatives", true_negatives))
  print(string.format("%-20s %-10d", "False Negatives", false_negatives))
  print(string.format("%-20s %-10.2f", "Accuracy", accuracy))
  print(string.format("%-20s %-10.2f", "Precision", precision))
  print(string.format("%-20s %-10.2f", "Recall", recall))
  print(string.format("%-20s %-10.2f", "F1 Score", f1_score))
  print(string.format("%-20s %-10.2f", "Classified (%)", total / total_cv_files * 100))
  print(string.format("%-20s %-10.2f", "Elapsed time (seconds)", elapsed))
end

local function handler(args)
  opts = parser:parse(args)
  local ham_directory = opts['ham']
  local spam_directory = opts['spam']
  -- Get all files
  local spam_files = get_files(spam_directory)
  local known_spam_files = lua_util.list_to_hash(spam_files)
  local ham_files = get_files(ham_directory)
  local known_ham_files = lua_util.list_to_hash(ham_files)

  -- Split files into training and cross-validation sets

  local train_spam, cv_spam = split_table(spam_files, opts.cv_fraction)
  local train_ham, cv_ham = split_table(ham_files, opts.cv_fraction)

  print(string.format("Spam: %d train files, %d cv files; ham: %d train files, %d cv files",
      #train_spam, #cv_spam, #train_ham, #cv_ham))
  if not opts.no_learning then
    -- Train classifier
    local t, train_spam_time, train_ham_time
    print(string.format("Start learn spam, %d messages, %d connections", #train_spam, opts.nconns))
    t = rspamd_util.get_time()
    train_classifier(train_spam, "learn_spam")
    train_spam_time = rspamd_util.get_time() - t
    print(string.format("Start learn ham, %d messages, %d connections", #train_ham, opts.nconns))
    t = rspamd_util.get_time()
    train_classifier(train_ham, "learn_ham")
    train_ham_time = rspamd_util.get_time() - t
    print(string.format("Learning done: %d spam messages in %.2f seconds, %d ham messages in %.2f seconds",
        #train_spam, train_spam_time, #train_ham, train_ham_time))
  end

  -- Classify cross-validation files
  local cv_files = {}
  for _, file in ipairs(cv_spam) do
    table.insert(cv_files, file)
  end
  for _, file in ipairs(cv_ham) do
    table.insert(cv_files, file)
  end

  -- Shuffle cross-validation files
  cv_files = split_table(cv_files, 1)

  print(string.format("Start cross validation, %d messages, %d connections", #cv_files, opts.nconns))
  -- Get classification results
  local t = rspamd_util.get_time()
  local results = classify_files(cv_files, known_spam_files, known_ham_files)
  local elapsed = rspamd_util.get_time() - t

  -- Evaluate results
  evaluate_results(results, "spam", "ham",
      known_spam_files,
      known_ham_files,
      #cv_files,
      elapsed)

end

return {
  name = 'classifiertest',
  aliases = { 'classifier_test' },
  handler = handler,
  description = parser._description
}