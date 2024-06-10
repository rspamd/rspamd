local rspamd_util = require "rspamd_util"
local lua_util = require "lua_util"
local argparse = require "argparse"
local fun = require "fun"

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

local function shell_quote(argument)
  if argument:match('^[%w%+%-%.,:/=@_]+$') then
    return argument
  end
  argument = argument:gsub('[$`"\\]', '\\%0')
  return '"' .. argument .. '"'
end

-- Utility function to get all files in a directory
local function get_files(dir)
  return fun.totable(fun.map(shell_quote, rspamd_util.glob(dir .. '/*')))
end

-- Function to train the classifier with given files
local function train_classifier(files, command, connections)
  local rspamc_command = string.format("%s --connect %s -j --compact -n %s -t %.3f %s %s",
      opts.rspamc, opts.connect, opts.nconns, opts.timeout, command, table.concat(files, " "))
  local result = assert(io.popen(rspamc_command))
  result = result:read("*all")
end

-- Function to classify files and return results
local function classify_files(files)
  local settings_header = '--header Settings=\"{symbols_enabled=[BAYES_SPAM, BAYES_HAM]}\"'
  local rspamc_command = string.format("%s %s --connect %s --compact -n %s -t %.3f %s",
      opts.rspamc,
      settings_header,
      opts.connect,
      opts.nconns,
      opts.timeout, table.concat(files, " "))
  local result = assert(io.popen(rspamc_command))
  local results = {}
  for line in result:lines() do
    if string.match(line, "BAYES_SPAM") then
      table.insert(results, { result = "spam", output = line })
    elseif string.match(line, "BAYES_HAM") then
      table.insert(results, { result = "ham", output = line })
    end
  end

  return results
end

-- Function to evaluate classifier performance
local function evaluate_results(results, true_label)
  local true_positives, false_positives, true_negatives, false_negatives = 0, 0, 0, 0
  for _, res in ipairs(results) do
    if res.result == true_label then
      if string.match(res.file, true_label) then
        true_positives = true_positives + 1
      else
        false_positives = false_positives + 1
      end
    else
      if string.match(res.file, true_label) then
        false_negatives = false_negatives + 1
      else
        true_negatives = true_negatives + 1
      end
    end
  end

  local total = #results
  local accuracy = (true_positives + true_negatives) / total
  local precision = true_positives / (true_positives + false_positives)
  local recall = true_positives / (true_positives + false_negatives)
  local f1_score = 2 * (precision * recall) / (precision + recall)

  print("True Positives:", true_positives)
  print("False Positives:", false_positives)
  print("True Negatives:", true_negatives)
  print("False Negatives:", false_negatives)
  print("Accuracy:", accuracy)
  print("Precision:", precision)
  print("Recall:", recall)
  print("F1 Score:", f1_score)
end

local function handler(args)
  opts = parser:parse(args)
  local ham_directory = opts['ham']
  local spam_directory = opts['spam']
  -- Get all files
  local spam_files = get_files(spam_directory)
  local ham_files = get_files(ham_directory)

  -- Split files into training and cross-validation sets

  local train_spam, cv_spam = split_table(spam_files, opts.cv_fraction)
  local train_ham, cv_ham = split_table(ham_files, opts.cv_fraction)

  print(string.format("Spam: %d train files, %d cv files; ham: %d train files, %d cv files",
      #train_spam, #cv_spam, #train_ham, #cv_ham))
  if not opts.no_learning then
    -- Train classifier
    print(string.format("Start learn spam, %d messages, %d connections", #train_spam, opts.nconns))
    train_classifier(train_spam, "learn_spam")
    print(string.format("Start learn ham, %d messages, %d connections", #train_ham, opts.nconns))
    train_classifier(train_ham, "learn_ham")
    print("Learning done")
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
  local results = classify_files(cv_files)

  -- Evaluate results
  evaluate_results(results, "spam")

end

return {
  name = 'classifiertest',
  aliases = { 'classifier_test' },
  handler = handler,
  description = parser._description
}