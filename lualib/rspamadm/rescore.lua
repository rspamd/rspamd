--[[
Copyright (c) 2018, Vsevolod Stakhov <vsevolod@highsecure.ru>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
]]--

--[[
local lua_util = require "lua_util"
local ucl = require "ucl"
local logger = require "rspamd_logger"
local rspamd_util = require "rspamd_util"
local argparse = require "argparse"
local rescore_utility = require "rescore_utility"


local opts
local ignore_symbols = {
  ['DATE_IN_PAST'] =true,
  ['DATE_IN_FUTURE'] = true,
}

local parser = argparse()
    :name "rspamadm rescore"
    :description "Estimate optimal symbol weights from log files"
    :help_description_margin(37)

parser:option "-l --log"
      :description "Log file or files (from rescore)"
      :argname("<log>")
      :args "*"
parser:option "-c --config"
      :description "Path to config file"
      :argname("<file>")
      :default(rspamd_paths["CONFDIR"] .. "/" .. "rspamd.conf")
parser:option "-o --output"
      :description "Output file"
      :argname("<file>")
      :default("new.scores")
parser:flag "-d --diff"
      :description "Show differences in scores"
parser:flag "-v --verbose"
      :description "Verbose output"
parser:flag "-z --freq"
      :description "Display hit frequencies"
parser:option "-i --iters"
      :description "Learn iterations"
      :argname("<n>")
      :convert(tonumber)
      :default(10)
parser:option "-b --batch"
      :description "Batch size"
      :argname("<n>")
      :convert(tonumber)
      :default(100)
parser:option "-d --decay"
      :description "Decay rate"
      :argname("<n>")
      :convert(tonumber)
      :default(0.001)
parser:option "-m --momentum"
      :description "Learn momentum"
      :argname("<n>")
      :convert(tonumber)
      :default(0.1)
parser:option "-t --threads"
      :description "Number of threads to use"
      :argname("<n>")
      :convert(tonumber)
      :default(1)
parser:option "-o --optim"
      :description "Optimisation algorithm"
      :argname("<alg>")
      :convert {
        LBFGS = "LBFGS",
        ADAM = "ADAM",
        ADAGRAD = "ADAGRAD",
        SGD = "SGD",
        NAG = "NAG"
      }
      :default "ADAM"
parser:option "--ignore-symbol"
      :description "Ignore symbol from logs"
      :argname("<sym>")
      :args "*"
parser:option "--penalty-weight"
      :description "Add new penalty weight to test"
      :argname("<n>")
      :convert(tonumber)
      :args "*"
parser:option "--learning-rate"
      :description "Add new learning rate to test"
      :argname("<n>")
      :convert(tonumber)
      :args "*"
parser:option "--spam_action"
      :description "Spam action"
      :argname("<act>")
      :default("reject")
parser:option "--learning_rate_decay"
      :description "Learn rate decay (for some algs)"
      :argname("<n>")
      :convert(tonumber)
      :default(0.0)
parser:option "--weight_decay"
      :description "Weight decay (for some algs)"
      :argname("<n>")
      :convert(tonumber)
      :default(0.0)
parser:option "--l1"
      :description "L1 regularization penalty"
      :argname("<n>")
      :convert(tonumber)
      :default(0.0)
parser:option "--l2"
      :description "L2 regularization penalty"
      :argname("<n>")
      :convert(tonumber)
      :default(0.0)

local function make_dataset_from_logs(logs, all_symbols, spam_score)

  local inputs = {}
  local outputs = {}

  for _, log in pairs(logs) do

    log = lua_util.rspamd_str_split(log, " ")

    if log[1] == "SPAM" then
      outputs[#outputs+1] = 1
    else
      outputs[#outputs+1] = 0
    end

    local symbols_set = {}

    for i=4,#log do
      if not ignore_symbols[ log[i] ] then
        symbols_set[log[i] ] = true
      end
    end

    local input_vec = {}
    for index, symbol in pairs(all_symbols) do
      if symbols_set[symbol] then
        input_vec[index] = 1
      else
        input_vec[index] = 0
      end
    end

    inputs[#inputs + 1] = input_vec
  end

  return inputs,outputs
end

local function init_weights(all_symbols, original_symbol_scores)
end

local function shuffle(logs, messages)

  local size = #logs
  for i = size, 1, -1 do
    local rand = math.random(size)
    logs[i], logs[rand] = logs[rand], logs[i]
    messages[i], messages[rand] = messages[rand], messages[i]
  end

end

local function split_logs(logs, messages, split_percent)

  if not split_percent then
    split_percent = 60
  end

  local split_index = math.floor(#logs * split_percent / 100)

  local test_logs = {}
  local train_logs = {}
  local test_messages = {}
  local train_messages = {}

  for i=1,split_index do
    table.insert(train_logs, logs[i])
    table.insert(train_messages, messages[i])
  end

  for i=split_index + 1, #logs do
    table.insert(test_logs, logs[i])
    table.insert(test_messages, messages[i])
  end

  return {train_logs,train_messages}, {test_logs,test_messages}
end

local function stitch_new_scores(all_symbols, new_scores)

  local new_symbol_scores = {}

  for idx, symbol in pairs(all_symbols) do
    new_symbol_scores[symbol] = new_scores[idx]
  end

  return new_symbol_scores
end


local function update_logs(logs, symbol_scores)

  for i, log in ipairs(logs) do

    log = lua_util.rspamd_str_split(log, " ")

    local score = 0

    for j=4,#log do
      log[j] = log[j]:gsub("%s+", "")
      score = score + (symbol_scores[log[j] ] or 0)
    end

    log[2] = lua_util.round(score, 2)

    logs[i] = table.concat(log, " ")
  end

  return logs
end

local function write_scores(new_symbol_scores, file_path)

  local file = assert(io.open(file_path, "w"))

  local new_scores_ucl = ucl.to_format(new_symbol_scores, "ucl")

  file:write(new_scores_ucl)

  file:close()
end

local function print_score_diff(new_symbol_scores, original_symbol_scores)

  logger.message(string.format("%-35s %-10s %-10s",
      "SYMBOL", "OLD_SCORE", "NEW_SCORE"))

  for symbol, new_score in pairs(new_symbol_scores) do
    logger.message(string.format("%-35s %-10s %-10s",
        symbol,
        original_symbol_scores[symbol] or 0,
        lua_util.round(new_score, 2)))
  end

  logger.message("\nClass changes \n")
  for symbol, new_score in pairs(new_symbol_scores) do
    if original_symbol_scores[symbol] ~= nil then
      if (original_symbol_scores[symbol] > 0 and new_score < 0) or
          (original_symbol_scores[symbol] < 0 and new_score > 0) then
        logger.message(string.format("%-35s %-10s %-10s",
            symbol,
            original_symbol_scores[symbol] or 0,
            lua_util.round(new_score, 2)))
      end
    end
  end

end

local function calculate_fscore_from_weights(logs, messages,
                                             all_symbols,
                                             weights,
                                             threshold)

  local new_symbol_scores = weights:clone()

  new_symbol_scores = stitch_new_scores(all_symbols, new_symbol_scores)

  logs = update_logs(logs, new_symbol_scores)

  local file_stats, _, all_fps, all_fns =
      rescore_utility.generate_statistics_from_logs(logs, messages, threshold)

  return file_stats.fscore, all_fps, all_fns
end

local function print_stats(logs, messages, threshold)

  local file_stats, _ = rescore_utility.generate_statistics_from_logs(logs,
      messages, threshold)

  local file_stat_format = [=[
F-score: %.2f
False positive rate: %.2f %%
False negative rate: %.2f %%
Overall accuracy: %.2f %%
Slowest message: %.2f (%s)
]=]

  logger.message("\nStatistics at threshold: " .. threshold)

  logger.message(string.format(file_stat_format,
      file_stats.fscore,
      file_stats.false_positive_rate,
      file_stats.false_negative_rate,
      file_stats.overall_accuracy,
      file_stats.slowest,
      file_stats.slowest_file))

end

-- training function
local function train(dataset, opt, model, criterion, epoch,
                     all_symbols, spam_threshold, initial_weights)
end

local learning_rates = {
  0.01
}
local penalty_weights = {
  0
}

local function get_threshold()
  local actions = rspamd_config:get_all_actions()

  if opts['spam-action'] then
    return (actions[opts['spam-action'] ] or 0),actions['reject']
  end
  return (actions['add header'] or actions['rewrite subject']
      or actions['reject']), actions['reject']
end

local function handler(args)
  opts = parser:parse(args)
  if not opts['log'] then
    parser:error('no log specified')
  end

  local _r,err = rspamd_config:load_ucl(opts['config'])

  if not _r then
    logger.errx('cannot parse %s: %s', opts['config'], err)
    os.exit(1)
  end

  _r,err = rspamd_config:parse_rcl({'logging', 'worker'})
  if not _r then
    logger.errx('cannot process %s: %s', opts['config'], err)
    os.exit(1)
  end

  local threshold,reject_score = get_threshold()
  local logs,messages = rescore_utility.get_all_logs(opts['log'])

  if opts['ignore-symbol'] then
    local function add_ignore(s)
      ignore_symbols[s] = true
    end
    if type(opts['ignore-symbol']) == 'table' then
      for _,s in ipairs(opts['ignore-symbol']) do
        add_ignore(s)
      end
    else
      add_ignore(opts['ignore-symbol'])
    end
  end

  if opts['learning-rate'] then
    learning_rates = {}

    local function add_rate(r)
      if tonumber(r) then
        table.insert(learning_rates, tonumber(r))
      end
    end
    if type(opts['learning-rate']) == 'table' then
      for _,s in ipairs(opts['learning-rate']) do
        add_rate(s)
      end
    else
      add_rate(opts['learning-rate'])
    end
  end

  if opts['penalty-weight'] then
    penalty_weights = {}

    local function add_weight(r)
      if tonumber(r) then
        table.insert(penalty_weights, tonumber(r))
      end
    end
    if type(opts['penalty-weight']) == 'table' then
      for _,s in ipairs(opts['penalty-weight']) do
        add_weight(s)
      end
    else
      add_weight(opts['penalty-weight'])
    end
  end

  local all_symbols = rescore_utility.get_all_symbols(logs, ignore_symbols)
  local original_symbol_scores = rescore_utility.get_all_symbol_scores(rspamd_config,
      ignore_symbols)

  -- Display hit frequencies
  if opts['freq'] then
      local _, all_symbols_stats = rescore_utility.generate_statistics_from_logs(logs,
          messages,
          threshold)
      local t = {}
      for _, symbol_stats in pairs(all_symbols_stats) do table.insert(t, symbol_stats) end

      local function compare_symbols(a, b)
          if (a.spam_overall ~= b.spam_overall) then
              return b.spam_overall < a.spam_overall
          end
          if (b.spam_hits ~= a.spam_hits) then
              return b.spam_hits < a.spam_hits
          end
          return b.ham_hits < a.ham_hits
      end
      table.sort(t, compare_symbols)

      logger.message(string.format("%-40s %6s %6s %6s %6s %6s %6s %6s",
                     "NAME", "HITS", "HAM", "HAM%", "SPAM", "SPAM%", "S/O", "OVER%"))
      for _, symbol_stats in pairs(t) do
          logger.message(
              string.format("%-40s %6d %6d %6.2f %6d %6.2f %6.2f %6.2f",
                  symbol_stats.name,
                  symbol_stats.no_of_hits,
                  symbol_stats.ham_hits,
                  lua_util.round(symbol_stats.ham_percent,2),
                  symbol_stats.spam_hits,
                  lua_util.round(symbol_stats.spam_percent,2),
                  lua_util.round(symbol_stats.spam_overall,2),
                  lua_util.round(symbol_stats.overall, 2)
              )
          )
      end

      -- Print file statistics
      print_stats(logs, messages, threshold)

      -- Work out how many symbols weren't seen in the corpus
      local symbols_no_hits = {}
      local total_symbols = 0
      for sym in pairs(original_symbol_scores) do
          total_symbols = total_symbols + 1
          if (all_symbols_stats[sym] == nil) then
              table.insert(symbols_no_hits, sym)
          end
      end
      if (#symbols_no_hits > 0) then
          table.sort(symbols_no_hits)
          -- Calculate percentage of rules with no hits
          local nhpct = lua_util.round((#symbols_no_hits/total_symbols)*100,2)
          logger.message(
              string.format('\nFound %s (%-.2f%%) symbols out of %s with no hits in corpus:',
                            #symbols_no_hits, nhpct, total_symbols
              )
          )
          for _, symbol in pairs(symbols_no_hits) do
              logger.messagex('%s', symbol)
          end
      end

      return
  end

  shuffle(logs, messages)
  local train_logs, validation_logs = split_logs(logs, messages,70)
  local cv_logs, test_logs = split_logs(validation_logs[1], validation_logs[2], 50)

  local dataset = make_dataset_from_logs(train_logs[1], all_symbols, reject_score)
  -- Start of perceptron training
  local input_size = #all_symbols

  local linear_module = nn.Linear(input_size, 1, false)
  local activation = nn.Sigmoid()

  local perceptron = nn.Sequential()
  perceptron:add(linear_module)
  perceptron:add(activation)

  local criterion = nn.MSECriterion()
  --criterion.sizeAverage = false

  local best_fscore = -math.huge
  local best_weights = linear_module.weight[1]:clone()
  local best_learning_rate
  local best_weight_decay
  local all_fps
  local all_fns

  for _,lr in ipairs(learning_rates) do
    for _,wd in ipairs(penalty_weights) do
      linear_module.weight[1] = init_weights(all_symbols, original_symbol_scores)
      local initial_weights = linear_module.weight[1]:clone()
      opts.learning_rate = lr
      opts.weight_decay = wd
      for i=1,tonumber(opts.iters) do
        train(dataset, opts, perceptron, criterion, i, all_symbols, threshold,
            initial_weights)
      end

      local fscore, fps, fns = calculate_fscore_from_weights(cv_logs[1],
          cv_logs[2],
          all_symbols,
          linear_module.weight[1],
          threshold)

      logger.messagex("Cross-validation fscore=%s, learning rate=%s, weight decay=%s",
          fscore, lr, wd)

      if best_fscore < fscore then
        best_learning_rate = lr
        best_weight_decay = wd
        best_fscore = fscore
        best_weights = linear_module.weight[1]:clone()
        all_fps = fps
        all_fns = fns
      end
    end
  end

  -- End perceptron training

  local new_symbol_scores = best_weights

  new_symbol_scores = stitch_new_scores(all_symbols, new_symbol_scores)

  if opts["output"] then
    write_scores(new_symbol_scores, opts["output"])
  end

  if opts["diff"] then
    print_score_diff(new_symbol_scores, original_symbol_scores)
  end

  -- Pre-rescore test stats
  logger.message("\n\nPre-rescore test stats\n")
  test_logs[1] = update_logs(test_logs[1], original_symbol_scores)
  print_stats(test_logs[1], test_logs[2], threshold)

  -- Post-rescore test stats
  test_logs[1] = update_logs(test_logs[1], new_symbol_scores)
  logger.message("\n\nPost-rescore test stats\n")
  print_stats(test_logs[1], test_logs[2], threshold)

  logger.messagex('Best fscore=%s, best learning rate=%s, best weight decay=%s',
      best_fscore, best_learning_rate, best_weight_decay)

  -- Show all FPs/FNs, useful for corpus checking and rule creation/modification
  if (all_fps and #all_fps > 0) then
      logger.message("\nFalse-Positives:")
      for _, fp in pairs(all_fps) do
          logger.messagex('%s', fp)
      end
  end

  if (all_fns and #all_fns > 0) then
      logger.message("\nFalse-Negatives:")
      for _, fn in pairs(all_fns) do
          logger.messagex('%s', fn)
      end
  end
end


return {
  handler = handler,
  description = parser._description,
  name = 'rescore'
}
--]]

return nil
