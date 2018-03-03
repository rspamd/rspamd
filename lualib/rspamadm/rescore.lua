local torch = require "torch"
local nn = require "nn"
local lua_util = require "lua_util"
local ucl = require "ucl"
local logger = require "rspamd_logger"
local getopt = require "rspamadm/getopt"

local rescore_utility = require "rspamadm/rescore_utility"

local opts
local ignore_symbols = {
  ['DATE_IN_PAST'] =true,
  ['DATE_IN_FUTURE'] = true,
}

local function make_dataset_from_logs(logs, all_symbols)
  -- Returns a list of {input, output} for torch SGD train

  local dataset = {}

  for _, log in pairs(logs) do
    local input = torch.Tensor(#all_symbols)
    local output = torch.Tensor(1)
    log = lua_util.rspamd_str_split(log, " ")

    if log[1] == "SPAM" then
      output[1] = 1
    else
      output[1] = 0
    end

    local symbols_set = {}

    for i=4,#log do
      if not ignore_symbols[log[i]] then
        symbols_set[log[i]] = true
      end
    end

    for index, symbol in pairs(all_symbols) do
      if symbols_set[symbol] then
        input[index] = 1
      else
        input[index] = 0
      end
    end

    dataset[#dataset + 1] = {input, output}

  end

  function dataset:size()
    return #dataset
  end

  return dataset
end

local function init_weights(all_symbols, original_symbol_scores)

  local weights = torch.Tensor(#all_symbols)

  local mean = 0

  for i, symbol in pairs(all_symbols) do
    local score = original_symbol_scores[symbol]
    if not score then score = 0 end
    weights[i] = score
    mean = mean + score
  end

  return weights
end

local function shuffle(logs)

  local size = #logs
  for i = size, 1, -1 do
    local rand = math.random(size)
    logs[i], logs[rand] = logs[rand], logs[i]
  end

end

local function split_logs(logs, split_percent)

  if not split_percent then
    split_percent = 60
  end

  local split_index = math.floor(#logs * split_percent / 100)

  local test_logs = {}
  local train_logs = {}

  for i=1,split_index do
    train_logs[#train_logs + 1] = logs[i]
  end

  for i=split_index + 1, #logs do
    test_logs[#test_logs + 1] = logs[i]
  end

  return train_logs, test_logs
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
      score = score + (symbol_scores[log[j	]] or 0)
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
        rescore_utility.round(new_score, 2)))
  end

  logger.message("\nClass changes \n")
  for symbol, new_score in pairs(new_symbol_scores) do
    if original_symbol_scores[symbol] ~= nil then
      if (original_symbol_scores[symbol] > 0 and new_score < 0) or
          (original_symbol_scores[symbol] < 0 and new_score > 0) then
        logger.message(string.format("%-35s %-10s %-10s",
            symbol,
            original_symbol_scores[symbol] or 0,
            rescore_utility.round(new_score, 2)))
      end
    end
  end

end

local function calculate_fscore_from_weights(logs, all_symbols, weights, bias, threshold)

  local new_symbol_scores = weights:clone()

  new_symbol_scores = stitch_new_scores(all_symbols, new_symbol_scores)

  logs = update_logs(logs, new_symbol_scores)

  local file_stats, _ = rescore_utility.generate_statistics_from_logs(logs, threshold)

  return file_stats.fscore
end

local function print_stats(logs, threshold)

  local file_stats, _ = rescore_utility.generate_statistics_from_logs(logs, threshold)

  local file_stat_format = [[
F-score: %.2f
False positive rate: %.2f %%
False negative rate: %.2f %%
Overall accuracy: %.2f %%
]]

  logger.message("\nStatistics at threshold: " .. threshold)

  logger.message(string.format(file_stat_format,
      file_stats.fscore,
      file_stats.false_positive_rate,
      file_stats.false_negative_rate,
      file_stats.overall_accuracy))

end

local default_opts = {
  verbose = true,
  iters = 10,
  threads = 1,
}

local learning_rates = {
  0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 2.5, 5, 7.5, 10
}
local penalty_weights = {
  0, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 3, 5, 10, 15, 20, 25, 50, 75, 100
}

local function override_defaults(def, override)
  for k,v in pairs(override) do
    if def[k] then
      if type(v) == 'table' then
        override_defaults(def[k], v)
      else
        def[k] = v
      end
    else
      def[k] = v
    end
  end
end

local function get_threshold()
  local actions = rspamd_config:get_all_actions()

  if opts['spam-action'] then
    return actions[opts['spam-action']] or 0
  else
    return actions['add header'] or actions['rewrite subject'] or actions['reject']
  end
end

return function (args, cfg)
  opts = default_opts
  override_defaults(opts, getopt.getopt(args, 'i:'))
  local threshold = get_threshold()
  local logs = rescore_utility.get_all_logs(cfg["logdir"])

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

  if opts['i'] then opts['iters'] = opts['i'] end
  logger.errx('%s', opts)

  local all_symbols = rescore_utility.get_all_symbols(logs, ignore_symbols)
  local original_symbol_scores = rescore_utility.get_all_symbol_scores(rspamd_config,
      ignore_symbols)

  shuffle(logs)
  torch.setdefaulttensortype('torch.FloatTensor')

  local train_logs, validation_logs = split_logs(logs, 70)
  local cv_logs, test_logs = split_logs(validation_logs, 50)

  local dataset = make_dataset_from_logs(train_logs, all_symbols)


  -- Start of perceptron training
  local input_size = #all_symbols
  torch.setnumthreads(opts['threads'])
  local linear_module = nn.Linear(input_size, 1)

  local perceptron = nn.Sequential()
  perceptron:add(linear_module)

  local activation = nn.Sigmoid()

  perceptron:add(activation)

  local criterion = nn.MSECriterion()
  criterion.sizeAverage = false

  local best_fscore = -math.huge
  local best_weights = linear_module.weight[1]:clone()

  local trainer = nn.StochasticGradient(perceptron, criterion)
  trainer.maxIteration = tonumber(opts["iters"])
  trainer.verbose = opts['verbose']
  trainer.hookIteration = function(self, iteration, error)

    if iteration == trainer.maxIteration then

      local fscore = calculate_fscore_from_weights(cv_logs,
          all_symbols,
          linear_module.weight[1],
          linear_module.bias[1],
          threshold)

      logger.messagex("Cross-validation fscore: %s", fscore)

      if best_fscore < fscore then
        best_fscore = fscore
        best_weights = linear_module.weight[1]:clone()
      end
    end
  end

  for _, learning_rate in ipairs(learning_rates) do
    for _, weight in ipairs(penalty_weights) do

      trainer.weightDecay = weight
      logger.messagex("Learning with learning_rate: %s, l2_weight: %s",
          learning_rate, weight)

      linear_module.weight[1] = init_weights(all_symbols, original_symbol_scores)

      trainer.learningRate = learning_rate
      trainer:train(dataset)
    end
  end

  -- End perceptron training

  local new_symbol_scores = best_weights

  new_symbol_scores = stitch_new_scores(all_symbols, new_symbol_scores)

  if cfg["output"] then
    write_scores(new_symbol_scores, cfg["output"])
  end

  if opts["diff"] then
    print_score_diff(new_symbol_scores, original_symbol_scores)
  end


  -- Pre-rescore test stats
  logger.message("\n\nPre-rescore test stats\n")
  test_logs = update_logs(test_logs, original_symbol_scores)
  print_stats(test_logs, threshold)

  -- Post-rescore test stats
  test_logs = update_logs(test_logs, new_symbol_scores)
  logger.message("\n\nPost-rescore test stats\n")
  print_stats(test_logs, threshold)
end