local torch = require "torch"
local nn = require "nn"
local lua_util = require "lua_util"
local ucl = require "ucl"
local logger = require "rspamd_logger"
local getopt = require "rspamadm/getopt"
local optim = require "optim"
local rspamd_util = require "rspamd_util"

local rescore_utility = require "rspamadm/rescore_utility"

local opts
local ignore_symbols = {
  ['DATE_IN_PAST'] =true,
  ['DATE_IN_FUTURE'] = true,
}

local function make_dataset_from_logs(logs, all_symbols, spam_score)
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

  for i, symbol in pairs(all_symbols) do
    local score = original_symbol_scores[symbol]
    if not score then score = 0 end
    weights[i] = score
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
      score = score + (symbol_scores[log[j]] or 0)
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

local function calculate_fscore_from_weights(logs, all_symbols, weights, threshold)

  local new_symbol_scores = weights:clone()

  new_symbol_scores = stitch_new_scores(all_symbols, new_symbol_scores)

  logs = update_logs(logs, new_symbol_scores)

  local file_stats, _, all_fps, all_fns = rescore_utility.generate_statistics_from_logs(logs, threshold)

  return file_stats.fscore, all_fps, all_fns
end

local function print_stats(logs, threshold)

  local file_stats, _ = rescore_utility.generate_statistics_from_logs(logs, threshold)

  local file_stat_format = [[
F-score: %.2f
False positive rate: %.2f %%
False negative rate: %.2f %%
Overall accuracy: %.2f %%
Slowest message: %.2f (%s)
]]

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
  -- epoch tracker
  epoch = epoch or 1

  -- local vars
  local time = rspamd_util.get_ticks()
  local confusion = optim.ConfusionMatrix({'ham', 'spam'})

  -- do one epoch

  local lbfgsState
  local sgdState

  local batch_size = opt.batch_size

  logger.messagex("trainer epoch #%s, %s batch", epoch, batch_size)

  for t = 1,dataset:size(),batch_size do
    -- create mini batch
    local k = 1
    local last = math.min(t + batch_size - 1, dataset:size())
    local inputs = torch.Tensor(last - t + 1, #all_symbols)
    local targets = torch.Tensor(last - t + 1)
    for i = t,last do
      -- load new sample
      local sample = dataset[i]
      local input = sample[1]:clone()
      local target = sample[2]:clone()
      --target = target:squeeze()
      inputs[k] = input
      targets[k] = target
      k = k + 1
    end

    local parameters,gradParameters = model:getParameters()

    -- create closure to evaluate f(X) and df/dX
    local feval = function(x)
      -- just in case:
      collectgarbage()

      -- get new parameters
      if x ~= parameters then
        parameters:copy(x)
      end

      -- reset gradients
      gradParameters:zero()

      -- evaluate function for complete mini batch
      local outputs = model:forward(inputs)
      local f = criterion:forward(outputs, targets)

      -- estimate df/dW
      local df_do = criterion:backward(outputs, targets)
      model:backward(inputs, df_do)

      -- penalties (L1 and L2):
      local l1 = tonumber(opt.l1) or 0
      local l2 = tonumber(opt.l2) or 0

      if l1 ~= 0 or l2 ~= 0 then
        -- locals:
        local norm,sign= torch.norm,torch.sign

        local diff = parameters - initial_weights
        -- Loss:
        f = f + l1 * norm(diff,1)
        f = f + l2 * norm(diff,2)^2/2

        -- Gradients:
        gradParameters:add( sign(diff):mul(l1) + diff:clone():mul(l2) )
      end

      -- update confusion
      for i = 1,(last - t + 1) do
        local class_predicted, target_class = 1, 1
        if outputs[i][1] > 0.5 then class_predicted = 2 end
        if targets[i] > 0.5 then target_class = 2 end
        confusion:add(class_predicted, target_class)
      end

      -- return f and df/dX
      return f,gradParameters
    end

    -- optimize on current mini-batch
    if opt.optimization == 'LBFGS' then

      -- Perform LBFGS step:
      lbfgsState = lbfgsState or {
        maxIter = opt.iters,
        lineSearch = optim.lswolfe
      }
      optim.lbfgs(feval, parameters, lbfgsState)

      -- disp report:
      logger.messagex('LBFGS step')
      logger.messagex(' - progress in batch: ' .. t .. '/' .. dataset:size())
      logger.messagex(' - nb of iterations: ' .. lbfgsState.nIter)
      logger.messagex(' - nb of function evalutions: ' .. lbfgsState.funcEval)

    elseif opt.optimization == 'ADAM' then
      sgdState = sgdState or {
        learningRate = tonumber(opts.learning_rate),-- opt.learningRate,
        momentum = tonumber(opts.momentum), -- opt.momentum,
        learningRateDecay = tonumber(opts.learning_rate_decay),
        weightDecay = tonumber(opts.weight_decay),
      }
      optim.adam(feval, parameters, sgdState)
    elseif opt.optimization == 'ADAGRAD' then
      sgdState = sgdState or {
        learningRate = tonumber(opts.learning_rate),-- opt.learningRate,
        momentum = tonumber(opts.momentum), -- opt.momentum,
        learningRateDecay = tonumber(opts.learning_rate_decay),
        weightDecay = tonumber(opts.weight_decay),
      }
      optim.adagrad(feval, parameters, sgdState)
    elseif opt.optimization == 'SGD' then
      sgdState = sgdState or {
        learningRate = tonumber(opts.learning_rate),-- opt.learningRate,
        momentum = tonumber(opts.momentum), -- opt.momentum,
        learningRateDecay = tonumber(opts.learning_rate_decay),
        weightDecay = tonumber(opts.weight_decay),
      }
      optim.sgd(feval, parameters, sgdState)
    elseif opt.optimization == 'NAG' then
      sgdState = sgdState or {
        learningRate = tonumber(opts.learning_rate),-- opt.learningRate,
        momentum = tonumber(opts.momentum), -- opt.momentum,
        learningRateDecay = tonumber(opts.learning_rate_decay),
        weightDecay = tonumber(opts.weight_decay),
      }
      optim.nag(feval, parameters, sgdState)
    else
      error('unknown optimization method')
    end
  end

  -- time taken
  time = rspamd_util.get_ticks() - time
  time = time / dataset:size()
  logger.messagex("time to learn 1 sample = " .. (time*1000) .. 'ms')

  -- logger.messagex confusion matrix
  logger.messagex('confusion: %s', tostring(confusion))
  logger.messagex('%s mean class accuracy (train set)', confusion.totalValid * 100)
  confusion:zero()
end


local default_opts = {
  verbose = true,
  iters = 10,
  threads = 1,
  batch_size = 1000,
  optimization = 'ADAM',
  learning_rate_decay = 0.001,
  momentum = 0.1,
  l1 = 0.0,
  l2 = 0.0,
}

local learning_rates = {
  0.01
}
local penalty_weights = {
  0
}

local function get_threshold()
  local actions = rspamd_config:get_all_actions()

  if opts['spam-action'] then
    return (actions[opts['spam-action']] or 0),actions['reject']
  end
  return (actions['add header'] or actions['rewrite subject']
      or actions['reject']), actions['reject']
end

return function (args, cfg)
  opts = default_opts
  opts = lua_util.override_defaults(opts, getopt.getopt(args, 'i:'))
  local threshold,reject_score = get_threshold()
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

  local all_symbols = rescore_utility.get_all_symbols(logs, ignore_symbols)
  local original_symbol_scores = rescore_utility.get_all_symbol_scores(rspamd_config,
      ignore_symbols)

  -- Display hit frequencies
  if opts['z'] then
      local _, all_symbols_stats = rescore_utility.generate_statistics_from_logs(logs, threshold)
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
      print_stats(logs, threshold)

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

  shuffle(logs)
  torch.setdefaulttensortype('torch.FloatTensor')

  local train_logs, validation_logs = split_logs(logs, 70)
  local cv_logs, test_logs = split_logs(validation_logs, 50)

  local dataset = make_dataset_from_logs(train_logs, all_symbols, reject_score)

  -- Start of perceptron training
  local input_size = #all_symbols
  torch.setnumthreads(opts['threads'])

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

      local fscore, fps, fns = calculate_fscore_from_weights(cv_logs,
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

  if cfg["output"] then
    write_scores(new_symbol_scores, cfg["output"])
  end

  if cfg["diff"] then
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
