local argparse = require "argparse"
local torch = require "torch"
local nn = require "nn"
local lua_util = require "lua_util"
local rspamd_logger = require "rspamd_logger"
local ucl = require "ucl"
local nninit = require "nninit"

local rescore_utility = require "rescore_utility"

local function weight_to_score(weight, bias, threshold) 
   return weight * threshold / bias
end

local function score_to_weight(weight,  bias, threshold)
   return weight * bias / threshold
end

local function make_dataset_from_logs(logs, all_symbols)
   -- Returns a list of {input, output} for torch SGD train

   local dataset = {}
   
   for temp, log in pairs(logs) do
      input = torch.Tensor(#all_symbols)
      output = torch.Tensor(1)
      log = lua_util.rspamd_str_split(log, " ")

      if log[1] == "SPAM" then
	 output[1] = 1
      else
	 output[1] = 0
      end
      
      local symbols_set = {}

      for i=4,#log do
	 symbols_set[log[i]] = true
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
   local size = weights:size()[1]
   
   local mean = 0
   
   for i, symbol in pairs(all_symbols) do
      local score = original_symbol_scores[symbol]
      if not score then score = 0 end
      weights[i] = score
      mean = mean + score
   end
--[[
   mean = mean / size

   local dev = 0
   for i=1,size do
      dev = dev + (weights[i] - mean) * (weights[i] - mean)
   end

   dev = math.sqrt(dev / size)
   
   for i=1,size do
      weights[i] = (weights[i] - mean) / dev
   end
]]
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

   local split_index = #logs * split_percent / 100

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
      for i=4,#log do
	 log[i] = log[i]:gsub("%s+", "")
	 score = score + (symbol_scores[log[i]] or 0)
      end
      log[2] = rescore_utility.round(score, 2)

      logs[i] = table.concat(log, " ")
   end

   return logs
end

local function write_scores(new_symbol_scores, file_path)
   
   local file = assert(io.open(file_path, "w"))

   local new_scores_json = ucl.to_format(new_symbol_scores, "json")

   file:write(new_scores_json)
   
   file:close()
end

local function print_score_diff(new_symbol_scores, original_symbol_scores)

   print(string.format("%-35s %-10s %-10s", "SYMBOL", "OLD_SCORE", "NEW_SCORE"))

   for symbol, new_score in pairs(new_symbol_scores) do
      print(string.format("%-35s %-10s %-10s",
			  symbol,
			  original_symbol_scores[symbol] or 0,
			  rescore_utility.round(new_score, 2)))
   end

   print "\nClass changes \n"
   for symbol, new_score in pairs(new_symbol_scores) do
      if original_symbol_scores[symbol] ~= nil then
	 if (original_symbol_scores[symbol] > 0 and new_score < 0) or
	 (original_symbol_scores[symbol] < 0 and new_score > 0) then
	       print(string.format("%-35s %-10s %-10s",
				   symbol,
				   original_symbol_scores[symbol] or 0,
				   rescore_utility.round(new_score, 2)))
	 end
      end

   end
      
end

local function calculate_fscore_from_weights(logs, all_symbols, weights, bias, threshold)

   local scale_factor = threshold / bias
   local new_symbol_scores = weights:clone()

   new_symbol_scores:apply( function(wt) wt = wt * scale_factor end )
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

   io.write("\nStatistics at threshold: " .. threshold .. "\n")
   
   io.write(string.format(file_stat_format,
			  file_stats.fscore,
			  file_stats.false_positive_rate,
			  file_stats.false_negative_rate,
			  file_stats.overall_accuracy))

end

local parser = argparse() {
   name = "rescore",
   description = "Rescore symbols using perceptron"
}

parser:option("-i --iters", "Number of iterations", 500, tonumber)
parser:option("-l --logdir", "Path to log files")
parser:option("-r --rate", "Learning rate", 1, tonumber)
parser:option("-t --threshold", "Set spam threshold", 15, tonumber)
parser:option("-o --output", "Write new scores to file in json")
parser:flag("--diff", "Print score diff")

parser:mutex(
   parser:flag("--tanh", "Use tanh as activation function instead of sigmoid"),
   parser:flag("--relu", "Use ReLU as activation function instead of sigmoid"),
   parser:flag("--leakyrelu", "Use leaky ReLU as activation function instead of sigmoid")
)


local params = parser:parse()

local logs = rescore_utility.get_all_logs(params.logdir)
local all_symbols = rescore_utility.get_all_symbols(logs)
local original_symbol_scores = rescore_utility.get_all_symbol_scores()

shuffle(logs)

local train_logs, test_logs = split_logs(logs, 70)
local cv_logs, test_logs = split_logs(test_logs, 50)

local dataset = make_dataset_from_logs(train_logs, all_symbols)

local learning_rates = {0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 2.5, 5, 7.5, 10}
local penalty_weights = {0, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 3, 5, 10, 15, 20, 25, 50, 75, 100}

-- Start of perceptron training

local input_size = #all_symbols
local linear_module = nn.Linear(input_size, 1)
   
local perceptron = nn.Sequential()
perceptron:add(linear_module)

local activation

if params.tanh then
   activation = nn.Tanh()
elseif params.relu then
   activation = nn.ReLU()
elseif params.leakyrelu then
   activation = nn.LeakyReLU()
else
   activation = nn.Sigmoid()
end

perceptron:add(activation)

local criterion = nn.MSECriterion()
criterion.sizeAverage = false

local best_fscore = -math.huge
local best_weights = linear_module.weight[1]:clone()
local best_weights_bias = linear_module.bias[1]
local l1_weight = 0
local l2_weight = 0

trainer = nn.StochasticGradient(perceptron, criterion)
trainer.maxIteration = params.iters
trainer.verbose = false

local function regularize_parameters(network, l1_weight, l2_weight)

   local parameters, _ = network:parameters()
   for i = 1, table.getn(parameters) do
      local update = torch.clamp(parameters[i], -l1_weight, l1_weight)
      update:add(parameters[i]:mul(-l2_weight))
      parameters[i]:csub(update)      
   end
end

trainer.hookIteration = function(self, iteration, error)

   if iteration == trainer.maxIteration then

      fscore = calculate_fscore_from_weights(cv_logs,
					     all_symbols,
					     linear_module.weight[1],
					     linear_module.bias[1],
					     params.threshold)
      
      print("Cross-validation fscore: " .. fscore)
      
      if best_fscore < fscore then
	 best_fscore = fscore
	 best_weights = linear_module.weight[1]:clone()
	 best_weights_bias = linear_module.bias[1]
      end
   end
end

for _, learning_rate in pairs(learning_rates) do
   for _, weight in pairs(penalty_weights) do

      trainer.weightDecay = weight
      print("Learning with learning_rate: " .. learning_rate .. " | l2_weight: " .. weight)
   
      linear_module.weight[1] = init_weights(all_symbols, original_symbol_scores)

      trainer.learningRate = learning_rate
      trainer:train(dataset)
   
      print()
   end   
end

-- End perceptron training

local scale_factor = params.threshold / best_weights_bias

local new_symbol_scores = best_weights

new_symbol_scores:apply( function(wt) wt = wt * scale_factor end )

new_symbol_scores = stitch_new_scores(all_symbols, new_symbol_scores)

if params.output then
   write_scores(new_symbol_scores, params.output)
end

if params.diff then
   print_score_diff(new_symbol_scores, original_symbol_scores)
end


-- Pre-rescore test stats
print("\n\nPre-rescore test stats\n")
test_logs = update_logs(test_logs, original_symbol_scores)
print_stats(test_logs, 15)

-- Post-rescore test stats
test_logs = update_logs(test_logs, new_symbol_scores)
print("\n\nPost-rescore test stats\n")
print_stats(test_logs, 15)

