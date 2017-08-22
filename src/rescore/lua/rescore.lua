local argparse = require "argparse"
local torch = require "torch"
local nn = require "nn"
local lua_util = require "lua_util"
local rspamd_logger = require "rspamd_logger"
local ucl = require "ucl"

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

   weights = torch.Tensor(#all_symbols)

   for i, symbol in pairs(all_symbols) do
      local score = original_symbol_scores[symbol]
      if not score then score = 0 end

      score = score + math.random() - 0.5
      
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

local function split_train_test(logs, split_percent)

   if not split_percent then
      split_percent = 70
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


local function update_logs(logs, new_symbol_scores)

   for i, log in ipairs(logs) do
      log = rescore_utility.string_split(log, " ")
      local score = 0
      for i=4,#log do
	 log[i] = log[i]:gsub("%s+", "")
	 score = score + new_symbol_scores[log[i]]
      end
      log[2] = rescore_utility.round(score, 2)

      logs[i] = table.concat(log, " ")
   end

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

parser:option("-i --iters", "Number of iterations", 1000, tonumber)
parser:option("-l --logdir", "Path to log files")
parser:option("-r --rate", "Learning rate", 1, tonumber)
parser:option("-t --threshold", "Set spam threshold", 15, tonumber)
parser:option("-d --decay", "Set learning rate decay", 1, tonumber)
parser:option("-o --output", "Write new scores to file in json")
parser:flag("--diff", "Print score diff")

local params = parser:parse()

local logs = rescore_utility.get_all_logs(params.logdir)
local all_symbols = rescore_utility.get_all_symbols(logs)
local original_symbol_scores = rescore_utility.get_all_symbol_scores()

shuffle(logs)

local train_logs, test_logs = split_train_test(logs)

local dataset = make_dataset_from_logs(train_logs, all_symbols)

-- Start of perceptron training

local input_size = #all_symbols
local linear_module = nn.Linear(input_size, 1)

linear_module.weight[1] = init_weights(all_symbols, original_symbol_scores)

local perceptron = nn.Sequential()
perceptron:add(linear_module)
perceptron:add(nn.Tanh())

local criterion = nn.MSECriterion()
criterion.sizeAverage = false

trainer = nn.StochasticGradient(perceptron, criterion)
trainer.maxIteration = params.iters
trainer.learningRate = params.rate
trainer.learningRateDecay = params.decay

trainer:train(dataset)

-- End perceptron training

local scale_factor = params.threshold / linear_module.bias[1]

local new_symbol_scores = linear_module.weight[1]:clone()

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
print_stats(test_logs, 15)

-- Post-rescore test stats
update_logs(test_logs, new_symbol_scores)
print("\n\nPost-rescore test stats\n")
print_stats(test_logs, 15)


