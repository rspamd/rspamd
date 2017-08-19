local argparse = require "argparse"
local torch = require "torch"
local nn = require "nn"
local lua_util = require "lua_util"
local rspamd_logger = require "rspamd_logger"
local json = require "json"

local utility = require "utility"

local function inspect(tab)
   rspamd_logger.infox("%s", tab)
end

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

local function write_new_log_file(logs, all_symbols, new_score, file_path)

   local new_symbol_scores = {}

   for idx, symbol in pairs(all_symbols) do
      new_symbol_scores[symbol] = new_score[idx]
   end

   local f = io.open(file_path, "w")

   for _, log in pairs(logs) do
      log = utility.string_split(log, " ")
      local score = 0
      for i=4,#log do
	 log[i] = log[i]:gsub("%s+", "")
	 score = score + new_symbol_scores[log[i]]
      end
      log[2] = utility.round(score, 2)

      for k, v in pairs(log) do
	 f:write(v .. " ")
      end
      f:write("\r\n")
   end
   
end

local function write_scores(all_symbols, new_scores, file_path)
   
   local file = assert(io.open(file_path, "w"))

   for idx, symbol in pairs(all_symbols) do
      file:write(string.format("%-35s %.2f\n", symbol, new_scores[idx]))
   end
   
   file:close()
end

local function print_score_diff(all_symbols, new_scores, original_symbol_scores)

   print(string.format("%-35s %-10s %-10s", "SYMBOL", "OLD_SCORE", "NEW_SCORE"))

   for idx, symbol in pairs(all_symbols) do
      print(string.format("%-35s %-10s %-10s",
			  symbol,
			  original_symbol_scores[symbol] or 0,
			  utility.round(new_scores[idx], 2)))
   end
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

local logs = utility.get_all_logs(params.logdir)
local all_symbols = utility.get_all_symbols(logs)
local original_symbol_scores = utility.get_all_symbol_scores()

local dataset = make_dataset_from_logs(logs, all_symbols)

-- Start of perceptron training

local input_size = #all_symbols
local module = nn.Linear(input_size, 1)

module.weight[1] = init_weights(all_symbols, original_symbol_scores)
module.bias[1] = 15

local perceptron = nn.Sequential()
perceptron:add(module)
perceptron:add(nn.Sigmoid())

local criterion = nn.MSECriterion()
trainer = nn.StochasticGradient(perceptron, criterion)
trainer.maxIteration = params.iters
trainer.learningRate = params.rate
trainer.learningRateDecay = params.decay
trainer:train(dataset)

-- End perceptron training

local scale_factor = params.threshold / module.bias[1]

local new_scores = module.weight[1]:clone()

new_scores:apply( function(wt) wt = wt * scale_factor end )

if params.output then
   write_scores(all_symbols, new_scores, params.output)
end

if params.diff then
   print_score_diff(all_symbols, new_scores, original_symbol_scores)
end


-- TESTING
-- Writing log file with new scores to be used by statistics.lua
write_new_log_file(logs, all_symbols, new_scores, "newlogs/results.log")

