local torch = require "torch"
local nn = require "nn"
local lua_util = require "lua_util"
local rspamd_logger = require "rspamd_logger"

local utility = require "utility"

local function inspect(tab)
   rspamd_logger.infox("%s", tab)
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


local cmd = torch.CmdLine()
cmd:text()
cmd:text()
cmd:text("Rescore symbols using perceptron")
cmd:text()
cmd:text("Options")
cmd:text()
cmd:option("-logdir", "logs", "Specify directory to read logs from")
cmd:option("-iters", 10, "Number of iterations")

local params = cmd:parse(arg)

local logs = utility.get_all_logs(params.logdir)
local all_symbols = utility.get_all_symbols(logs)

local dataset = make_dataset_from_logs(logs, all_symbols)


-- Start of perceptron training
local input_size = #all_symbols
local module = nn.Linear(input_size, 1)

local perceptron = nn.Sequential()
perceptron:add(module)
perceptron:add(nn.Sigmoid())

local criterion = nn.MSECriterion()
trainer = nn.StochasticGradient(perceptron, criterion)
trainer.maxIteration = params.iters
trainer:train(dataset)


local scale = 15 / module.bias[1]

for i=1,#all_symbols do
   print(all_symbols[i], utility.round(module.weight[1][i] * scale, 2))
end

print(module.bias)




