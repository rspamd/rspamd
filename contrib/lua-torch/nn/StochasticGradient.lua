local StochasticGradient = torch.class('nn.StochasticGradient')

function StochasticGradient:__init(module, criterion)
   self.learningRate = 0.01
   self.learningRateDecay = 0
   self.maxIteration = 25
   self.shuffleIndices = true
   self.module = module
   self.criterion = criterion
   self.verbose = true
end

function StochasticGradient:train(dataset)
   local iteration = 1
   local currentLearningRate = self.learningRate
   local module = self.module
   local criterion = self.criterion

   local shuffledIndices = torch.randperm(dataset:size(), 'torch.LongTensor')
   if not self.shuffleIndices then
      for t = 1,dataset:size() do
         shuffledIndices[t] = t
      end
   end

   print("# StochasticGradient: training")

   while true do
      local currentError = 0
      for t = 1,dataset:size() do
         local example = dataset[shuffledIndices[t]]
         local input = example[1]
         local target = example[2]

         currentError = currentError + criterion:forward(module:forward(input), target)

         module:updateGradInput(input, criterion:updateGradInput(module.output, target))
         module:accUpdateGradParameters(input, criterion.gradInput, currentLearningRate)

         if self.hookExample then
            self.hookExample(self, example)
         end
      end

      currentError = currentError / dataset:size()

      if self.hookIteration then
         self.hookIteration(self, iteration, currentError)
      end

      if self.verbose then
         print("# current error = " .. currentError)
      end
      iteration = iteration + 1
      currentLearningRate = self.learningRate/(1+iteration*self.learningRateDecay)
      if self.maxIteration > 0 and iteration > self.maxIteration then
         print("# StochasticGradient: you have reached the maximum number of iterations")
         print("# training error = " .. currentError)
         break
      end
   end
end
