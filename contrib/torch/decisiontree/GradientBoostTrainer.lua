local dt = require "decisiontree._env"

-- Gradient boosted decision tree trainer
local GradientBoostTrainer = torch.class("dt.GradientBoostTrainer", "dt.DecisionForestTrainer", dt)

function GradientBoostTrainer:__init(opt)
   assert(torch.type(opt) == 'table')

   assert(torch.isTypeOf(opt.treeTrainer, 'dt.CartTrainer'))
   self.treeTrainer = opt.treeTrainer

   assert(torch.isTypeOf(opt.lossFunction, 'nn.Criterion'))
   self.lossFunction = opt.lossFunction

   assert(torch.type(opt.shrinkage) == 'number')
   assert(opt.shrinkage > 0)
   self.shrinkage = opt.shrinkage

   assert(torch.type(opt.downsampleRatio) == 'number')
   assert(opt.downsampleRatio > 0)
   self.downsampleRatio = opt.downsampleRatio

   assert(torch.type(opt.nTree) == 'number')
   assert(opt.nTree > 0)
   self.nTree = opt.nTree

   evalFreq = evalFreq or -1
   assert(torch.type(opt.evalFreq) == 'number')
   assert(torch.round(opt.evalFreq) == opt.evalFreq)
   self.evalFreq = opt.evalFreq

   -- when non-positive, no early-stopping
   earlyStop = earlyStop or (evalFreq-1)
   assert(torch.type(opt.earlyStop) == 'number')
   self.earlyStop = opt.earlyStop

    -- when non-positive, defaults to sqrt(#feature)
   assert(torch.type(opt.featureBaggingSize) == 'number')
   self.featureBaggingSize = opt.featureBaggingSize

   if opt.decisionForest then
      assert(torch.isTypeOf(opt.decisionForest, 'dt.DecisionForest'))
   end
   self.decisionForest = opt.decisionForest

   self.useInitBias = opt.useInitBias
end

function GradientBoostTrainer:computeBias(trainSet, verbose)
   assert(torch.isTypeOf(trainSet, 'dt.DataSet'))

   if verbose then print("Use new bias generated from the training examples.") end

   return -0.5 * self.gradInput:sum() / self.hessInput:sum()
end


function GradientBoostTrainer:initialize(trainSet, verbose)
   assert(torch.isTypeOf(trainSet, 'dt.DataSet'))

   trainSet:initScore()
   self.gradInput, self.hessInput = self.lossFunction:backward2(trainSet.score, trainSet.target)

   -- used for early-stopping (see validate())
   self.stopCount = 0
   self.prevTrainLoss = math.huge
   self.prevTestLoss = math.huge

   if verbose then print("Processing initial decision forest") end

   local decisionForest, bias

   if self.decisionForest then
      local bias = self.useInitBias and self.decisionForest.bias or self:computeBias(trainSet, verbose)

      decisionForest = dt.DecisionForest(self.decisionForest.trees, self.decisionForest.weight, bias)

      local input = trainSet.input
      if torch.isTensor(input) and input.isContiguous and input:isContiguous() then
         score = decisionForest:score(input)
      else
         score:resize(trainSet:size())
         for exampleId=1,trainSet:size() do
            score[exampleId] = decisionForest:score(input[exampleId])
         end
      end
   else
      local bias = self:computeBias(trainSet, verbose)
      decisionForest = dt.DecisionForest({}, torch.Tensor(), bias)

      trainSet.score:fill(bias)
   end

   if verbose then print("Finish loading initial decision forest") end

   return decisionForest
end

-- Trains a decision forest of boosted decision trees.
-- examples are the training examples. validExamples are used for cross-validation.
function GradientBoostTrainer:train(trainSet, featureIds, validSet, verbose)
   assert(torch.isTypeOf(trainSet, 'dt.DataSet'))
   assert(torch.type(featureIds) == 'torch.LongTensor')
   assert(torch.isTypeOf(validSet, 'dt.DataSet'))

   local decisionForest = self:initialize(trainSet, verbose)
   local bestDecisionForest

   if verbose then print(string.format("Get %d featureIds.", featureIds:size(1))) end

   local baggingSize = self.featureBaggingSize > 0 and self.featureBaggingSize or torch.round(math.sqrt(featureIds:size(1)))
   local trainExampleIds = trainSet:getExampleIds()
   local baggingIndices, activeFeatures
   local treeExampleIds

   local timer = torch.Timer()

   for treeId = 1,self.nTree do
      timer:reset()
      if verbose then print(string.format("Begin processing tree number %d of %d", treeId, self.nTree)) end

      -- Get active features
      activeFeatures = activeFeatures or torch.LongTensor()
      if baggingSize < featureIds:size(1) then
         if verbose then print(string.format("Tree %d: Bagging %d from %d features", treeId, baggingSize, featureIds:size(1))) end

         baggingIndices = baggingIndices or torch.LongTensor()
         baggingIndices:randperm(featureIds:size(1))
         activeFeatures:index(featureIds, 1, baggingIndices:narrow(1,1,baggingSize))
      else
         activeFeatures = featureIds
      end

      -- Get data samples
      if self.downsampleRatio < 0.99 then
         local sampleSize = torch.round(trainSet:size() * self.downsampleRatio)

         if verbose then print(string.format("Tree %d: Downsampling %d of %d samples", treeId, sampleSize, trainSet:size())) end

         baggingIndices = baggingIndices or torch.LongTensor()
         baggingIndices:randperm(trainSet:size())

         treeExampleIds = treeExampleIds or torch.LongTensor()
         treeExampleIds:index(trainExampleIds, 1, baggingIndices:narrow(1,1,sampleSize))
      else
         treeExampleIds = trainExampleIds
      end

      if verbose then print(string.format("Tree %d: training CART tree", treeId)) end

      local rootTreeState = dt.GradientBoostState(treeExampleIds, self.gradInput, self.hessInput)
      local cartTree = self.treeTrainer:train(rootTreeState, activeFeatures)

      if verbose then print(string.format("Tree %d: finished training CART tree in %f seconds", treeId, timer:time().real)) end

      decisionForest:add(cartTree, self.shrinkage)

      -- update score
      local predictionScore
      local input = trainSet.input
      if torch.isTensor(input) and input:isContiguous() then
         predictionScore = cartTree:score(trainSet.input, nil, true)
      else
         local size = trainSet:size()
         predictionScore = torch.Tensor(size)
         for exampleId=1,size do
            predictionScore[exampleId] = cartTree:score(trainSet.input[exampleId])
         end
      end
      trainSet.score:add(self.shrinkage, predictionScore)
      self.gradInput, self.hessInput = self.lossFunction:backward2(trainSet.score, trainSet.target)

      if verbose then print(string.format("Tree %d: training complete in %f seconds", treeId, timer:time().real)) end

      -- cross-validation/early-stopping
      if self.evalFreq > 0 and treeId % self.evalFreq == 0 then
         timer:reset()
         local stop, validLoss, bestDecisionForest = self:validate(trainSet, validSet, decisionForest, bestDecisionForest)
         if dt.PROFILE then print("validate tree time: "..timer:time().real) end
         if verbose then print(string.format("Loss: train=%7.4f, valid=%7.4f", trainLoss, validLoss)) end
         if stop then
            if verbose then print(string.format("GBDT early stopped on tree %d", treeId)) end
            break
         end

      end
   end

   return bestDecisionForest or decisionForest
end

function dt.GradientBoostTrainer:validate(trainSet, validSet, decisionForest, bestDecisionForest)
   assert(torch.isTypeOf(trainSet, 'dt.DataSet'))
   assert(torch.isTypeOf(validSet, 'dt.DataSet'))
   assert(torch.isTypeOf(decisionForest, 'dt.DecisionForest'))
   assert(not bestDecisionForest or torch.isTypeOf(decisionForest, 'dt.DecisionForest'))

   -- buffer
   local buffer = dt.getBufferTable('GradientBoost')
   buffer.tensor = buffer.tensor or trainSet.score.new()
   local score = buffer.tensor

   -- per thread loss function (tensors are shared)
   local lossname = torch.typename(self.lossFunction)
   buffer[lossname] = buffer[lossname] or self.lossFunction:clone()
   local lossFunction = buffer[lossname]

   -- TODO batch this for large datasets
   local input = validSet.input
   if torch.isTensor(input) and input.isContiguous and input:isContiguous() then
      score = decisionForest:score(input, 'val')
   else
      score:resize(validSet:size())
      for exampleId=1,validSet:size() do
         score[exampleId] = decisionForest:score(input[exampleId], 'val')
      end
   end
   local validLoss = lossFunction:forward(score, validSet.target)

   -- early stop is not enabled when earlyStop=0
   local stop = false
   if self.earlyStop > 0 then
      -- Track test loss and detect early stop
      if self.prevTestLoss - validLoss < 0 then
         self.stopCount = self.stopCount + 1
      else
         bestDecisionForest = decisionForest:clone()
         self.stopCount = 0
      end

      stop = self.stopCount >= self.earlyStop
   end

   self.prevTestLoss = validLoss

   return stop, validLoss, bestDecisionForest
end

function GradientBoostTrainer:getName()
   return string.format(
      "gbdt-dRatio-%s-maxLeaf-%s-minExample-%s-nTree-%s-shrinkage-%s",
      self.downsampleRatio, self.maxLeafNodes, self.minLeafSize, self.nTree, self.shrinkage
   )
end
