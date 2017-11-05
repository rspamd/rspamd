local dt = require 'decisiontree._env'

local GradientBoostState, parent = torch.class("dt.GradientBoostState", "dt.TreeState", dt)

function GradientBoostState:__init(exampleIds, gradInput, hessInput)
   parent.__init(self, exampleIds)
   self.gradInput = gradInput
   self.hessInput = hessInput
end

function GradientBoostState:score(dataset)
   local dt = require 'decisiontree'
   local gradInput = self.gradInput:index(1, self.exampleIds)
   local hessInput = self.hessInput:index(1, self.exampleIds)
   return dt.computeNewtonScore(gradInput:sum(), hessInput:sum())
end

-- calls _branch and encapsulates the left and right exampleIds into a TreeStates
function GradientBoostState:branch(splitInfo, dataset)
   local leftExampleIds, rightExampleIds = self:_branch(splitInfo, dataset)
   return self.new(leftExampleIds, self.gradInput, self.hessInput), self.new(rightExampleIds, self.gradInput, self.hessInput)
end

-- Partitions self given a splitInfo table, producing a pair of exampleIds corresponding to the left and right subtrees.
function GradientBoostState:_branch(splitInfo, dataset)
   local input = dataset.input
   -- if the input is dense, we can use the optimized version
   if torch.isTensor(input) and input.isContiguous and input:isContiguous() and input:nDimension() == 2 then
      return input.nn.GBDT_branch(splitInfo, input, self.exampleIds)
   end
   return parent._branch(self, splitInfo, dataset)
end

-- The following methods are supersets of each other. You can comment out them to re-use the lua
-- version with just the provided core optimized

-- THIS ONE CANNOT BE COMMENTED OUT
function GradientBoostState:findBestFeatureSplit(dataset, featureId, minLeafSize)
   local ret = self.hessInput.nn.GBDT_findBestFeatureSplit(self.exampleIds, dataset, featureId, minLeafSize, self.gradInput, self.hessInput)
   return ret
end

-- finds the best split of examples in treeState among featureIds
function GradientBoostState:findBestSplit(dataset, featureIds, minLeafSize, shardId, nShard)
   local ret = self.hessInput.nn.GBDT_findBestSplit(self.exampleIds, dataset, featureIds, minLeafSize, shardId, nShard, self.gradInput, self.hessInput)
   return ret
end

-- finds the best split like the previous one, but performs feature parallelism. Note that the
-- optimization is only applied if the input is dense
function GradientBoostState:findBestSplitFP(dataset, featureIds, minLeafSize, nThread)
   local input = dataset.input
   if torch.isTensor(input) and input.isContiguous and input:isContiguous() and input:nDimension() == 2 then
      local ret = self.hessInput.nn.GBDT_findBestSplitFP(self.exampleIds, dataset, featureIds, minLeafSize, self.gradInput, self.hessInput, nThread)
      return ret
   end
end
