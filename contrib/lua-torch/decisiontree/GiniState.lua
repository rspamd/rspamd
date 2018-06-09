local dt = require 'decisiontree._env'

-- used by RandomForestTrainer
local GiniState, parent = torch.class("dt.GiniState", "dt.TreeState", dt)

function GiniState:__init(exampleIds)
   parent.__init(self, exampleIds)
   self.nPositiveInLeftBranch = 0
   self.nPositiveInRightBranch = 0
end

function GiniState:score(dataset)
   local dt = require 'decisiontree'
   local nPositive = dataset:countPositive(self.exampleIds)
   return dt.calculateLogitScore(nPositive, self.exampleIds:size(1))
end

function GiniState:initialize(exampleIdsWithFeature, dataset)
   assert(torch.type(exampleIdsWithFeature) == 'torch.LongTensor')
   assert(torch.isTypeOf(dataset, 'dt.DataSet'))
   self.nPositiveInLeftBranch = dataset:countPositive(exampleIdsWithFeature)
   self.nPositiveInRightBranch = 0

   self.nExampleInLeftBranch = exampleIdsWithFeature:size(1)
   self.nExampleInRightBranch = 0
end

function GiniState:update(exampleId, dataset)
   assert(torch.type(exampleId) == 'number')
   assert(torch.isTypeOf(dataset, 'dt.DataSet'))
   if dataset.target[exampleId] > 0 then
      self.nPositiveInLeftBranch = self.nPositiveInLeftBranch - 1
      self.nPositiveInRightBranch = self.nPositiveInRightBranch + 1
   end

   self.nExampleInLeftBranch = self.nExampleInLeftBranch - 1
   self.nExampleInRightBranch = self.nExampleInRightBranch + 1
end

function GiniState:computeSplitInfo(splitFeatureId, splitFeatureValue)
   local dt = require 'decisiontree'
   local gini = dt.computeGini(self.nExampleInLeftBranch, self.nPositiveInLeftBranch, self.nExampleInRightBranch, self.nPositiveInRightBranch)
   local splitInfo = {
      splitId = assert(splitFeatureId),
      splitValue = assert(splitFeatureValue),
      leftChildSize = assert(self.nExampleInLeftBranch),
      leftPositiveCount = assert(self.nPositiveInLeftBranch),
      rightChildSize = assert(self.nExampleInRightBranch),
      rightPositiveCount = assert(self.nPositiveInRightBranch),
      gini = assert(gini),
      splitGain = gini
   }
   return splitInfo
end