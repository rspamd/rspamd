local dt = require "decisiontree._env"

local TreeState = torch.class("dt.TreeState", dt)

-- Holds the state of a subtree during decision tree training.
-- Also, manages the state of candidate splits
function TreeState:__init(exampleIds)
   assert(torch.type(exampleIds) == 'torch.LongTensor')
   self.exampleIds = exampleIds

   self.nExampleInLeftBranch = 0
   self.nExampleInRightBranch = 0
end

-- computes and returns the score of the node based on its examples
function TreeState:score(dataset)
   error"NotImplemented"
end


-- Initializes the split-state-updater. Initially all examples are in the left branch.
-- exampleIdsWithFeature is list of examples to split (those having a particular feature)
function TreeState:initialize(exampleIdsWithFeature, dataset)
   error"NotImplemented"
end

-- Update the split state. This call has the effect of shifting the example from the left to the right branch.
function TreeState:update(exampleId, dataset)
   error"NotImplemented"
end

-- Computes the SplitInfo determined by the current split state
-- @param splitFeatureId the feature id of the split feature
-- @param splitFeatureValue the feature value of the split feature
-- @return the SplitInfo determined by the current split state
function TreeState:computeSplitInfo(splitFeatureId, splitFeatureValue)
   error"NotImplemented"
end

-- bottleneck
function TreeState:findBestFeatureSplit(dataset, featureId, minLeafSize)
   local dt = require "decisiontree"
   assert(torch.isTypeOf(dataset, 'dt.DataSet'))
   assert(torch.type(featureId) == 'number')
   assert(torch.type(minLeafSize) == 'number')

   -- all dataset example having this feature, sorted by value
   local featureExampleIds = dataset:getSortedFeature(featureId)

   local buffer = dt.getBufferTable('TreeState')
   buffer.longtensor = buffer.longtensor or torch.LongTensor()
   local exampleIdsWithFeature = buffer.longtensor

   -- map and tensor of examples containing feature:
   local exampleMap = {}
   local getExampleFeatureValue

   local j = 0
   if torch.type(dataset.input) == 'table' then
      exampleIdsWithFeature:resize(self.exampleIds:size())
      self.exampleIds:apply(function(exampleId)
         local input = dataset.input[exampleId]
         input:buildIndex()-- only builds index first time
         if input[featureId] then
            j = j + 1
            exampleIdsWithFeature[j] = exampleId
            exampleMap[exampleId] = j
         end
      end)
      if j == 0 then
         return
      end
      exampleIdsWithFeature:resize(j)
      getExampleFeatureValue = function(exampleId) return dataset.input[exampleId][featureId] end
   else
      exampleIdsWithFeature = self.exampleIds
      self.exampleIds:apply(function(exampleId)
         j = j + 1
         exampleMap[exampleId] = j
      end)
      local featureValues = dataset.input:select(2,featureId)
      getExampleFeatureValue = function(exampleId) return featureValues[exampleId] end
   end


   self:initialize(exampleIdsWithFeature, dataset)

   -- bottleneck
   local bestSplit, previousSplitValue, _tictoc
   for i=featureExampleIds:size(1),1,-1 do -- loop over examples sorted (desc) by feature value
      local exampleId = featureExampleIds[i]

      local exampleIdx = exampleMap[exampleId]
      if exampleIdx then
         local splitValue = getExampleFeatureValue(exampleId)

         if previousSplitValue and math.abs(splitValue - previousSplitValue) > dt.EPSILON then
            local splitInfo = self:computeSplitInfo(featureId, previousSplitValue, _tictoc)
            if (splitInfo.leftChildSize >= minLeafSize) and (splitInfo.rightChildSize >= minLeafSize) then

               if (not bestSplit) or (splitInfo.splitGain < bestSplit.splitGain) then
                  _tictoc = bestSplit or {} -- reuse table
                  bestSplit = splitInfo
               end

            end
         end

         previousSplitValue = splitValue

         -- bottleneck
         self:update(exampleId, dataset, exampleIdx)
      end
   end

   return bestSplit
end

-- finds the best split of examples in treeState among featureIds
function TreeState:findBestSplit(dataset, featureIds, minLeafSize, shardId, nShard)
   assert(torch.isTypeOf(dataset, 'dt.DataSet'))
   assert(torch.type(featureIds) == 'torch.LongTensor')
   assert(torch.type(minLeafSize) == 'number')
   assert(torch.type(shardId) == 'number')
   assert(torch.type(nShard) == 'number')

   local bestSplit
   for i=1,featureIds:size(1) do
      local featureId = featureIds[i]
      if (nShard <= 1) or ( (featureId % nShard) + 1 == shardId ) then -- feature sharded
         local splitCandidate = self:findBestFeatureSplit(dataset, featureId, minLeafSize)
         if splitCandidate and ((not bestSplit) or (splitCandidate.splitGain < bestSplit.splitGain)) then
            bestSplit = splitCandidate
         end
      end
   end

   return bestSplit
end

-- Partitions self given a splitInfo table, producing a pair of exampleIds corresponding to the left and right subtrees.
function TreeState:_branch(splitInfo, dataset)
   local leftIdx, rightIdx = 0, 0
   local nExample = self.exampleIds:size(1)
   local splitExampleIds = torch.LongTensor(nExample)


   for i=1,self.exampleIds:size(1) do
      local exampleId = self.exampleIds[i]
      local input = dataset.input[exampleId]
      local val = input[splitInfo.splitId]
      -- Note: when the feature is not present in the example, the example is droped from all sub-trees.
      -- Which means that for most sparse data, a tree cannot reach 100% accuracy...
      if val then
         if val < splitInfo.splitValue then
            leftIdx = leftIdx + 1
            splitExampleIds[leftIdx] = exampleId
         else
            rightIdx = rightIdx + 1
            splitExampleIds[nExample-rightIdx+1] = exampleId
         end
      end
   end

   local leftExampleIds = splitExampleIds:narrow(1,1,leftIdx)
   local rightExampleIds = splitExampleIds:narrow(1,nExample-rightIdx+1,rightIdx)

   assert(leftExampleIds:size(1) + rightExampleIds:size(1) <= self.exampleIds:size(1), "Left and right branches contain more data than the parent!")
   return leftExampleIds, rightExampleIds
end

-- calls _branch and encapsulates the left and right exampleIds into a TreeStates
function TreeState:branch(splitInfo, dataset)
   local leftExampleIds, rightExampleIds = self:_branch(splitInfo, dataset)
   return self.new(leftExampleIds), self.new(rightExampleIds)
end

function TreeState:size()
   return self.exampleIds:size(1)
end

function TreeState:contains(exampleId)
   local found = false
   self.exampleIds:apply(function(x)
      if x == exampleId then
         found = true
      end
   end)
   return found
end

