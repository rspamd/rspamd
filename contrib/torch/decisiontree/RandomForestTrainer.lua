local dt = require "decisiontree._env"

local RandomForestTrainer = torch.class("dt.RandomForestTrainer", dt)

function RandomForestTrainer:__init(opt)
   assert(torch.type(opt.nTree) == 'number')
   assert(opt.nTree > 0)
   self.nTree = opt.nTree
   -- max number of leaf nodes per tree
   assert(torch.type(opt.maxLeafNodes) == 'number')
   assert(opt.maxLeafNodes > 0)
   self.maxLeafNodes = opt.maxLeafNodes
   -- min number of examples per leaf
   assert(torch.type(opt.minLeafSize) == 'number')
   assert(opt.minLeafSize > 0)
   self.minLeafSize = opt.minLeafSize

   -- when non-positive, defaults to sqrt(#feature)
   assert(torch.type(opt.featureBaggingSize) == 'number')
   self.featureBaggingSize = opt.featureBaggingSize

   assert(torch.type(opt.activeRatio) == 'number')
   assert(opt.activeRatio > 0)
   self.activeRatio = opt.activeRatio

   -- default parallelization is singlethread
   self.parallelMode = 'singlethread'
end

-- Train a DecisionForest
function RandomForestTrainer:train(trainSet, featureIds, verbose)
   assert(torch.isTypeOf(trainSet, 'dt.DataSet'))
   assert(torch.type(featureIds) == 'torch.LongTensor')

   if verbose then print(string.format("Begin training Decision Forest with %d trees", self.nTree)) end

   local weight = torch.Tensor(self.nTree):fill(1 / self.nTree) -- RF uses uniform weights

   local trees
   if self.parallelMode == 'singlethread' then
      trees = self:trainTrees(trainSet, featureIds, verbose)
   elseif self.parallelMode == 'treeparallel' then
      trainSet:deleteIndex() -- prevents serialization bottleneck
      trees = self:trainTreesTP(trainSet, featureIds, verbose)
   else
      error("Unrecognized parallel mode: " .. self.parallelMode)
   end

   if verbose then print(string.format("Successfully trained %d trees", #trees)) end

   -- set bias
   local bias = 0;
   for i, tree in ipairs(trees) do
      bias = bias + tree.root.score * weight[i]
   end

   return dt.DecisionForest(trees, weight, bias)
end

function RandomForestTrainer:trainTrees(trainSet, featureIds, verbose)

   -- the same CartTrainer will be used for each tree
   local cartTrainer = dt.CartTrainer(trainSet, self.minLeafSize, self.maxLeafNodes)

   local trees = {}
   for treeId=1,self.nTree do
      -- Train a CartTree
      local tree = self.trainTree(cartTrainer, featureIds, self.featureBaggingSize, self.activeRatio, treeId, verbose)
      table.insert(trees, tree)
   end
   return trees
end

-- static function that returns a cartTree
function RandomForestTrainer.trainTree(cartTrainer, featureIds, baggingSize, activeRatio, treeId, verbose)
   assert(torch.isTypeOf(cartTrainer, 'dt.CartTrainer'))
   assert(torch.type(featureIds) == 'torch.LongTensor')
   local baggingSize = baggingSize > 0 and baggingSize or torch.round(math.sqrt(featureIds:size(1)))

   if verbose then
      print(string.format("Tree %d: Creating features bootstrap sample with baggingSize %d, nFeatures %d", treeId, baggingSize, featureIds:size(1)))
   end

   local trainSet = cartTrainer.dataset

   -- sample boot strap features
   local baggingIndices = torch.LongTensor(baggingSize):random(1,featureIds:size(1))
   local activeFeatures = featureIds:index(1, baggingIndices)

    -- sample boot strap examples
   local sampleSize = torch.round(trainSet:size() * activeRatio)
   if verbose then print(string.format("Creating bootstrap sample created of size %d", sampleSize)) end

   baggingIndices:resize(sampleSize):random(1,trainSet:size())
   local bootStrapExampleIds = torch.LongTensor()
   bootStrapExampleIds:index(trainSet:getExampleIds(), 1, baggingIndices)

   local cartTree = cartTrainer:train(dt.GiniState(bootStrapExampleIds), activeFeatures)

   if verbose then print(string.format("Complete processing tree number %d", treeId)) end

   return cartTree
end

-- call before training to enable tree-level parallelization
function RandomForestTrainer:treeParallel(workPool)
   assert(self.parallelMode == 'singlethread', self.parallelMode)
   self.parallelMode = 'treeparallel'
   self.workPool = torch.type(workPool) == 'number' and dt.WorkPool(workPool) or workPool
   assert(torch.isTypeOf(self.workPool, 'dt.WorkPool'))

   -- require the dt package
   self.workPool:update('require', {libname='decisiontree',varname='dt'})
end

-- TP is for tree parallel (not toilet paper)
function RandomForestTrainer:trainTreesTP(trainSet, featureIds, verbose)
   assert(torch.isTypeOf(trainSet, 'dt.DataSet'))
   assert(torch.type(featureIds) == 'torch.LongTensor')
   local minLeafSize = self.minLeafSize
   local maxLeafNodes = self.maxLeafNodes

   -- setup worker store (each worker will have its own cartTrainer)
   self.workPool:updateup('execute', function(store)
      local dt = require 'decisiontree'

      store.cartTrainer = dt.CartTrainer(trainSet, minLeafSize, maxLeafNodes)
      store.featureIds = featureIds
   end)

   for treeId=1,self.nTree do
      -- upvalues
      local baggingSize = self.featureBaggingSize
      local activeRatio = self.activeRatio
      -- task closure that will be executed in worker-thread
      local function trainTreeTask(store)
         local dt = require 'decisiontree'
         return dt.RandomForestTrainer.trainTree(store.cartTrainer, store.featureIds, baggingSize, activeRatio, treeId, verbose)
      end
      self.workPool:writeup('execute', trainTreeTask)
   end

   local trees = {}
   for treeId=1,self.nTree do
      local taskname, tree = self.workPool:read()
      assert(taskname=='execute')
      assert(torch.isTypeOf(tree, 'dt.CartTree'))
      table.insert(trees, tree)
   end
   return trees
end

function RandomForestTrainer:getName()
   return string.format(
      "randomforest-aRatio-%4.2f-maxLeaf-%d-minExample-%d-nTree-%d",
      self.activeRatio, self.maxLeafNodes, self.minLeafSize, self.nTree
   )
end

