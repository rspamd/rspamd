local dt = require "decisiontree._env"
local _ = require "moses"

local CartTrainer = torch.class("dt.CartTrainer", dt)

-- Generic CART trainer
function CartTrainer:__init(dataset, minLeafSize, maxLeafNodes)
   assert(torch.isTypeOf(dataset, 'dt.DataSet'))
   self.dataset = dataset
   self.minLeafSize = assert(minLeafSize) -- min examples per leaf
   self.maxLeafNodes = assert(maxLeafNodes) -- max leaf nodes in tree

   -- by default, single thread
   self.parallelMode = 'singlethread'
end

function CartTrainer:train(rootTreeState, activeFeatures)
   assert(torch.isTypeOf(rootTreeState, 'dt.TreeState'))
   assert(torch.isTensor(activeFeatures))
   local root = dt.CartNode()
   root.id = 0
   root.score = rootTreeState:score(self.dataset)

   local nleaf = 1

   -- TODO : nodeparallel: parallelize here. The queue is a workqueue.
   local queue = {}
   table.insert(queue, 1, {cartNode=root, treeState=rootTreeState})

   while #queue > 0 and nleaf < self.maxLeafNodes do
      local treeGrowerArgs = table.remove(queue, #queue)
      local currentTreeState = treeGrowerArgs.treeState

      -- Note: if minLeafSize = 1 and maxLeafNode = inf, then each example will be its own leaf...
      if self:hasEnoughTrainingExamplesToSplit(currentTreeState.exampleIds:size(1)) then
         nleaf = self:processNode(nleaf, queue, treeGrowerArgs.cartNode, currentTreeState, activeFeatures)
      end
   end

   -- CartTree with random branching (when feature is missing)
   local branchleft = function() return math.random() < 0.5 end
   return dt.CartTree(root, branchleft), nleaf
end

function CartTrainer:processNode(nleaf, queue, node, treeState, activeFeatures)
   local bestSplit
   if self.parallelMode == 'singlethread' then
      bestSplit = self:findBestSplitForAllFeatures(treeState, activeFeatures)
   elseif self.parallelMode == 'featureparallel' then
      bestSplit = self:findBestSplitForAllFeaturesFP(treeState, activeFeatures)
   else
      error("Unrecognized parallel mode: " .. self.parallelMode)
   end

   if bestSplit then
      local leftTreeState, rightTreeState = treeState:branch(bestSplit, self.dataset)
      assert(bestSplit.leftChildSize + bestSplit.rightChildSize == leftTreeState.exampleIds:size(1) + rightTreeState.exampleIds:size(1), "The left and right subtrees don't match the split found!")
      self:setValuesAndCreateChildrenForNode(node, bestSplit, leftTreeState, rightTreeState, nleaf)

      table.insert(queue, 1, {cartNode=node.leftChild, treeState=leftTreeState})
      table.insert(queue, 1, {cartNode=node.rightChild, treeState=rightTreeState})

      return nleaf + 1
    end

    return nleaf
end

function CartTrainer:findBestSplitForAllFeatures(treeState, activeFeatures)
   local timer = torch.Timer()
   local bestSplit = treeState:findBestSplit(self.dataset, activeFeatures, self.minLeafSize, -1, -1)

   if bestSplit then
      assert(torch.type(bestSplit) == 'table')
   end

   if dt.PROFILE then
      print("findBestSplitForAllFeatures time="..timer:time().real)
   end
   return bestSplit
end

-- Updates the parentNode with the bestSplit information by creates left/right child Nodes.
function CartTrainer:setValuesAndCreateChildrenForNode(parentNode, bestSplit, leftState, rightState, nleaf)
   assert(torch.isTypeOf(parentNode, 'dt.CartNode'))
   assert(torch.type(bestSplit) == 'table')
   assert(torch.isTypeOf(leftState, 'dt.TreeState'))
   assert(torch.isTypeOf(rightState, 'dt.TreeState'))
   assert(torch.type(nleaf) == 'number')

   local leftChild = dt.CartNode()
   leftChild.score = leftState:score(self.dataset)
   leftChild.nodeId = 2 * nleaf - 1

   local rightChild = dt.CartNode()
   rightChild.score = rightState:score(self.dataset)
   rightChild.nodeId = 2 * nleaf

   parentNode.splitFeatureId = bestSplit.splitId
   parentNode.splitFeatureValue = bestSplit.splitValue
   parentNode.leftChild = leftChild
   parentNode.rightChild = rightChild
   parentNode.splitGain = bestSplit.splitGain
end

-- We minimally need 2 * N examples in the parent to satisfy >= N examples per child
function CartTrainer:hasEnoughTrainingExamplesToSplit(count)
   return count >= 2 * self.minLeafSize
end

-- call before training to enable feature-parallelization
function CartTrainer:featureParallel(workPool)
   assert(self.parallelMode == 'singlethread', self.parallelMode)
   self.parallelMode = 'featureparallel'
   self.workPool = torch.type(workPool) == 'number' and dt.WorkPool(workPool) or workPool
   assert(torch.isTypeOf(self.workPool, 'dt.WorkPool'))

   -- this deletes all SparseTensor hash maps so that they aren't serialized
   self.dataset:deleteIndex()

   -- require the dt package
   self.workPool:update('require', {libname='decisiontree',varname='dt'})
   -- setup worker store (each worker will have its own copy)
   local store = {
      dataset=self.dataset,
      minLeafSize=self.minLeafSize
   }
   self.workPool:update('storeKeysValues', store)
end

-- feature parallel
function CartTrainer:findBestSplitForAllFeaturesFP(treeState, activeFeatures)
   local timer = torch.Timer()
   local bestSplit
   if treeState.findBestSplitFP then
      bestSplit = treeState:findBestSplitFP(self.dataset, activeFeatures, self.minLeafSize, self.workPool.nThread)
   end

   if not bestSplit then
      for i=1,self.workPool.nThread do
         -- upvalues
         local treeState = treeState
         local shardId = i
         local nShard = self.workPool.nThread
         local featureIds = activeFeatures
         -- closure
         local task = function(store)
            assert(store.dataset)
            assert(store.minLeafSize)
            if treeState.threadInitialize then
               treeState:threadInitialize()
            end

            local bestSplit = treeState:findBestSplit(store.dataset, featureIds, store.minLeafSize, shardId, nShard)
            return bestSplit
         end

         self.workPool:writeup('execute', task)
      end

      for i=1,self.workPool.nThread do
         local taskname, candidateSplit = self.workPool:read()
         assert(taskname == 'execute')
         if candidateSplit then
            if ((not bestSplit) or candidateSplit.splitGain < bestSplit.splitGain) then
               bestSplit = candidateSplit
            end
         end
      end
   end

   if bestSplit then
      assert(torch.type(bestSplit) == 'table')
   end

   if dt.PROFILE then
      print("findBestSplitForAllFeaturesFP time="..timer:time().real)
   end
   return bestSplit
end
