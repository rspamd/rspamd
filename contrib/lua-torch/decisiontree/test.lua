local dt = require "decisiontree._env"

local dttest = {}
local nloop = 50
local epsilon = 0.000001
local mytester

--e.g. usage: th -e "dt = require 'decisiontree'; dt.test()"

-- test 99% accuracy
local function testAccuracy(cartTree, name, dataset, minacc)
   assert(torch.isTypeOf(dataset, 'dt.DataSet'))
   minacc = minacc or 0.99
   local output = torch.Tensor(dataset:size())
   local target, input = dataset.target, dataset.input

   for i=1,dataset:size() do
      local stack = {}
      local score = cartTree:score(input[i], stack)
      output[i] = score >= 0 and 1 or 0

      if dt.VERBOSE and torch.type(cartTree) == 'dt.CartTree' and target[i] ~= output[i] then
         print(cartTree:stackToString(stack, example.input))
         print(i, score, target[i], output[i])
      end
   end

   local accuracy = torch.eq(target, output):float():mean()
   mytester:assert(accuracy >= minacc, name .. ": insufficient accuracy: " .. accuracy .. " < " .. minacc)
end

function dttest.SparseTensor()
   local keys = torch.LongTensor{1,5,6,10}
   local values = torch.randn(keys:size(1))
   local st = torch.SparseTensor(keys, values)

   mytester:assert(st[1] == values[1])
   mytester:assert(st[5] == values[2])
   mytester:assert(st[6] == values[3])
   mytester:assert(st[10] == values[4])

   mytester:assert(st[2] == nil)

   st:buildIndex()

   mytester:assert(st[1] == values[1])
   mytester:assert(st[5] == values[2])
   mytester:assert(st[6] == values[3])
   mytester:assert(st[10] == values[4])

   mytester:assert(st[2] == nil)

   -- test empty sparse tensor

   local est = torch.SparseTensor()
end

function dttest.GiniState()
   local featureId = 2
   local minLeafSize = 0

   local input = torch.Tensor({{0,1,0},{0,2,0},{0,3,0}})
   local target = torch.Tensor({1, 1, 1})
   local dataset = dt.DataSet(input, target, 3)

   local splitInfo1 = {_id=1}
   local splitInfo2 = {_id=2, leftChildSize = 1, rightChildSize = 2, splitGain = 0}
   local splitInfo3 = {_id=3, leftChildSize = 2, rightChildSize = 1, splitGain = -1}

   local exampleIds = torch.LongTensor{1,2,3}

   local treeState = dt.GiniState(exampleIds)

   function treeState.computeSplitInfo(self, splitFeatureId, splitFeatureValue)
      if splitFeatureId  == featureId and splitFeatureValue == 2 then
         return splitInfo2
      elseif splitFeatureId  == featureId and splitFeatureValue == 3 then
         return splitInfo3
      else
         error("Unhandled computeSplitInfo call "..splitFeatureId.." "..splitFeatureValue)
      end
   end

   local splitInfo = treeState:findBestFeatureSplit(dataset, featureId, minLeafSize)
   mytester:assert(splitInfo._id == splitInfo3._id)
end

function dttest.CartTree()

   local splitFeatureId = 100
   local splitFeatureValue = 1.0

   local function getBinaryCartTreeRootNode()

      local leftNodeScore = 0.2
      local rightNodeScore = 0.4

      local rootNode = dt.CartNode()
      rootNode.nodeId = 0
      rootNode.score = 0.5
      rootNode.splitFeatureId = splitFeatureId
      rootNode.splitFeautreValue = splitFeatureValue

      local leftChild = dt.CartNode()
      leftChild.score = leftNodeScore
      leftChild.nodeId = 1

      local rightChild = dt.CartNode()
      rightChild.score = rightNodeScore
      rightChild.nodeId = 2

      rootNode.leftChild = leftChild
      rootNode.rightChild = rightChild

      return rootNode
   end

   local function testScoreCartTreeBranchLeftIfMissing()
      local rootNode = getBinaryCartTreeRootNode()

      local cartTree = dt.CartTree(rootNode)

      local continuousFeatures = torch.SparseTensor()

      local score, nodeId = cartTree:score(continuousFeatures)

      mytester:assert(math.abs(rootNode.leftChild.score - score) < epsilon)
      mytester:assert(rootNode.leftChild.nodeId == nodeId)
   end

   local function testBranchRightWithFeature()
      local rootNode = getBinaryCartTreeRootNode()

      local cartTree = dt.CartTree(rootNode)

      local continuousFeatures = torch.zeros(100)
      continuousFeatures[splitFeatureId] = splitFeatureValue

      local score, nodeId = cartTree:score(continuousFeatures)

      mytester:assert(math.abs(rootNode.rightChild.score - score) < epsilon)
      mytester:assert(rootNode.rightChild.nodeId == nodeId)
   end

   local function testMissingRightNode()
      local rootNode = getBinaryCartTreeRootNode()

      rootNode.rightChild = nil

      local cartTree = dt.CartTree(rootNode)

      local continuousFeatures = torch.Tensor()

      local score, nodeId = cartTree:score(continuousFeatures)

      mytester:assert(math.abs(rootNode.leftChild.score - score) < epsilon)
      mytester:assert(rootNode.leftChild.nodeId == nodeId)
   end

   local function testMissingLeftNode()
      local rootNode = getBinaryCartTreeRootNode()

      rootNode.leftChild = nil

      local cartTree = dt.CartTree(rootNode)

      local continuousFeatures = torch.Tensor()

      local score, nodeId = cartTree:score(continuousFeatures)

      mytester:assert(math.abs(rootNode.rightChild.score - score) < epsilon)
      mytester:assert(rootNode.rightChild.nodeId == nodeId)
   end

   local function testMissingAllChildren()
      local rootNode = getBinaryCartTreeRootNode()

      rootNode.leftChild = nil
      rootNode.rightChild = nil

      local cartTree = dt.CartTree(rootNode)

      local continuousFeatures = torch.Tensor()

      local score, nodeId = cartTree:score(continuousFeatures)

      mytester:assert(math.abs(rootNode.score - score) < epsilon)
      mytester:assert(rootNode.nodeId == nodeId)
   end

   local function testScoreCartTreeBranchRandomlyRight()
      local rootNode = getBinaryCartTreeRootNode();

      -- Force Branch Right
      local cartTree = dt.CartTree(rootNode, function() return false end);

      local continuousFeatures = torch.SparseTensor()

      local score, nodeId = cartTree:score(continuousFeatures)

      mytester:assert(math.abs(rootNode.rightChild.score - score) < epsilon)
      mytester:assert(rootNode.rightChild.nodeId == nodeId)
   end

   local function testScoreCartTreeBranchRandomlyLeft()
      local rootNode = getBinaryCartTreeRootNode();

      -- Force Branch Left
      local cartTree = dt.CartTree(rootNode, function() return true end);

      local continuousFeatures = torch.SparseTensor()

      local score, nodeId = cartTree:score(continuousFeatures)

      mytester:assert(math.abs(rootNode.leftChild.score - score) < epsilon)
      mytester:assert(rootNode.leftChild.nodeId == nodeId)
   end

   testScoreCartTreeBranchLeftIfMissing()
   testBranchRightWithFeature()
   testMissingRightNode()
   testMissingLeftNode()
   testMissingAllChildren()
   testScoreCartTreeBranchRandomlyRight()
   testScoreCartTreeBranchRandomlyLeft()

end

function dttest.TreeState_branch()
   local _ = require 'moses'
   local binFeatureId = 1
   local featureId = 2

   local input = {
      torch.SparseTensor(torch.LongTensor{binFeatureId},torch.Tensor{1}),
      torch.SparseTensor(torch.LongTensor{binFeatureId,featureId},torch.Tensor{1,1}),
      torch.SparseTensor(torch.LongTensor{binFeatureId,featureId},torch.Tensor{0,2}),
      torch.SparseTensor(torch.LongTensor{binFeatureId,featureId},torch.Tensor{0,3})
   }
   local target = torch.LongTensor(4):fill(1)

   local dataset = dt.DataSet(input, target)

   local treeState = dt.TreeState(torch.LongTensor():range(1,4))
   local splitInfo = {splitId = binFeatureId, splitValue = 1}

   local function testBranchBinaryFeature()
      splitInfo = {splitId = binFeatureId, splitValue = 1}
      local leftBranch, rightBranch = treeState:branch(splitInfo, dataset)
      mytester:assert(leftBranch ~= nil and rightBranch ~= nil)

      mytester:assert(2 == leftBranch:size())
      mytester:assert(leftBranch:contains(3))
      mytester:assert(leftBranch:contains(4))

      mytester:assert(2 == rightBranch:size())
      mytester:assert(rightBranch:contains(1))
      mytester:assert(rightBranch:contains(2))
   end

   local function testBranchContinuousFeature()
      local splitValue = 2
      splitInfo = {splitId = featureId, splitValue = splitValue}

      local leftBranch, rightBranch = treeState:branch(splitInfo, dataset)
      mytester:assert(leftBranch ~= nil and rightBranch ~= nil)

      mytester:assert(1 == leftBranch:size())
      mytester:assert(leftBranch:contains(2))

      mytester:assert(2 == rightBranch:size())
      mytester:assert(rightBranch:contains(3))
      mytester:assert(rightBranch:contains(4))
   end

   testBranchBinaryFeature()
   testBranchContinuousFeature()

end

function dttest.DecisionForest()
   -- Create test decision forest, each forest has only a single node, and returns score == score of root node.

   local function createCartTreeWithSingleNode(score)
      local cartNode = dt.CartNode()
      cartNode.score = score
      return dt.CartTree(cartNode)
   end

   local function getTestDecisionForest()
      local cartTrees = {
         createCartTreeWithSingleNode(1),
         createCartTreeWithSingleNode(2),
         createCartTreeWithSingleNode(3)
      }
      local weight = torch.Tensor{10,20,30}
      local bias = 0.5

      return dt.DecisionForest(cartTrees, weight, bias)
   end

   local function testScoreDecisionForest()
      local df = getTestDecisionForest()
      local continuousFeatures = torch.SparseTensor()

      local expectedResult = 1.0 * 10.0 + 2.0 * 20.0 + 3.0 * 30.0 + 0.5;
      local result = df:score(continuousFeatures)

      mytester:assert(math.abs(expectedResult - result) < epsilon)
   end

   testScoreDecisionForest()
end

function dttest.CartTrainer()
   local minLeafSize, maxLeafNodes = 1, 1000
   local nExample = 100

   -- 1. dense dataset
   local trainSet, validSet, clusterExamples, inputs, targets = dt.getDenseDummyData(nExample)

   -- assert that the dataset is valid
   for clusterId, exampleIds in ipairs(clusterExamples) do
      local exampleIdx = torch.LongTensor(exampleIds)
      local input = inputs:index(1,exampleIdx)
      local target = targets:index(1,exampleIdx)
      assert(input:std(1):mean() < 0.05)
   end

   local cartTrainer = dt.CartTrainer(trainSet, minLeafSize, maxLeafNodes)
   local treeState = dt.GiniState(trainSet:getExampleIds())
   local cartTree, nleaf = cartTrainer:train(treeState, trainSet.featureIds)

   mytester:assert(nleaf == nExample) -- for dense inputs, minLeafSize =1 and maxLeafNode = inf, this is true
   testAccuracy(cartTree, "dense train single-thread first", trainSet, 0.99)
   testAccuracy(cartTree, "dense valid single-thread first", validSet, 0.7) -- they don't generalize very well..

   local cartTree, nleaf = cartTrainer:train(treeState, trainSet.featureIds)
   testAccuracy(cartTree, "dense single-thread second", trainSet)

   -- test feature parallelization
   local nThread = 2
   cartTrainer:featureParallel(nThread)
   local treeState = dt.GiniState(trainSet:getExampleIds())
   local cartTree, nleaf = cartTrainer:train(treeState, trainSet.featureIds)
   testAccuracy(cartTree, "dense feature-parallel", trainSet)

   -- 2. sparse-dense dataset
   local trainSet, validSet, clusterExamples, inputs, targets = dt.getSparseDummyData(nExample, nil, 10, nil, nil, 10)

   -- assert that the dataset is valid
   for clusterId, exampleIds in ipairs(clusterExamples) do
      local input = torch.Tensor(#exampleIds, 10):zero()
      for i, exampleId in ipairs(exampleIds) do
         input[i]:indexCopy(1, inputs[exampleId].keys, inputs[exampleId].values)
      end
      assert(input:std(1):mean() < 0.05)
   end

   local cartTrainer = dt.CartTrainer(trainSet, minLeafSize, maxLeafNodes)
   local treeState = dt.GiniState(trainSet:getExampleIds())
   local cartTree, nleaf = cartTrainer:train(treeState, trainSet.featureIds)

   mytester:assert(nleaf == nExample) -- for dense inputs, minLeafSize =1 and maxLeafNode = inf, this is true
   testAccuracy(cartTree, "sparse-dense train single-thread first", trainSet, 0.99)

   local shuffle = torch.LongTensor():randperm(10)
   for i, input in ipairs(inputs) do
      input.keys = input.keys:index(1, shuffle)
      input.values = input.values:index(1, shuffle)
      input._map = nil
   end
   testAccuracy(cartTree, "sparse-dense shuffled keys train single-thread first", trainSet, 0.99)
   testAccuracy(cartTree, "sparse-dense valid single-thread first", validSet, 0.8)

   -- 3. sparse dataset
   local trainSet, validSet = dt.getSparseDummyData(nExample, 2, 10, nil, nil, 9)

   local cartTrainer = dt.CartTrainer(trainSet, minLeafSize, maxLeafNodes)
   local treeState = dt.GiniState(trainSet:getExampleIds())
   local cartTree, nleaf = cartTrainer:train(treeState, trainSet.featureIds)
   cartTree.branchleft = function() return true end

   mytester:assert(nleaf < nExample) -- for dense inputs, minLeafSize =1 and maxLeafNode = inf, this is true
   testAccuracy(cartTree, "sparse train single-thread first", trainSet, 0.9) -- the TreeBrancher drops examples with missing features, making it difficult to overfit
   testAccuracy(cartTree, "sparse valid single-thread first", validSet, 0.8)
end

function dttest.GradientBoostTrainer()
   local nExample = 100
   local trainSet, validSet = dt.getSparseDummyData(nExample, 2, 10, nil, nil, 9)

   local maxLeafNode, minLeafSize = nExample/2, nExample/10
   local loss = nn.LogitBoostCriterion(false)

   local cartTrainer = dt.CartTrainer(trainSet, minLeafSize, maxLeafNode)

   local opt = {
      lossFunction=loss,
      treeTrainer=cartTrainer,
      shrinkage=0.1,
      downsampleRatio=6,
      featureBaggingSize=-1,
      nTree=14,
      evalFreq=8,
      earlyStop=0 -- no early-stopping
   }

   -- test single-thread
   local trainer = dt.GradientBoostTrainer(opt)
   local decisionForest = trainer:train(trainSet, trainSet.featureIds, validSet)

   mytester:assert(#decisionForest.trees == opt.nTree)
   testAccuracy(decisionForest, "sparse train single-thread first", trainSet, 0.98)
   testAccuracy(decisionForest, "sparse valid single-thread first", validSet, 0.95)

   -- test stateless
   local decisionForest = trainer:train(trainSet, trainSet.featureIds, validSet)

   mytester:assert(#decisionForest.trees == opt.nTree)
   testAccuracy(decisionForest, "sparse train single-thread second", trainSet, 0.98)
   testAccuracy(decisionForest, "sparse valid single-thread second", validSet, 0.95)

   -- test feature-parallel
   local nThread = 2
   cartTrainer:featureParallel(nThread)

   local trainer = dt.GradientBoostTrainer(opt)
   local decisionForest = trainer:train(trainSet, trainSet.featureIds, validSet)

   mytester:assert(#decisionForest.trees == opt.nTree)
   testAccuracy(decisionForest, "sparse train feature-parallel first", trainSet, 0.98)
   testAccuracy(decisionForest, "sparse valid feature-parallel first", validSet, 0.95)

end

function dttest.RandomForestTrainer()
   local nExample = 100
   local trainSet, validSet = dt.getSparseDummyData(nExample, 2, 10, nil, nil, 9)

   local opt = {
      activeRatio=0.5,
      featureBaggingSize=5,
      nTree=14,
      maxLeafNodes=nExample/2,
      minLeafSize=nExample/10,
   }

   local trainer = dt.RandomForestTrainer(opt)

   local decisionForest = trainer:train(trainSet, trainSet.featureIds)
   mytester:assert(#decisionForest.trees == opt.nTree)
   testAccuracy(decisionForest, "sparse train single-thread first", trainSet, 0.98)
   testAccuracy(decisionForest, "sparse valid single-thread first", validSet, 0.95)

   -- test stateless
   local decisionForest = trainer:train(trainSet, trainSet.featureIds)

   mytester:assert(#decisionForest.trees == opt.nTree)
   testAccuracy(decisionForest, "sparse train single-thread second", trainSet, 0.98)
   testAccuracy(decisionForest, "sparse valid single-thread second", validSet, 0.95)

   -- test tree-parallel
   local nThread = 2
   trainer:treeParallel(nThread)

   local trainer = dt.RandomForestTrainer(opt)
   local decisionForest = trainer:train(trainSet, trainSet.featureIds)

   mytester:assert(#decisionForest.trees == opt.nTree)
   testAccuracy(decisionForest, "sparse train tree-parallel first", trainSet, 0.98)
   testAccuracy(decisionForest, "sparse valid tree-parallel first", validSet, 0.95)
end

function dttest.WorkPool()
   local nThread = 2
   local wp = dt.WorkPool(nThread)

   -- 1. some easy tests
   local store = {key='nick',value=7}
   wp:update('storeKeyValue', store)

   wp:update('require', {libname='decisiontree', varname='dt'})

   local bias = 2
   local obj = nn.MSECriterion()
   wp:update('require', {libname='decisiontree', varname='dt'})
   wp:writeup('execute', function(store) return bias + obj:updateOutput(torch.Tensor{1},torch.Tensor{1}) + store.nick end)

   local taskname, res = wp:read()
   mytester:assert(taskname == 'execute')
   mytester:assert(res == 9)

   -- 2. trying to reproduce a difficult error
   local trainSet, validSet = dt.getSparseDummyData()

   -- setup worker store (each worker will have its own copy)
   local store = {
      trainSet=trainSet,
      minLeafSize=2
   }
   wp:update('storeKeysValues', store)

   -- arguments/upvalues
   local treeState = dt.GiniState(trainSet:getExampleIds())
   local shardId = 1
   local nShard = nThread
   local featureIds = trainSet.featureIds

   local task = function(store, args)
      assert(store.trainSet)
      assert(store.minLeafSize)

      local bestSplit = args.treeState:findBestSplit(store.trainSet, args.featureIds, store.minLeafSize, args.shardId, args.nShard)
      return bestSplit
   end
   local args = {treeState=treeState,featureIds=featureIds,shardId=shardId,nShard=nShard}
   wp:writeup("execute", {func=task,args=args})

   local taskname, bestSplit = wp:read()
   mytester:assert(taskname == 'execute')
   mytester:assert(torch.type(bestSplit) == 'table')

   -- closure
   local task = function(store)
      assert(store.trainSet)
      assert(store.minLeafSize)

      local bestSplit = treeState:findBestSplit(store.trainSet, featureIds, store.minLeafSize, shardId, nShard)
      return bestSplit
   end
   wp:writeup("execute", task)

   local taskname, bestSplit = wp:read()
   mytester:assert(taskname == 'execute')
   mytester:assert(torch.type(bestSplit) == 'table')

   local task = function(store, args)
      assert(store.trainSet)
      assert(torch.isTypeOf(treeState, 'dt.TreeState'), torch.type(treeState))

      local bestSplit = treeState:findBestSplit(store.trainSet, featureIds, store.minLeafSize, shardId, nShard)
      return bestSplit
   end
   local args = {featureIds=featureIds,shardId=shardId,nShard=nShard}
   wp:writeup("execute", {func=task,args=args})


   local taskname, bestSplit = wp:read()
   mytester:assert(taskname == 'execute')
   mytester:assert(torch.type(bestSplit) == 'table')

   wp:terminate()
end

function dttest.Sparse2Dense()
   local batchsize = 4
   local minFeatureId, maxFeatureId = 10, 100
   local input = {{},{}}
   for i=1,batchsize do
      local inputsize = math.random(5,10)
      input[1][i] = torch.LongTensor(inputsize):random(minFeatureId,maxFeatureId)
      input[2][i] = torch.Tensor(inputsize):uniform(0,1)
   end
   local s2d = nn.Sparse2Dense(torch.LongTensor():range(minFeatureId,maxFeatureId))
   -- test 2d forward
   local output = s2d:forward(input)
   local output2 = torch.Tensor(batchsize, maxFeatureId-minFeatureId+1):zero()
   local featureMap = {}
   local j = 0
   for i=minFeatureId,maxFeatureId do
      j = j + 1
      featureMap[i] = j
   end
   for i=1,batchsize do
      local keys, values = input[1][i], input[2][i]
      for j=1,keys:size(1) do
         output2[{i,featureMap[keys[j] ]}] = values[j]
      end
   end
   mytester:assertTensorEq(output, output2, 0.000001)
   -- test 1d forward
   local input = {input[1][batchsize], input[2][batchsize]}
   local output = s2d:forward(input)
   mytester:assertTensorEq(output, output2[batchsize], 0.000001)
end

function dttest.Sparse2DenseDouble()
   local batchsize = 4
   local minFeatureId, maxFeatureId = 10, 100
   local input = {{},{}}
   for i=1,batchsize do
      local inputsize = math.random(5,10)
      input[1][i] = torch.LongTensor(inputsize):random(minFeatureId,maxFeatureId)
      input[2][i] = torch.Tensor(inputsize):uniform(0,1):double()
   end
   local s2d = nn.Sparse2Dense(torch.LongTensor():range(minFeatureId,maxFeatureId))
   s2d:double()
   -- test 2d forward
   local output = s2d:forward(input)
   local output2 = torch.Tensor(batchsize, maxFeatureId-minFeatureId+1):zero():double()
   local featureMap = {}
   local j = 0
   for i=minFeatureId,maxFeatureId do
      j = j + 1
      featureMap[i] = j
   end
   for i=1,batchsize do
      local keys, values = input[1][i], input[2][i]
      for j=1,keys:size(1) do
         output2[{i,featureMap[keys[j] ]}] = values[j]
      end
   end
   mytester:assertTensorEq(output, output2, 0.000001)
   -- test 1d forward
   local input = {input[1][batchsize], input[2][batchsize]}
   local output = s2d:forward(input)
   mytester:assertTensorEq(output, output2[batchsize], 0.000001)
end

function dttest.LogitBoostCriterion()
   local input = torch.randn(10)
   local target = torch.LongTensor(10):random(0,1):type(torch.type(input))

   local lb = nn.LogitBoostCriterion(false)
   local loss = lb:updateOutput(input, target)

   local loss2 = 0
   for i=1,10 do
      loss2 = loss2 + math.log(1 + math.exp(target[i] <= 0 and input[i] or -input[i]))
   end
   mytester:assert(math.abs(loss - loss2) < 0.00001)

   local gradInput = lb:updateGradInput(input, target)
   local gradInput2 = gradInput:clone():zero()
   for i=1,10 do
      local p = dt.logistic(input[i])
      gradInput2[i] = (target[i] <= 0) and p or (p - 1)
   end
   mytester:assertTensorEq(gradInput, gradInput2, 0.000001)

   local hessInput = lb:updateHessInput(input, target)
   local hessInput2 = hessInput:clone():zero()
   for i=1,10 do
      local p = dt.logistic(input[i])
      hessInput2[i] = p * (1.0 - p)
   end
   mytester:assertTensorEq(hessInput, hessInput2, 0.000001)
end

function dttest.DFD()
   local nExample = 100
   local batchsize = 4
   local inputsize = 10

   -- train Random Forest
   local trainSet, validSet, clusterExamples, inputs, targets = dt.getDenseDummyData(nExample, nil, inputsize)
   local opt = {
      activeRatio=0.5,
      featureBaggingSize=5,
      nTree=4,
      maxLeafNodes=nExample/2,
      minLeafSize=nExample/10,
   }
   local trainer = dt.RandomForestTrainer(opt)
   local df = trainer:train(trainSet, trainSet.featureIds)
   mytester:assert(#df.trees == opt.nTree)

   local dfd = nn.DFD(df)
   dfd = nn.DFD(dfd:getReconstructionInfo())
   local dfd2 = nn.DFD(dfd:getReconstructionInfo(), true)
   local input = validSet.input:sub(1,batchsize)
   local output = dfd:forward(input)
   local output2 = dfd2:forward(input)

   local _ = require 'moses'

   local function hasKey(keys,key)
      local found = false
      keys:apply(function(x)
         if x == key then
            found = true
         end
      end)
      return found
   end

   for i=1,batchsize do
      local nodes = {}
      local keys = output[1][i]
      local keys2 = output2[1][i]
      for j,tree in ipairs(df.trees) do
         local stack = {}
         tree:score(input[i], stack)
         mytester:assert(hasKey(keys2, stack[#stack]._nodeId))

         for k,node in ipairs(stack) do
            if k > 1 then
               assert(node._nodeId)
               mytester:assert(hasKey(keys, node._nodeId), string.format("missing key=%d in %s", node._nodeId, tostring(keys)))
               table.insert(nodes, node._nodeId)
            end
         end
      end
      mytester:assert(#nodes == keys:size(1))
      mytester:assert(#df.trees == keys2:size(1))
   end
end

function dttest.DFDDouble()
   local nExample = 100
   local batchsize = 4
   local inputsize = 10

   -- train Random Forest
   local trainSet, validSet, clusterExamples, inputs, targets = dt.getDenseDummyData(nExample, nil, inputsize)
   local opt = {
      activeRatio=0.5,
      featureBaggingSize=5,
      nTree=4,
      maxLeafNodes=nExample/2,
      minLeafSize=nExample/10,
   }
   local trainer = dt.RandomForestTrainer(opt)
   local df = trainer:train(trainSet, trainSet.featureIds)
   mytester:assert(#df.trees == opt.nTree)

   local dfd = nn.DFD(df)
   dfd:double()
   dfd = nn.DFD(dfd:getReconstructionInfo())
   local dfd2 = nn.DFD(dfd:getReconstructionInfo(), true)
   local input = validSet.input:sub(1,batchsize):double()
   local output = dfd:forward(input)
   local output2 = dfd2:forward(input)

   local _ = require 'moses'

   local function hasKey(keys,key)
      local found = false
      keys:apply(function(x)
         if x == key then
            found = true
         end
      end)
      return found
   end

   for i=1,batchsize do
      local nodes = {}
      local keys = output[1][i]
      local keys2 = output2[1][i]
      for j,tree in ipairs(df.trees) do
         local stack = {}
         tree:score(input[i], stack)
         mytester:assert(hasKey(keys2, stack[#stack]._nodeId))

         for k,node in ipairs(stack) do
            if k > 1 then
               assert(node._nodeId)
               mytester:assert(hasKey(keys, node._nodeId), string.format("missing key=%d in %s", node._nodeId, tostring(keys)))
               table.insert(nodes, node._nodeId)
            end
         end
      end
      mytester:assert(#nodes == keys:size(1))
      mytester:assert(#df.trees == keys2:size(1))
   end
end

function dttest.uniquecounts() -- DEPRECATED
   local target = torch.LongTensor(100):random(1,3)
   local input = torch.Tensor()
   local inputset = {input=input, target=target}

   local counts = dt.uniquecounts(nil, inputset, 3)

   mytester:assert(counts:sum() == 100)
   mytester:assert(counts:nElement() == 3)

   local res = torch.Tensor(3):zero()
   target:apply(function(t) res[t] = res[t] + 1 end)

   mytester:assertTensorEq(counts, res)
end

function dttest.entropy() -- DEPRECATED
   -- 2 clusters with a bit overlap between classes:
   local input = torch.Tensor(100,2)
   input:narrow(1,1,50):normal(-1,.01)
   input:narrow(1,51,50):normal(2,.01)

   local target = torch.LongTensor(100):fill(3)
   target:narrow(1,1,45):fill(1)
   target:narrow(1,56,45):fill(2)

   local inputset = {input=input, target=target}

   -- test entropy()
   local fullent = dt.entropy(inputset)

   local halfset = {input=input:narrow(1,1,50), target=target:narrow(1,1,50)}
   local halfent = dt.entropy(halfset)

   local perfectset = {input=input:narrow(1,56,45), target=target:narrow(1,56,45)}
   local perfectent = dt.entropy(perfectset)

   mytester:assert(fullent > halfent)
   mytester:assert(halfent > perfectent)
   mytester:assert(perfectent < 0.0000001 and perfectent >= 0)
end

function dt.test(tests)
   math.randomseed(os.time())
   mytester = torch.Tester()
   mytester:add(dttest)
   mytester:run(tests)
end
