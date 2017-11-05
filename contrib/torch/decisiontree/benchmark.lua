local dt = require "decisiontree._env"

local bm = {}
function bm.CartTrainer(opt)
   local timer = torch.Timer()
   local trainSet, validSet = dt.getSparseDummyData(opt)
   print(string.format("CartTrainer: sparse dataset create: %f samples/sec; %f sec", opt.nExample/timer:time().real, timer:time().real))

   local cartTrainer = dt.CartTrainer(trainSet, opt.minLeafSize, opt.maxLeafNodes)
   local treeState = dt.GiniState(trainSet:getExampleIds())
   timer:reset()
   local cartTree, nleaf = cartTrainer:train(treeState, trainSet.featureIds)
   print(string.format("CartTrainer: train single-thread : %f samples/sec; %f sec", opt.nExample/timer:time().real, timer:time().real))

   timer:reset()
   cartTrainer:featureParallel(opt.nThread)
   print(string.format("CartTrainer: setup feature-parallel : %f samples/sec; %f sec", opt.nExample/timer:time().real, timer:time().real))
   timer:reset()
   local cartTree, nleaf = cartTrainer:train(treeState, trainSet.featureIds)
   print(string.format("CartTrainer: train feature-parallel : %f samples/sec; %f sec", opt.nExample/timer:time().real, timer:time().real))
end

function bm.GradientBoostState(opt)
   local trainSet, validSet = dt.getSparseDummyData(opt)

   trainSet:initScore()

   local treeState = dt.GradientBoostState(trainSet:getExampleIds(), nn.LogitBoostCriterion(false))

   local timer = torch.Timer() -- first step also calls SparseTensor:buildIndex()
   treeState:findBestSplit(trainSet, trainSet.featureIds, 10, 1, 3)
   print(string.format("GradientBoostState: findBestSplit (first) : %f sec", timer:time().real))

   timer:reset()
   treeState:findBestSplit(trainSet, trainSet.featureIds, 10, 1, 3)
   print(string.format("GradientBoostState: findBestSplit (second) : %f sec", timer:time().real))

end

local function file_exists(name)
   local f=io.open(name,"r")
   if f~=nil then io.close(f) return true else return false end
end

function bm.GradientBoostTrainer(opt)
   local trainSet, validSet
   if file_exists("/tmp/train.bin") and file_exists("/tmp/valid.bin") then
      trainSet = torch.load("/tmp/train.bin")
      validSet = torch.load("/tmp/valid.bin")
   else
      if opt.sparse then
         trainSet, validSet = dt.getSparseDummyData(opt)
      else
         trainSet, validSet = dt.getDenseDummyData(opt)
      end
      torch.save("/tmp/train.bin", trainSet)
      torch.save("/tmp/valid.bin", validSet)
   end

   local cartTrainer = dt.CartTrainer(trainSet, opt.minLeafSize, opt.maxLeafNodes)
   opt.lossFunction = nn.LogitBoostCriterion(false)
   opt.treeTrainer = cartTrainer
   local forestTrainer = dt.GradientBoostTrainer(opt)

   local timer = torch.Timer()
   local decisionForest = forestTrainer:train(trainSet, trainSet.featureIds, validSet)
   local time = timer:time().real
   print(string.format("GradientBoostTrainer: train single-thread : %f samples/sec; %f sec/tree, %f sec", opt.nExample/time, time/opt.nTree, time))

   cartTrainer:featureParallel(opt.nThread)
   timer:reset()
   local decisionForest = forestTrainer:train(trainSet, trainSet.featureIds, validSet)
   local time = timer:time().real
   print(string.format("GradientBoostTrainer: train feature-parallel : %f samples/sec; %f sec/tree, %f sec", opt.nExample/time, time/opt.nTree, time))
end

function bm.RandomForestTrainer(opt)
   local trainSet, validSet = dt.getSparseDummyData(opt)

   local forestTrainer = dt.RandomForestTrainer(opt)
   local decisionForest = forestTrainer:train(trainSet, trainSet.featureIds)

   local timer = torch.Timer()
   local decisionForest = forestTrainer:train(trainSet, trainSet.featureIds)
   local time = timer:time().real
   print(string.format("RandomForestTrainer: train single-thread : %f samples/sec; %f sec/tree, %f sec", opt.nExample/time, time/opt.nTree, time))

   timer:reset()
   forestTrainer:treeParallel(opt.nThread)
   print(string.format("RandomForestTrainer: setup tree-parallel : %f samples/sec; %f sec", opt.nExample/timer:time().real, timer:time().real))

   timer:reset()
   local decisionForest = forestTrainer:train(trainSet, trainSet.featureIds)
   local time = timer:time().real
   print(string.format("RandomForestTrainer: train tree-parallel : %f samples/sec; %f sec/tree, %f sec", opt.nExample/time, time/opt.nTree, time))
end

function bm.DFD(opt)
   local _ = require 'moses'
   local opt = _.clone(opt)
   opt.nExample = 200
   local trainSet, validSet = dt.getDenseDummyData(opt)

   local forestTrainer = dt.RandomForestTrainer(opt)
   forestTrainer:treeParallel(opt.nThread)
   local timer = torch.Timer()
   local decisionForest = forestTrainer:train(trainSet, trainSet.featureIds)
   local time = timer:time().real
   print(string.format("DFD: train random forest in parallel : %f samples/sec; %f sec/tree, %f sec", opt.nExample/time, time/opt.nTree, time))


   -- benchmark nn.DFD
   local input = trainSet.input:sub(1,opt.batchsize)
   local dfd = nn.DFD(decisionForest)
   dfd:forward(input)
   timer:reset()
   for i=1,opt.nloop do
      dfd:forward(input)
   end
   print(string.format("DFD: updateOutput : %f samples/sec; %f sec", opt.nloop*opt.batchsize/timer:time().real, timer:time().real))
end

function bm.Sparse2Dense(opt)
   local _ = require 'moses'
   local opt = _.clone(opt)
   opt.nExample = opt.batchsize
   local trainSet = dt.getSparseDummyData(opt)

   local input = {{},{}}
   for i=1,opt.batchsize do
      input[1][i] = trainSet.input[i].keys
      input[2][i] = trainSet.input[i].values
   end
   assert(#input[1] == opt.batchsize)

   -- benchmark nn.Sparse2Dense
   local s2d = nn.Sparse2Dense(torch.LongTensor():range(1,opt.nFeature))
   s2d:forward(input)
   local timer = torch.Timer()
   for i=1,opt.nloop do
      s2d:forward(input)
   end
   print(string.format("Sparse2Dense: updateOutput : %f samples/sec; %f sec", opt.nloop*opt.batchsize/timer:time().real, timer:time().real))
end

function dt.benchmark(benchmarks, opt2)
   local opt = {
      nExample=10000, nCluster=2, nFeature=1000, overlap=0, nValid=100,        -- getSparseDummyData
      nTree=20, featureBaggingSize=-1, sparse=true,                           -- GradientBoostTrainer and RandomForestTrainer
      nThread=2, shrinkage=0.1, downsampleRatio=0.1, evalFreq=5, earlyStop=0, -- GradientBoostTrainer
      activeRatio=0.5,                                                      -- RandomForestTrainer
      batchsize=32, nloop=10
   }

   local _ = require 'moses'
   benchmarks = benchmarks or _.keys(bm)
   assert(torch.type(benchmarks) == 'table')
   for i,benchmark in ipairs(benchmarks) do
      local opt1 = _.clone(opt)
      for key, value in pairs(opt2 or {}) do
         opt1[key] = value
      end
      opt1.nActive = opt1.nActive or torch.round(opt1.nFeature/10)
      opt1.maxLeafNodes = opt1.maxLeafNodes or (opt1.nExample/10)
      opt1.minLeafSize = opt1.minLeafSize or (opt1.nExample/100)

      assert(torch.type(benchmark) == 'string', benchmark)
      assert(bm[benchmark], benchmark)
      bm[benchmark](opt1)
   end
end
