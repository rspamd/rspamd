local dt = require "decisiontree._env"

-- returns a buffer table local to a thread (no serialized)
function dt.getBufferTable(name)
   local dt = require 'decisiontree'
   assert(torch.type(name) == 'string')
   dt.buffer = dt.buffer or {}
   dt.buffer[name] = dt.buffer[name] or {}
   return dt.buffer[name]
end

function dt.getSparseDummyData(nExample, nCluster, nFeature, overlap, nValid, nActive)
   local dt = require 'decisiontree'
   if torch.type(nExample) == 'table' then
      local opt = nExample
      nExample = opt.nExample
      nCluster = opt.nCluster
      nFeature = opt.nFeature
      overlap = opt.overlap
      nValid = opt.nValid
      nActive = opt.nActive
   end
   nExample = nExample or 100 -- training set size
   nCluster = nCluster or 10
   assert(nCluster >= 2)
   nFeature = math.max(2, nFeature or 10)
   overlap = overlap or 0
   nValid = nValid or nExample/10 -- validation set size
   nActive = nActive or math.max(2, nFeature / 2)

   -- sample nCluster centers
   local clusterCenter = torch.rand(nCluster, nFeature)
   local clusterLabel = torch.LongTensor(nCluster)
   local clusterExamples = {}
   for i=1,nCluster do
      clusterCenter[i]:add(i)
      clusterLabel[i] = i % 2
      clusterExamples[i] = {}
   end

   local sparseCenter = torch.Tensor()

   local shuffle = torch.LongTensor()

   -- build dataset in pseudo-dense format
   local inputs = {}
   local targets = torch.Tensor(nExample+nValid)
   for i=1,nExample+nValid do
      local clusterIdx = torch.random(1,nCluster)
      table.insert(clusterExamples[clusterIdx], i)

      shuffle:randperm(nFeature)
      local keys = torch.LongTensor(nActive):copy(shuffle:narrow(1,1,nActive))
      sparseCenter:index(clusterCenter[clusterIdx], 1, keys)
      local stdiv = i <= nExample and 100 or 1000
      local values = torch.randn(nActive):div(stdiv):add(sparseCenter)

      table.insert(inputs, torch.SparseTensor(keys, values))

      local label = clusterLabel[clusterIdx]
      if math.random() < overlap then
         targets[i] = label == 1 and 0 or 1
      else
         targets[i] = label
      end
   end

   local _ = require 'moses'
   local validSet = dt.DataSet(_.slice(inputs, nExample+1, nExample+nValid), targets:narrow(1,nExample+1,nValid))
   local trainSet = dt.DataSet(_.slice(inputs, 1, nExample), targets:narrow(1,1,nExample))

   return trainSet, validSet, clusterExamples, inputs, targets
end

function dt.getDenseDummyData(nExample, nCluster, nFeature, overlap, nValid)
   local dt = require 'decisiontree'
   if torch.type(nExample) == 'table' then
      local opt = nExample
      nExample = opt.nExample
      nCluster = opt.nCluster
      nFeature = opt.nFeature
      overlap = opt.overlap
      nValid = opt.nValid
   end
   nExample = nExample or 100 -- training set size
   nCluster = nCluster or 10
   assert(nCluster >= 2)
   nFeature = math.max(2, nFeature or 10)
   overlap = overlap or 0
   nValid = nValid or nExample/10 -- validation set size

   -- sample nCluster centers
   local clusterCenter = torch.rand(nCluster, nFeature)
   local clusterLabel = torch.LongTensor(nCluster)
   local clusterExamples = {}
   for i=1,nCluster do
      clusterCenter[i]:add(i)
      clusterLabel[i] = i % 2
      clusterExamples[i] = {}
   end

   -- build dataset in pseudo-dense format
   local inputs = torch.Tensor(nExample+nValid, nFeature)
   local targets = torch.Tensor(nExample+nValid)
   for i=1,nExample+nValid do
      local clusterIdx = torch.random(1,nCluster)
      table.insert(clusterExamples[clusterIdx], i)

      local stdiv = i <= nExample and 100 or 1000
      inputs[i]:normal():div(stdiv):add(clusterCenter[clusterIdx])

      local label = clusterLabel[clusterIdx]
      if math.random() < overlap then
         targets[i] = label == 1 and 0 or 1
      else
         targets[i] = label
      end
   end

   local _ = require 'moses'
   local validSet = dt.DataSet(inputs:narrow(1,nExample+1,nValid), targets:narrow(1,nExample+1,nValid))
   local trainSet = dt.DataSet(inputs:narrow(1,1,nExample), targets:narrow(1,1,nExample))

   return trainSet, validSet, clusterExamples, inputs, targets
end
