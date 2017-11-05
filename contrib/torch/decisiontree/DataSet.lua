local dt = require "decisiontree._env"
local ipc = require 'libipc'

local DataSet = torch.class("dt.DataSet", dt)

function DataSet:__init(input, target, nThreads)
   if torch.type(input) == 'table' then
      assert(torch.isTypeOf(input[1], 'torch.SparseTensor'))
   else
      assert(torch.isTensor(input))
   end
   self.input = input
   assert(torch.isTensor(target))
   self.target = target
   self.nThreads = nThreads or 1

   self.sortedFeatureValues, self.featureIds = self:sortFeatureValues(input)
end

-- group examples by featureId. For each featureId, sort examples by featureValue (ascending order)
-- returns a table mapping featureIds to sorted lists of exampleIds
-- e.g. {featureId={example1,example2,example3}}
function DataSet:sortFeatureValues(inputs)
   local isSparse = torch.typename(inputs[1]):match('torch.*SparseTensor')
   assert(isSparse or torch.isTensor(inputs))

   local featureIds = torch.LongTensor()
   local dataset = {} -- TODO use tds.Hash (will require SparseTensor to be userdata)
   if isSparse then
      local proto = inputs[1].values
      -- get list of featureIds
      local featureMap = {}
      for i,input in ipairs(inputs) do
         input.keys:apply(function(key)
            featureMap[key] = (featureMap[key] or 0) + 1
         end)
      end
      local _ = require "moses"
      featureIds = featureIds.new(_.keys(featureMap))
      local featureCounts = torch.LongTensor(featureIds:size(1))
      for i=1,featureIds:size(1) do
         featureCounts[i] = featureMap[featureIds[i]]
      end

      for i=1,featureIds:size(1) do
         local featureId = featureIds[i]
         local featureCount = featureCounts[i]
         dataset[featureId] = {
            values=proto.new(featureCount),
            examples=torch.LongTensor(featureCount),
            i=0
         }
      end

      for exampleId,input in ipairs(inputs) do
         local sparseIdx = 0
         input.keys:apply(function(key)
            sparseIdx = sparseIdx + 1
            local f = dataset[key]
            f.i = f.i + 1
            f.values[f.i] = input.values[sparseIdx]
            f.examples[f.i] = exampleId
         end)
      end

      local sortVal, sortIdx = proto.new(), torch.LongTensor()
      for featureId,f in pairs(dataset) do
         assert(f.values:size(1) == f.i)
         sortVal:sort(sortIdx, f.values, 1, false)

         local sortedExampleIds = torch.LongTensor(f.i)
         sortedExampleIds:index(f.examples, 1, sortIdx)

         dataset[featureId] = sortedExampleIds
      end
   else
      assert(torch.isTensor(inputs))
      featureIds:range(1,inputs:size(2))

      local wq = ipc.workqueue()
      for i=1,inputs:size(2) do
         wq:write({i, inputs:select(2, i)})
      end
      for i=1,self.nThreads do
         wq:write(nil)
      end

      ipc.map(self.nThreads, function(wq)
         while true do
            local data = wq:read()
            if data == nil then break end
            local featureId = data[1]
            local values = data[2]
            local sortFeatureValues, sortExampleIds = values:sort(1, false)
            sortFeatureValues = nil
            wq:write({featureId, sortExampleIds})
            collectgarbage()
         end
      end, wq)

      for _=1,inputs:size(2) do
         local data = wq:read()
         local featureId = data[1]
         local sortedFeatureExampleIds = data[2]
         dataset[featureId] = sortedFeatureExampleIds
      end
   end

   return dataset, featureIds
end

function DataSet:getSortedFeature(featureId)
   assert(self.sortedFeatureValues)
   return self.sortedFeatureValues[featureId]
end

function DataSet:size()
   return self.target:size(1)
end

function DataSet:getExampleIds()
   if not self.exampleIds then
      self.exampleIds = torch.LongTensor():range(1,self:size())
   end
   return self.exampleIds
end

function DataSet:countPositive(exampleIds)
   assert(torch.type(exampleIds) == 'torch.LongTensor')
   local dt = require 'decisiontree'
   local buffer = dt.getBufferTable('DataSet')
   buffer.tensor = buffer.tensor or self.target.new()
   buffer.tensor:index(self.target, 1, exampleIds)
   local nPositive = 0
   buffer.tensor:apply(function(x)
      if x > 0 then nPositive = nPositive + 1 end
   end)
   return nPositive
end

function DataSet:initScore()
   self.score = self.score or torch.Tensor()
   self.score:resize(self:size()):fill(0)
end

function DataSet:buildIndex()
   if torch.type(self.input) == 'table' then
      for exampleId,input in ipairs(self.input) do
         if torch.isTypeOf(input, 'torch.SparseTensor') then
            input:buildIndex()
         end
      end
   end
end

function DataSet:deleteIndex()
   if torch.type(self.input) == 'table' then
      for exampleId,input in ipairs(self.input) do
         if torch.isTypeOf(input, 'torch.SparseTensor') then
            input:deleteIndex()
         end
      end
   end
end
