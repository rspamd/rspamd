local dt = require "decisiontree._env"

-- Decision forest that ensembles a bag of decision trees.
local DecisionForest = torch.class("dt.DecisionForest", "dt.DecisionTree", dt)

function DecisionForest:__init(trees, weight, bias)
   assert(torch.type(trees) == 'table')
   self.trees = trees
   if #trees == 0 then
      self.weight = weight or torch.Tensor()
      assert(torch.isTensor(self.weight))
      assert(self.weight:nElement() == 0)
   else
      assert(torch.isTypeOf(trees[1], 'dt.DecisionTree'))
      self.weight = weight or torch.Tensor(#trees):fill(1)
      assert(torch.isTensor(self.weight))
      assert(self.weight:dim() == 1)
      assert(self.weight:min() >= 0, "Expecting positive weights")
      assert(#trees == self.weight:size(1))
   end

   self.bias = bias or 0
   assert(torch.type(self.bias) == 'number')
end

function DecisionForest:score(input, incrementalId)
   assert(torch.isTensor(input))

   local buffer = {}
   if incrementalId then
      self.buffers = self.buffers or {}
      self.buffers[incrementalId] = self.buffers[incrementalId] or {}
      buffer = self.buffers[incrementalId]
   end
   buffer.initialCounter = buffer.initialCounter or 0

   -- TODO: score in parallel
   local output
   if torch.isTensor(input) and input.isContiguous and input:isContiguous() and input:nDimension() == 2 then
      buffer.output = buffer.output or input.new()
      output = buffer.output
      assert(output:nElement() == 0 or output:size(1) == input:size(1))
      if output:nElement() == 0 then
         output:resize(input:size(1)):fill(self.bias)
      end
      for i,tree in ipairs(self.trees) do
         if i > buffer.initialCounter then
            local score = tree:score(input, nil, true)
            output:add(self.weight[i], score)
         end
      end
   else
      output = buffer.output or self.bias
      for i,tree in ipairs(self.trees) do
         if i > buffer.initialCounter then
            output = output + tree:score(input) * self.weight[i]
         end
      end
      buffer.output = output
   end

   buffer.initialCounter = #self.trees

   return output
end

function DecisionForest:add(tree, weight)
   assert(torch.type(weight) == 'number')
   assert(weight > 0)
   table.insert(self.trees, tree)
   self.weight:resize(#self.trees)
   self.weight[#self.trees] = weight
   return self
end

function DecisionForest:clone()
   local trees = {}
   for i, tree in ipairs(self.trees) do
      trees[i] = tree:clone()
   end
   return DecisionForest(trees, self.weight:clone(), self.bias)
end
