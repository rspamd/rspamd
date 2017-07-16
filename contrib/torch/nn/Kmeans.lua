-- Online (Hard) Kmeans layer.
local Kmeans, parent = torch.class('nn.Kmeans', 'nn.Module')

function Kmeans:__init(k, dim, scale)
   parent.__init(self)
   self.k = k
   self.dim = dim

   -- scale for online kmean update
   self.scale = scale

   assert(k > 0, "Clusters cannot be 0 or negative.")
   assert(dim > 0, "Dimensionality cannot be 0 or negative.")

   -- Kmeans centers -> self.weight
   self.weight = torch.Tensor(self.k, self.dim)

   self.gradWeight = torch.Tensor(self.weight:size())
   self.loss = 0 -- within cluster error of the last forward

   self.clusterSampleCount = torch.Tensor(self.k)

   self:reset()
end

-- Reset
function Kmeans:reset(stdev)
   stdev = stdev or 1
   self.weight:uniform(-stdev, stdev)
end

-- Initialize Kmeans weight with random samples from input.
function Kmeans:initRandom(input)
   local inputDim = input:nDimension()
   assert(inputDim == 2, "Incorrect input dimensionality. Expecting 2D.")

   local noOfSamples = input:size(1)
   local dim = input:size(2)
   assert(dim == self.dim, "Dimensionality of input and weight don't match.")
   assert(noOfSamples >= self.k, "Need atleast k samples for initialization.")

   local indices = torch.zeros(self.k)
   indices:random(1, noOfSamples)

   for i=1, self.k do
      self.weight[i]:copy(input[indices[i]])
   end
end

-- Initialize using Kmeans++
function Kmeans:initKmeansPlus(input, p)
   self.p = p or self.p or 0.95
   assert(self.p>=0 and self.p<=1, "P value should be between 0-1.")

   local inputDim = input:nDimension()
   assert(inputDim == 2, "Incorrect input dimensionality. Expecting 2D.")
   local noOfSamples = input:size(1)

   local pcount = math.ceil((1-self.p)*noOfSamples)
   if pcount <= 0 then pcount = 1 end

   local initializedK = 1
   self.weight[initializedK]:copy(input[torch.random(noOfSamples)])
   initializedK = initializedK + 1

   local clusters = self.weight.new()
   local clusterDistances = self.weight.new()
   local temp = self.weight.new()
   local expandedSample = self.weight.new()
   local distances = self.weight.new()
   distances:resize(noOfSamples):fill(math.huge)
   local maxScores = self.weight.new()
   local maxIndx = self.weight.new()

   for k=initializedK, self.k do
      clusters = self.weight[{{initializedK-1, initializedK-1}}]
      for i=1, noOfSamples do
         temp:expand(input[{{i}}], 1, self.dim)
         expandedSample:resize(temp:size()):copy(temp)

         -- Squared Euclidean distance
         expandedSample:add(-1, clusters)
         clusterDistances:norm(expandedSample, 2, 2)
         clusterDistances:pow(2)
         distances[i] = math.min(clusterDistances:min(), distances[i])
      end
      maxScores, maxIndx = distances:sort(true)
      local tempIndx = torch.random(pcount)
      local indx = maxIndx[tempIndx]
      self.weight[initializedK]:copy(input[indx])
      initializedK = initializedK + 1
   end
end

local function isCudaTensor(tensor)
   local typename = torch.typename(tensor)
   if typename and typename:find('torch.Cuda*Tensor') then
      return true
   end
   return false
end

-- Kmeans updateOutput (forward)
function Kmeans:updateOutput(input)
   local inputDim = input:nDimension()
   assert(inputDim == 2, "Incorrect input dimensionality. Expecting 2D.")

   local batchSize = input:size(1)
   local dim = input:size(2)
   assert(dim == self.dim, "Dimensionality of input and weight don't match.")

   assert(input:isContiguous(), "Input is not contiguous.")

   -- a sample copied k times to compute distance between sample and weight
   self._expandedSamples = self._expandedSamples or self.weight.new()

   -- distance between a sample and weight
   self._clusterDistances = self._clusterDistances or self.weight.new()

   self._temp = self._temp or input.new()
   self._tempExpanded = self._tempExpanded or input.new()

   -- Expanding inputs
   self._temp:view(input, 1, batchSize, self.dim)
   self._tempExpanded:expand(self._temp, self.k, batchSize, self.dim)
   self._expandedSamples:resize(self.k, batchSize, self.dim)
                        :copy(self._tempExpanded)

   -- Expanding weights
   self._tempWeight = self._tempWeight or self.weight.new()
   self._tempWeightExp = self._tempWeightExp or self.weight.new()
   self._expandedWeight = self._expanedWeight or self.weight.new()
   self._tempWeight:view(self.weight, self.k, 1, self.dim)
   self._tempWeightExp:expand(self._tempWeight, self._expandedSamples:size())
   self._expandedWeight:resize(self.k, batchSize, self.dim)
                       :copy(self._tempWeightExp)

   -- x-c
   self._expandedSamples:add(-1, self._expandedWeight)
   -- Squared Euclidean distance
   self._clusterDistances:norm(self._expandedSamples, 2, 3)
   self._clusterDistances:pow(2)
   self._clusterDistances:resize(self.k, batchSize)

   self._minScore = self._minScore or self.weight.new()
   self._minIndx = self._minIndx or (isCudaTensor(input) and torch.CudaLongTensor() or torch.LongTensor())
   self._minScore:min(self._minIndx, self._clusterDistances, 1)
   self._minIndx:resize(batchSize)

   self.output:resize(batchSize):copy(self._minIndx)
   self.loss = self._minScore:sum()

   return self.output
end

-- Kmeans has its own criterion hence gradInput are zeros
function Kmeans:updateGradInput(input, gradOuput)
   self.gradInput:resize(input:size()):zero()

   return self.gradInput
end

-- We define kmeans update rule as c -> c + scale * 1/n * sum_i (x-c).
-- n is no. of x's belonging to c.
-- With this update rule and gradient descent will be negative the gradWeights.
function Kmeans:accGradParameters(input, gradOutput, scale)
   local scale = self.scale or scale or 1
   assert(scale > 0 , " Scale has to be positive.")

   -- Update cluster sample count
   local batchSize = input:size(1)
   self._cscAdder = self._cscAdder or self.weight.new()
   self._cscAdder:resize(batchSize):fill(1)
   self.clusterSampleCount:zero()
   self.clusterSampleCount:indexAdd(1, self._minIndx, self._cscAdder)

   -- scale * (x[k]-c[k]) where k is nearest cluster to x
   self._gradWeight = self._gradWeight or self.gradWeight.new()
   self._gradWeight:index(self.weight, 1, self._minIndx)
   self._gradWeight:mul(-1)
   self._gradWeight:add(input)
   self._gradWeight:mul(-scale)

   self._gradWeight2 = self._gradWeight2 or self.gradWeight.new()
   self._gradWeight2:resizeAs(self.gradWeight):zero()
   self._gradWeight2:indexAdd(1, self._minIndx, self._gradWeight)

   -- scale/n * sum_i (x-c)
   self._ccounts = self._ccounts or self.clusterSampleCount.new()
   self._ccounts:resize(self.k):copy(self.clusterSampleCount)
   self._ccounts:add(0.0000001) -- prevent division by zero errors

   self._gradWeight2:cdiv(self._ccounts:view(self.k,1):expandAs(self.gradWeight))

   self.gradWeight:add(self._gradWeight2)
end

function Kmeans:clearState()
   -- prevent premature memory allocations
   self._expandedSamples = nil
   self._clusterDistances = nil
   self._temp = nil
   self._tempExpanded = nil
   self._tempWeight = nil
   self._tempWeightExp = nil
   self._expandedWeight = nil
   self._minScore = nil
   self._minIndx = nil
   self._cscAdder = nil
end

function Kmeans:type(type, tensorCache)
   self:clearState()
   return parent.type(self, type, tensorCache)
end
