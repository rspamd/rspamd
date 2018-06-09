local THNN = require 'nn.THNN'
local ClassNLLCriterion, parent = torch.class('nn.ClassNLLCriterion', 'nn.Criterion')

function ClassNLLCriterion:__init(weights, sizeAverage, ignoreIndex)
    parent.__init(self)
    self.sizeAverage = (sizeAverage == nil) and true or sizeAverage
    self.ignoreIndex = ignoreIndex or -100 -- this target index will be ignored
    if weights then
       assert(weights:dim() == 1, "weights input should be 1-D Tensor")
       self.weights = weights
    end

    self.output_tensor = torch.zeros(1)
    self.total_weight_tensor = torch.ones(1)
    self.target = torch.zeros(1):long()
end

function ClassNLLCriterion:__len()
   if (self.weights) then
      return #self.weights
   else
      return 0
   end
end

function ClassNLLCriterion:updateOutput(input, target)
   if type(target) == 'number' then
      if torch.typename(input):find('torch%.Cuda.*Tensor') then
          self.target = torch.CudaLongTensor and self.target:cudaLong() or self.target:cuda()
      else
          self.target = self.target:long()
      end
      self.target:resize(1)
      self.target[1] = target
   elseif torch.typename(input):find('torch%.Cuda.*Tensor') then
      self.target = torch.CudaLongTensor and target:cudaLong() or target
   else
      self.target = target:long()
   end

   input.THNN.ClassNLLCriterion_updateOutput(
      input:cdata(),
      self.target:cdata(),
      self.output_tensor:cdata(),
      self.sizeAverage,
      THNN.optionalTensor(self.weights),
      self.total_weight_tensor:cdata(),
      self.ignoreIndex
   )
   self.output = self.output_tensor[1]
   return self.output, self.total_weight_tensor[1]
end

function ClassNLLCriterion:updateGradInput(input, target)
   if type(target) == 'number' then
      if torch.typename(input):find('torch%.Cuda.*Tensor') then
          self.target = torch.CudaLongTensor and self.target:cudaLong() or self.target:cuda()
      else
          self.target = self.target:long()
      end
      self.target:resize(1)
      self.target[1] = target
   elseif torch.typename(input):find('torch%.Cuda.*Tensor') then
      self.target = torch.CudaLongTensor and target:cudaLong() or target
   else
      self.target = target:long()
   end

   self.gradInput:resizeAs(input):zero()

   input.THNN.ClassNLLCriterion_updateGradInput(
      input:cdata(),
      self.target:cdata(),
      self.gradInput:cdata(),
      self.sizeAverage,
      THNN.optionalTensor(self.weights),
      self.total_weight_tensor:cdata(),
      self.ignoreIndex
   )

   return self.gradInput
end
