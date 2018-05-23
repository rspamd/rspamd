local THNN = require 'nn.THNN'
local SpatialClassNLLCriterion, parent = torch.class('nn.SpatialClassNLLCriterion', 'nn.Criterion')

function SpatialClassNLLCriterion:__init(weights, sizeAverage)
    parent.__init(self)
    if sizeAverage ~= nil then
       self.sizeAverage = sizeAverage
    else
       self.sizeAverage = true
    end
    if weights then
       assert(weights:dim() == 1, "weights input should be 1-D Tensor")
       self.weights = weights
    end

    self.output_tensor = torch.zeros(1)
    self.total_weight_tensor = torch.ones(1)
    self.target = torch.zeros(1):long()
end

function SpatialClassNLLCriterion:__len()
   if (self.weights) then
      return #self.weights
   else
      return 0
   end
end

function SpatialClassNLLCriterion:updateOutput(input, target)
   if type(target) == 'number' then
      if torch.typename(input):find('torch%.Cuda.*Tensor') then
          self.target = torch.CudaLongTensor and self.target:cudaLong() or self.target:cuda()
      else
          self.target = self.target:long()
      end
      self.target[1] = target
   elseif torch.typename(input):find('torch%.Cuda.*Tensor') then
      self.target = torch.CudaLongTensor and target:cudaLong() or target
   else
      self.target = target:long()
   end

   input.THNN.SpatialClassNLLCriterion_updateOutput(
      input:cdata(),
      self.target:cdata(),
      self.output_tensor:cdata(),
      self.sizeAverage,
      THNN.optionalTensor(self.weights),
      self.total_weight_tensor:cdata()
   )
   self.output = self.output_tensor[1]
   return self.output, self.total_weight_tensor[1]
end

function SpatialClassNLLCriterion:updateGradInput(input, target)
   if type(target) == 'number' then
      if torch.typename(input):find('torch%.Cuda.*Tensor') then
          self.target = torch.CudaLongTensor and self.target:cudaLong() or self.target:cuda()
      else
          self.target = self.target:long()
      end
      self.target[1] = target
   elseif torch.typename(input):find('torch%.Cuda.*Tensor') then
      self.target = torch.CudaLongTensor and target:cudaLong() or target
   else
      self.target = target:long()
   end

   self.gradInput:resizeAs(input):zero()

   input.THNN.SpatialClassNLLCriterion_updateGradInput(
      input:cdata(),
      self.target:cdata(),
      self.gradInput:cdata(),
      self.sizeAverage,
      THNN.optionalTensor(self.weights),
      self.total_weight_tensor:cdata()
   )

   return self.gradInput
end
