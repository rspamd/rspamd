local THNN = require 'nn.THNN'
local MultiMarginCriterion, parent = torch.class('nn.MultiMarginCriterion', 'nn.Criterion')

function MultiMarginCriterion:__init(p, weights, margin)
   assert(p == nil or p == 1 or p == 2, 'only p=1 and p=2 supported')
   self.p = p or 1
   self.margin = margin or 1.0
   parent.__init(self)
   self.sizeAverage = true
   if weights then
       assert(weights:dim() == 1, "weights input should be 1-D Tensor")
       self.weights = weights
   end
end

function MultiMarginCriterion:updateOutput(input, target)
   -- backward compatibility
   if not torch.isTensor(target) then
     self.target_tensor = self.target_tensor or torch.LongTensor(1)
     self.target_tensor[1] = target
     target = self.target_tensor
   end
   if torch.typename(input):find('torch%.Cuda.*Tensor') then
     target = torch.CudaLongTensor and target:cudaLong() or target
   else
     target = target:long()
   end
   self.p = self.p or 1
   self.output_tensor = self.output_tensor or input.new(1)
   input.THNN.MultiMarginCriterion_updateOutput(
      input:cdata(),
      target:cdata(),
      self.output_tensor:cdata(),
      self.sizeAverage,
      self.p,
      THNN.optionalTensor(self.weights),
      self.margin
   )
   self.output = self.output_tensor[1]
   return self.output
end

function MultiMarginCriterion:updateGradInput(input, target)
   if not torch.isTensor(target) then
     self.target_tensor = self.target_tensor or torch.LongTensor(1)
     self.target_tensor[1] = target
     target = self.target_tensor
   end
   if torch.typename(input):find('torch%.Cuda.*Tensor') then
     target = torch.CudaLongTensor and target:cudaLong() or target
   else
     target = target:long()
   end
   input.THNN.MultiMarginCriterion_updateGradInput(
      input:cdata(),
      target:cdata(),
      self.gradInput:cdata(),
      self.sizeAverage,
      self.p,
      THNN.optionalTensor(self.weights),
      self.margin
   )
   return self.gradInput
end
