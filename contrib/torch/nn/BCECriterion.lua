local THNN = require 'nn.THNN'
local BCECriterion, parent = torch.class('nn.BCECriterion', 'nn.Criterion')

function BCECriterion:__init(weights, sizeAverage)
   parent.__init(self)
   if sizeAverage ~= nil then
      self.sizeAverage = sizeAverage
   else
      self.sizeAverage = true
   end
   if weights ~= nil then
      assert(weights:dim() == 1, "weights input should be 1-D Tensor")
      self.weights = weights
   end
end


function BCECriterion:__len()
   return self.weights and #self.weights or 0
end

function BCECriterion:updateOutput(input, target)
   -- - log(input) * target - log(1 - input) * (1 - target)
   assert( input:nElement() == target:nElement(),
   "input and target size mismatch")
   self.output_tensor = self.output_tensor or input.new(1)

   local weights = self.weights
   if weights ~= nil and target:dim() ~= 1 then
      weights = self.weights:view(1, target:size(2)):expandAs(target)
   end

   input.THNN.BCECriterion_updateOutput(
      input:cdata(),
      target:cdata(),
      self.output_tensor:cdata(),
      self.sizeAverage,
      THNN.optionalTensor(weights)
   )

   self.output = self.output_tensor[1]
   return self.output
end

function BCECriterion:updateGradInput(input, target)
   -- - (target - input) / ( input (1 - input) )
   assert( input:nElement() == target:nElement(),
   "input and target size mismatch")

   local weights = self.weights
   if weights ~= nil and target:dim() ~= 1 then
      weights = self.weights:view(1, target:size(2)):expandAs(target)
   end

   input.THNN.BCECriterion_updateGradInput(
      input:cdata(),
      target:cdata(),
      self.gradInput:cdata(),
      self.sizeAverage,
      THNN.optionalTensor(weights)
   )

   return self.gradInput
end
