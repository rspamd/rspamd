local AbsCriterion, parent = torch.class('nn.AbsCriterion', 'nn.Criterion')

function AbsCriterion:__init(sizeAverage)
   parent.__init(self)
   if sizeAverage ~= nil then
      self.sizeAverage = sizeAverage
   else
      self.sizeAverage = true
   end
end

function AbsCriterion:updateOutput(input, target)
   self.output_tensor = self.output_tensor or input.new(1)
   input.THNN.AbsCriterion_updateOutput(
      input:cdata(),
      target:cdata(),
      self.output_tensor:cdata(),
      self.sizeAverage
   )
   self.output = self.output_tensor[1]
   return self.output
end

function AbsCriterion:updateGradInput(input, target)
   input.THNN.AbsCriterion_updateGradInput(
      input:cdata(),
      target:cdata(),
      self.gradInput:cdata(),
      self.sizeAverage
   )
   return self.gradInput
end
