local SoftMarginCriterion, parent = torch.class('nn.SoftMarginCriterion', 'nn.Criterion')

function SoftMarginCriterion:__init()
   parent.__init(self)
   self.sizeAverage = true
end

function SoftMarginCriterion:updateOutput(input, target)
   self.output_tensor = self.output_tensor or input.new(1)
   input.THNN.SoftMarginCriterion_updateOutput(
      input:cdata(), target:cdata(),
      self.output_tensor:cdata(),
      self.sizeAverage)
   self.output = self.output_tensor[1]
   return self.output
end

function SoftMarginCriterion:updateGradInput(input, target)
   input.THNN.SoftMarginCriterion_updateGradInput(
      input:cdata(), target:cdata(),
      self.gradInput:cdata(),
      self.sizeAverage)
   return self.gradInput
end
