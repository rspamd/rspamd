local SoftShrink, parent = torch.class('nn.SoftShrink', 'nn.Module')

function SoftShrink:__init(lam)
   parent.__init(self)
   self.lambda = lam or 0.5
end

function SoftShrink:updateOutput(input)
   input.THNN.SoftShrink_updateOutput(
      input:cdata(),
      self.output:cdata(),
      self.lambda
   )
   return self.output
end

function SoftShrink:updateGradInput(input, gradOutput)
   input.THNN.SoftShrink_updateGradInput(
      input:cdata(),
      gradOutput:cdata(),
      self.gradInput:cdata(),
      self.lambda
   )
   return self.gradInput
end
