local Sigmoid = torch.class('nn.Sigmoid', 'nn.Module')

function Sigmoid:updateOutput(input)
   input.THNN.Sigmoid_updateOutput(
      input:cdata(),
      self.output:cdata()
   )
   return self.output
end

function Sigmoid:updateGradInput(input, gradOutput)
   input.THNN.Sigmoid_updateGradInput(
      input:cdata(),
      gradOutput:cdata(),
      self.gradInput:cdata(),
      self.output:cdata()
   )
   return self.gradInput
end
