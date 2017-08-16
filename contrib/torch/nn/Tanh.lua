local Tanh = torch.class('nn.Tanh', 'nn.Module')

function Tanh:updateOutput(input)
   input.THNN.Tanh_updateOutput(
      input:cdata(),
      self.output:cdata()
   )
   return self.output
end

function Tanh:updateGradInput(input, gradOutput)
   input.THNN.Tanh_updateGradInput(
      input:cdata(),
      gradOutput:cdata(),
      self.gradInput:cdata(),
      self.output:cdata()
   )
   return self.gradInput
end
