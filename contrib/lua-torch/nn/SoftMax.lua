local SoftMax, _ = torch.class('nn.SoftMax', 'nn.Module')

function SoftMax:updateOutput(input)
   input.THNN.SoftMax_updateOutput(
      input:cdata(),
      self.output:cdata()
   )
   return self.output
end

function SoftMax:updateGradInput(input, gradOutput)
   input.THNN.SoftMax_updateGradInput(
      input:cdata(),
      gradOutput:cdata(),
      self.gradInput:cdata(),
      self.output:cdata()
   )
   return self.gradInput
end
