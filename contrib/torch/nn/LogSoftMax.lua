local LogSoftMax = torch.class('nn.LogSoftMax', 'nn.Module')

function LogSoftMax:updateOutput(input)
   input.THNN.LogSoftMax_updateOutput(
      input:cdata(),
      self.output:cdata()
   )
   return self.output
end

function LogSoftMax:updateGradInput(input, gradOutput)
   input.THNN.LogSoftMax_updateGradInput(
      input:cdata(),
      gradOutput:cdata(),
      self.gradInput:cdata(),
      self.output:cdata()
   )
   return self.gradInput
end
