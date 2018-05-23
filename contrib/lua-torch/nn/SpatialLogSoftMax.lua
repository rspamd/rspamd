local SpatialLogSoftMax = torch.class('nn.SpatialLogSoftMax', 'nn.Module')

function SpatialLogSoftMax:updateOutput(input)
   input.THNN.LogSoftMax_updateOutput(
      input:cdata(),
      self.output:cdata()
   )
   return self.output
end

function SpatialLogSoftMax:updateGradInput(input, gradOutput)
   input.THNN.LogSoftMax_updateGradInput(
      input:cdata(),
      gradOutput:cdata(),
      self.gradInput:cdata(),
      self.output:cdata()
   )
   return self.gradInput
end
