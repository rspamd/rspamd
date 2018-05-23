local SpatialSoftMax, _ = torch.class('nn.SpatialSoftMax', 'nn.Module')

function SpatialSoftMax:updateOutput(input)
   input.THNN.SoftMax_updateOutput(
      input:cdata(),
      self.output:cdata()
   )
   return self.output
end

function SpatialSoftMax:updateGradInput(input, gradOutput)
   input.THNN.SoftMax_updateGradInput(
      input:cdata(),
      gradOutput:cdata(),
      self.gradInput:cdata(),
      self.output:cdata()
   )
   return self.gradInput
end
