local SoftMin, parent = torch.class('nn.SoftMin', 'nn.Module')

function SoftMin:updateOutput(input)
   self.mininput = self.mininput or input.new()
   self.mininput:resizeAs(input):copy(input):mul(-1)
   input.THNN.SoftMax_updateOutput(
      self.mininput:cdata(),
      self.output:cdata()
   )
   return self.output
end

function SoftMin:updateGradInput(input, gradOutput)
   self.mininput = self.mininput or input.new()
   self.mininput:resizeAs(input):copy(input):mul(-1)

   input.THNN.SoftMax_updateGradInput(
      self.mininput:cdata(),
      gradOutput:cdata(),
      self.gradInput:cdata(),
      self.output:cdata()
   )

   self.gradInput:mul(-1)
   return self.gradInput
end

function SoftMin:clearState()
   if self.mininput then self.mininput:set() end
   return parent.clearState(self)
end
