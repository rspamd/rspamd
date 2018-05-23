local PReLU, parent = torch.class('nn.PReLU','nn.Module')

function PReLU:__init(nOutputPlane)
   parent.__init(self)
   -- if no argument provided, use shared model (weight is scalar)
   self.nOutputPlane = nOutputPlane or 0
   self.weight = torch.Tensor(nOutputPlane or 1):fill(0.25)
   self.gradWeight = torch.Tensor(nOutputPlane or 1)
end

function PReLU:updateOutput(input)
   input.THNN.PReLU_updateOutput(
      input:cdata(),
      self.output:cdata(),
      self.weight:cdata(),
      self.nOutputPlane
   )
   return self.output
end

function PReLU:updateGradInput(input, gradOutput)
   input.THNN.PReLU_updateGradInput(
      input:cdata(),
      gradOutput:cdata(),
      self.gradInput:cdata(),
      self.weight:cdata(),
      self.nOutputPlane
   )
   return self.gradInput
end

function PReLU:accGradParameters(input, gradOutput, scale)
   self.gradWeightBuf = self.gradWeightBuf or input.new()
   self.gradWeightBuf2 = self.gradWeightBuf2 or input.new()
   input.THNN.PReLU_accGradParameters(
      input:cdata(),
      gradOutput:cdata(),
      self.gradInput:cdata(),
      self.weight:cdata(),
      self.gradWeight:cdata(),
      self.gradWeightBuf:cdata(),
      self.gradWeightBuf2:cdata(),
      self.nOutputPlane,
      scale or 1
   )
   return self.gradWeight
end

function PReLU:clearState()
   nn.utils.clear(self, 'gradWeightBuf', 'gradWeightBuf2')
   return parent.clearState(self)
end
