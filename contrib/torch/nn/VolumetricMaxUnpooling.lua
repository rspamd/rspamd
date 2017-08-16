local VolumetricMaxUnpooling, parent = torch.class('nn.VolumetricMaxUnpooling', 'nn.Module')

function VolumetricMaxUnpooling:__init(poolingModule)
  parent.__init(self)
  assert(torch.type(poolingModule)=='nn.VolumetricMaxPooling', 'Argument must be a nn.VolumetricMaxPooling module')
  assert(poolingModule.kT==poolingModule.dT and poolingModule.kH==poolingModule.dH and poolingModule.kW==poolingModule.dW, "The size of pooling module's kernel must be equal to its stride")
  self.pooling = poolingModule
end

function VolumetricMaxUnpooling:setParams()
  self.indices = self.pooling.indices
  self.otime = self.pooling.itime
  self.oheight = self.pooling.iheight
  self.owidth = self.pooling.iwidth
  self.dT = self.pooling.dT
  self.dH = self.pooling.dH
  self.dW = self.pooling.dW
  self.padT = self.pooling.padT
  self.padH = self.pooling.padH
  self.padW = self.pooling.padW
end

function VolumetricMaxUnpooling:updateOutput(input)
  self:setParams()
  input.THNN.VolumetricMaxUnpooling_updateOutput(
     input:cdata(),
     self.output:cdata(),
     self.indices:cdata(),
     self.otime, self.owidth, self.oheight,
     self.dT, self.dW, self.dH,
     self.padT, self.padW, self.padH
  )
  return self.output
end

function VolumetricMaxUnpooling:updateGradInput(input, gradOutput)
  self:setParams()
  input.THNN.VolumetricMaxUnpooling_updateGradInput(
     input:cdata(),
     gradOutput:cdata(),
     self.gradInput:cdata(),
     self.indices:cdata(),
     self.otime, self.owidth, self.oheight,
     self.dT, self.dW, self.dH,
     self.padT, self.padW, self.padH
  )
  return self.gradInput
end

function VolumetricMaxUnpooling:empty()
   self:clearState()
end

function VolumetricMaxUnpooling:__tostring__()
   return 'nn.VolumetricMaxUnpooling associated to '..tostring(self.pooling)
end
