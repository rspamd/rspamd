local SpatialMaxUnpooling, parent = torch.class('nn.SpatialMaxUnpooling', 'nn.Module')

function SpatialMaxUnpooling:__init(poolingModule)
   parent.__init(self)
   assert(torch.type(poolingModule)=='nn.SpatialMaxPooling', 'Argument must be a nn.SpatialMaxPooling module')
   assert(poolingModule.kH==poolingModule.dH and poolingModule.kW==poolingModule.dW, "The size of pooling module's kernel must be equal to its stride")
   self.pooling = poolingModule
end

function SpatialMaxUnpooling:setParams()
   self.indices = self.pooling.indices
   self.oheight = self.pooling.iheight
   self.owidth = self.pooling.iwidth
end

function SpatialMaxUnpooling:updateOutput(input)
   self:setParams()
   input.THNN.SpatialMaxUnpooling_updateOutput(
   input:cdata(),
   self.output:cdata(),
   self.indices:cdata(),
   self.owidth, self.oheight
   )
   return self.output
end

function SpatialMaxUnpooling:updateGradInput(input, gradOutput)
   self:setParams()
   input.THNN.SpatialMaxUnpooling_updateGradInput(
   input:cdata(),
   gradOutput:cdata(),
   self.gradInput:cdata(),
   self.indices:cdata(),
   self.owidth, self.oheight
   )
   return self.gradInput
end

function SpatialMaxUnpooling:empty()
   self:clearState()
end

function SpatialMaxUnpooling:__tostring__()
   return 'nn.SpatialMaxUnpooling associated to '..tostring(self.pooling)
end
