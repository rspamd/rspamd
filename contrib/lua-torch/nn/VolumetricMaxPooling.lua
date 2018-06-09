local VolumetricMaxPooling, parent = torch.class('nn.VolumetricMaxPooling', 'nn.Module')

VolumetricMaxPooling.__version = 2

function VolumetricMaxPooling:__init(kT, kW, kH, dT, dW, dH, padT, padW, padH)
   parent.__init(self)

   dT = dT or kT
   dW = dW or kW
   dH = dH or kH

   self.kT = kT
   self.kH = kH
   self.kW = kW
   self.dT = dT
   self.dW = dW
   self.dH = dH

   self.padT = padT or 0
   self.padW = padW or 0
   self.padH = padH or 0


   self.ceil_mode = false
   self.indices = torch.LongTensor()
end

function VolumetricMaxPooling:ceil()
    self.ceil_mode = true
    return self
end

function VolumetricMaxPooling:floor()
    self.ceil_mode = false
    return self
end

function VolumetricMaxPooling:updateOutput(input)
   local dims = input:dim()
   self.itime = input:size(dims-2)
   self.iheight = input:size(dims-1)
   self.iwidth = input:size(dims)

   self.indices = self.indices or torch.LongTensor()
   if torch.typename(input):find('torch%.Cuda.*Tensor') then
      self.indices = torch.CudaLongTensor and self.indices:cudaLong() or self.indices
   else
      self.indices = self.indices:long()
   end
   input.THNN.VolumetricMaxPooling_updateOutput(
      input:cdata(),
      self.output:cdata(),
      self.indices:cdata(),
      self.kT, self.kW, self.kH,
      self.dT, self.dW, self.dH,
      self.padT, self.padW, self.padH,
      self.ceil_mode
   )
   return self.output
end

function VolumetricMaxPooling:updateGradInput(input, gradOutput)
   input.THNN.VolumetricMaxPooling_updateGradInput(
      input:cdata(),
      gradOutput:cdata(),
      self.gradInput:cdata(),
      self.indices:cdata(),
      self.kT, self.kW, self.kH,
      self.dT, self.dW, self.dH,
      self.padT, self.padW, self.padH,
      self.ceil_mode
   )
   return self.gradInput
end

function VolumetricMaxPooling:empty()
   self:clearState()
end

function VolumetricMaxPooling:clearState()
   if self.indices then self.indices:set() end
   return parent.clearState(self)
end

function VolumetricMaxPooling:read(file, version)
   parent.read(self, file)
   if version < 2 then
      self.ceil_mode = false
   end
end

function VolumetricMaxPooling:__tostring__()
   local s =  string.format('%s(%dx%dx%d, %d,%d,%d', torch.type(self),
                            self.kT, self.kW, self.kH, self.dT, self.dW, self.dH)
   if (self.padT or self.padW or self.padH) and
      (self.padT ~= 0 or self.padW ~= 0 or self.padH ~= 0) then
      s = s .. ', ' .. self.padT.. ',' .. self.padW .. ','.. self.padH
   end
   s = s .. ')'

   return s
end
