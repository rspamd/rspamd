local THNN = require 'nn.THNN'
local VolumetricDilatedMaxPooling, parent = torch.class('nn.VolumetricDilatedMaxPooling', 'nn.VolumetricMaxPooling')

function VolumetricDilatedMaxPooling:__init(kT, kW, kH, dT, dW, dH, padT, padW, padH, dilationT, dilationW, dilationH)
   parent.__init(self, kT, kW, kH, dT, dW, dH, padT, padW, padH)

   self.dilationT = dilationT or 1
   self.dilationW = dilationW or 1
   self.dilationH = dilationH or 1

end

function VolumetricDilatedMaxPooling:updateOutput(input)
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
   input.THNN.VolumetricDilatedMaxPooling_updateOutput(
      input:cdata(),
      self.output:cdata(),
      self.indices:cdata(),
      self.kT, self.kW, self.kH,
      self.dT, self.dW, self.dH,
      self.padT, self.padW, self.padH,
      self.dilationT, self.dilationW, self.dilationH,
      self.ceil_mode
   )
   return self.output
end

function VolumetricDilatedMaxPooling:updateGradInput(input, gradOutput)
   input.THNN.VolumetricDilatedMaxPooling_updateGradInput(
      input:cdata(),
      gradOutput:cdata(),
      self.gradInput:cdata(),
      self.indices:cdata(),
      self.kT, self.kW, self.kH,
      self.dT, self.dW, self.dH,
      self.padT, self.padW, self.padH,
      self.dilationT, self.dilationW, self.dilationH,
      self.ceil_mode
   )
   return self.gradInput
end

function VolumetricDilatedMaxPooling:clearState()
   if self.indices then
      self.indices:set()
   end
   return parent.clearState(self)
end

function VolumetricDilatedMaxPooling:__tostring__()
   local s =  string.format('%s(%dx%dx%d, %d,%d,%d', torch.type(self),
                            self.kT, self.kW, self.kH, self.dT, self.dW, self.dH)
   if (self.padT or self.padW or self.padH) and
      (self.padT ~= 0 or self.padW ~= 0 or self.padH ~= 0) then
      s = s .. ', ' .. self.padT.. ',' .. self.padW .. ','.. self.padH
   end
   s = s .. ', ' .. self.dilationT .. ',' .. self.dilationW .. ',' .. self.dilationH
   s = s .. ')'

   return s
end
