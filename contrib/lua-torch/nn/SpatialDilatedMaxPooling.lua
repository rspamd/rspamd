local THNN = require 'nn.THNN'
local SpatialDilatedMaxPooling, parent = torch.class('nn.SpatialDilatedMaxPooling', 'nn.SpatialMaxPooling')

function SpatialDilatedMaxPooling:__init(kW, kH, dW, dH, padW, padH, dilationW, dilationH)
   parent.__init(self, kW, kH, dW, dH, padW, padH)

   self.dilationW = dilationW or 1
   self.dilationH = dilationH or 1
end

function SpatialDilatedMaxPooling:updateOutput(input)
   self.indices = self.indices or torch.LongTensor()
   if torch.typename(input):find('torch%.Cuda.*Tensor') then
      self.indices = torch.CudaLongTensor and self.indices:cudaLong() or self.indices
   else
      self.indices = self.indices:long()
   end

   local dims = input:dim()
   self.iheight = input:size(dims-1)
   self.iwidth = input:size(dims)

   input.THNN.SpatialDilatedMaxPooling_updateOutput(
      input:cdata(),
      self.output:cdata(),
      self.indices:cdata(),
      self.kW, self.kH,
      self.dW, self.dH,
      self.padW, self.padH,
      self.dilationW, self.dilationH,
      self.ceil_mode
   )
   return self.output
end

function SpatialDilatedMaxPooling:updateGradInput(input, gradOutput)
   input.THNN.SpatialDilatedMaxPooling_updateGradInput(
      input:cdata(),
      gradOutput:cdata(),
      self.gradInput:cdata(),
      self.indices:cdata(),
      self.kW, self.kH,
      self.dW, self.dH,
      self.padW, self.padH,
      self.dilationW, self.dilationH,
      self.ceil_mode
   )
   return self.gradInput
end

function SpatialDilatedMaxPooling:__tostring__()
   local s =  string.format('%s(%dx%d, %d,%d', torch.type(self),
                            self.kW, self.kH, self.dW, self.dH)
   if (self.padW or self.padH) and (self.padW ~= 0 or self.padH ~= 0) then
      s = s .. ', ' .. self.padW .. ','.. self.padH
   end
   s = s .. ', ' .. self.dilationW .. ',' .. self.dilationH
   s = s .. ')'
   return s
end

function SpatialDilatedMaxPooling:clearState()
   if self.indices then
      self.indices:set()
   end
   return parent.clearState(self)
end
