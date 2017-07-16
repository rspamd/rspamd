local SpatialMaxPooling, parent = torch.class('nn.SpatialMaxPooling', 'nn.Module')

function SpatialMaxPooling:__init(kW, kH, dW, dH, padW, padH)
   parent.__init(self)

   dW = dW or kW
   dH = dH or kH

   self.kW = kW
   self.kH = kH
   self.dW = dW
   self.dH = dH

   self.padW = padW or 0
   self.padH = padH or 0

   self.ceil_mode = false
   self.indices = torch.LongTensor()
end

function SpatialMaxPooling:ceil()
  self.ceil_mode = true
  return self
end

function SpatialMaxPooling:floor()
  self.ceil_mode = false
  return self
end

function SpatialMaxPooling:updateOutput(input)
   self.indices = self.indices or torch.LongTensor()
   if torch.typename(input):find('torch%.Cuda.*Tensor') then
      self.indices = torch.CudaLongTensor and self.indices:cudaLong() or self.indices
   else
      self.indices = self.indices:long()
   end

   local dims = input:dim()
   self.iheight = input:size(dims-1)
   self.iwidth = input:size(dims)

   -- backward compatibility
   self.ceil_mode = self.ceil_mode or false
   self.padW = self.padW or 0
   self.padH = self.padH or 0
   input.THNN.SpatialMaxPooling_updateOutput(
      input:cdata(),
      self.output:cdata(),
      self.indices:cdata(),
      self.kW, self.kH,
      self.dW, self.dH,
      self.padW, self.padH,
      self.ceil_mode
   )
   return self.output
end

function SpatialMaxPooling:updateGradInput(input, gradOutput)
   input.THNN.SpatialMaxPooling_updateGradInput(
      input:cdata(),
      gradOutput:cdata(),
      self.gradInput:cdata(),
      self.indices:cdata(),
      self.kW, self.kH,
      self.dW, self.dH,
      self.padW, self.padH,
      self.ceil_mode
   )
   return self.gradInput
end

-- for backward compat
function SpatialMaxPooling:empty()
   self:clearState()
end

function SpatialMaxPooling:__tostring__()
   local s =  string.format('%s(%dx%d, %d,%d', torch.type(self),
                            self.kW, self.kH, self.dW, self.dH)
   if (self.padW or self.padH) and (self.padW ~= 0 or self.padH ~= 0) then
      s = s .. ', ' .. self.padW .. ','.. self.padH
   end
   s = s .. ')'

   return s
end

function SpatialMaxPooling:clearState()
   if self.indices then
      self.indices:set()
   end
   return parent.clearState(self)
end
