local VolumetricAveragePooling, parent = torch.class(
   'nn.VolumetricAveragePooling', 'nn.Module')

function VolumetricAveragePooling:__init(kT, kW, kH, dT, dW, dH)
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
end

function VolumetricAveragePooling:updateOutput(input)
   input.THNN.VolumetricAveragePooling_updateOutput(
      input:cdata(),
      self.output:cdata(),
      self.kT, self.kW, self.kH,
      self.dT, self.dW, self.dH
   )
   return self.output
end

function VolumetricAveragePooling:updateGradInput(input, gradOutput)
   input.THNN.VolumetricAveragePooling_updateGradInput(
      input:cdata(),
      gradOutput:cdata(),
      self.gradInput:cdata(),
      self.kT, self.kW, self.kH,
      self.dT, self.dW, self.dH
   )
   return self.gradInput
end

function VolumetricAveragePooling:empty()
   return parent.clearState(self)
end

function VolumetricAveragePooling:__tostring__()
   local s =  string.format('%s(%dx%dx%d, %d,%d,%d', torch.type(self),
                            self.kT, self.kW, self.kH, self.dT, self.dW, self.dH)
   if (self.padT or self.padW or self.padH) and
      (self.padT ~= 0 or self.padW ~= 0 or self.padH ~= 0) then
      s = s .. ', ' .. self.padT.. ',' .. self.padW .. ','.. self.padH
   end
   s = s .. ')'

   return s
end
