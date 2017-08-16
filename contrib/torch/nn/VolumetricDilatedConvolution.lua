local THNN = require 'nn.THNN'
local VolumetricDilatedConvolution, parent = torch.class('nn.VolumetricDilatedConvolution', 'nn.VolumetricConvolution')

function VolumetricDilatedConvolution:__init(nInputPlane, nOutputPlane, kT, kW, kH, dT, dW, dH, padT, padW, padH, dilationT, dilationW, dilationH)
   parent.__init(self, nInputPlane, nOutputPlane, kT, kW, kH, dT, dW, dH, padT, padW, padH)

   self.dilationT = dilationT or 1
   self.dilationW = dilationW or 1
   self.dilationH = dilationH or 1
end

function VolumetricDilatedConvolution:updateOutput(input)
   self.finput = self.finput or self.weight.new()
   self.fgradInput = self.fgradInput or self.weight.new()
   input.THNN.VolumetricDilatedConvolution_updateOutput(
      input:cdata(),
      self.output:cdata(),
      self.weight:cdata(),
      THNN.optionalTensor(self.bias),
      self.finput:cdata(),
      self.fgradInput:cdata(),
      self.kT, self.kW, self.kH,
      self.dT, self.dW, self.dH,
      self.padT, self.padW, self.padH,
      self.dilationT, self.dilationW, self.dilationH
   )
   return self.output
end

function VolumetricDilatedConvolution:updateGradInput(input, gradOutput)
   if self.gradInput then
      self.fgradInput = self.fgradInput or self.weight.new()
      input.THNN.VolumetricDilatedConvolution_updateGradInput(
         input:cdata(),
         gradOutput:cdata(),
         self.gradInput:cdata(),
         self.weight:cdata(),
         self.finput:cdata(),
         self.kT, self.kW, self.kH,
         self.dT, self.dW, self.dH,
         self.padT, self.padW, self.padH,
         self.dilationT, self.dilationW, self.dilationH
      )
      return self.gradInput
   end
end

function VolumetricDilatedConvolution:accGradParameters(input, gradOutput, scale)
   scale = scale or 1
   self.fgradInput = self.fgradInput or self.weight.new()
   input.THNN.VolumetricDilatedConvolution_accGradParameters(
      input:cdata(),
      gradOutput:cdata(),
      self.gradWeight:cdata(),
      THNN.optionalTensor(self.gradBias),
      self.finput:cdata(),
      self.fgradInput:cdata(),
      self.kT, self.kW, self.kH,
      self.dT, self.dW, self.dH,
      self.padT, self.padW, self.padH,
      self.dilationT, self.dilationW, self.dilationH,
      scale
   )
end

function VolumetricDilatedConvolution:__tostring__()
   local s = string.format('%s(%d -> %d, %dx%dx%d', torch.type(self),
         self.nInputPlane, self.nOutputPlane, self.kT, self.kW, self.kH)
   if self.dT ~= 1 or self.dW ~= 1 or self.dH ~= 1
   or self.padT ~= 0 or self.padW ~= 0 or self.padH ~= 0 then
     s = s .. string.format(', %d,%d,%d', self.dT, self.dW, self.dH)
   end
   if (self.padT or self.padW or self.padH)
   and (self.padT ~= 0 or self.padW ~= 0 or self.padH ~= 0) then
     s = s .. ', ' .. self.padT .. ',' .. self.padW .. ',' .. self.padH
   end
   s = s .. ', ' .. self.dilationT .. ','
       .. self.dilationW .. ',' .. self.dilationH
   if self.bias then
      return s .. ')'
   else
      return s .. ') without bias'
   end
end
