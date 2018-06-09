local THNN = require 'nn.THNN'
local VolumetricConvolution, parent = torch.class('nn.VolumetricConvolution', 'nn.Module')

function VolumetricConvolution:__init(nInputPlane, nOutputPlane, kT, kW, kH, dT, dW, dH, padT, padW, padH)
   parent.__init(self)

   dT = dT or 1
   dW = dW or 1
   dH = dH or 1

   self.nInputPlane = nInputPlane
   self.nOutputPlane = nOutputPlane
   self.kT = kT
   self.kW = kW
   self.kH = kH
   self.dT = dT
   self.dW = dW
   self.dH = dH
   self.padT = padT or 0
   self.padW = padW or self.padT
   self.padH = padH or self.padW

   self.weight = torch.Tensor(nOutputPlane, nInputPlane, kT, kH, kW)
   self.bias = torch.Tensor(nOutputPlane)
   self.gradWeight = torch.Tensor(nOutputPlane, nInputPlane, kT, kH, kW)
   self.gradBias = torch.Tensor(nOutputPlane)
   self:reset()
end

function VolumetricConvolution:reset(stdv)
   if stdv then
      stdv = stdv * math.sqrt(3)
   else
      stdv = 1/math.sqrt(self.kT*self.kW*self.kH*self.nInputPlane)
   end
   if nn.oldSeed then
      self.weight:apply(function()
         return torch.uniform(-stdv, stdv)
      end)
      if self.bias then
         self.bias:apply(function()
            return torch.uniform(-stdv, stdv)
         end)
      end
   else
      self.weight:uniform(-stdv, stdv)
      if self.bias then
         self.bias:uniform(-stdv, stdv)
      end
   end
end

function VolumetricConvolution:noBias()
   self.bias = nil
   self.gradBias = nil
   return self
end

function VolumetricConvolution:updateOutput(input)
   self.finput = self.finput or input.new()
   self.fgradInput = self.fgradInput or input.new()
   if torch.typename(input):find('torch%.Cuda.*Tensor') then
      input.THNN.VolumetricConvolution_updateOutput(
        input:cdata(),
        self.output:cdata(),
        self.weight:cdata(),
        THNN.optionalTensor(self.bias),
        self.finput:cdata(),
        self.fgradInput:cdata(),
        self.dT, self.dW, self.dH,
        self.padT, self.padW, self.padH
      )
   else
      input.THNN.VolumetricConvolutionMM_updateOutput(
         input:cdata(),
         self.output:cdata(),
         self.weight:cdata(),
         THNN.optionalTensor(self.bias),
         self.finput:cdata(),
         self.kT, self.kW, self.kH,
         self.dT, self.dW, self.dH,
         self.padT, self.padW, self.padH
      )
   end
   return self.output
end

function VolumetricConvolution:updateGradInput(input, gradOutput)
   if torch.typename(input):find('torch%.Cuda.*Tensor') then
      input.THNN.VolumetricConvolution_updateGradInput(
         input:cdata(),
         gradOutput:cdata(),
         self.gradInput:cdata(),
         self.weight:cdata(),
         self.finput:cdata(),
         self.dT, self.dW, self.dH,
         self.padT, self.padW, self.padH
      )
      return self.gradInput
   else
      if self.gradInput then
         input.THNN.VolumetricConvolutionMM_updateGradInput(
            input:cdata(),
            gradOutput:cdata(),
            self.gradInput:cdata(),
            self.weight:cdata(),
            self.finput:cdata(),
            self.fgradInput:cdata(),
            self.kT, self.kW, self.kH,
            self.dT, self.dW, self.dH,
            self.padT, self.padW, self.padH
         )
         return self.gradInput
      end
   end
end

function VolumetricConvolution:accGradParameters(input, gradOutput, scale)
   if torch.typename(input):find('torch%.Cuda.*Tensor') then
      input.THNN.VolumetricConvolution_accGradParameters(
         input:cdata(),
         gradOutput:cdata(),
         self.gradWeight:cdata(),
         THNN.optionalTensor(self.gradBias),
         self.finput:cdata(),
         self.fgradInput:cdata(),
         self.dT, self.dW, self.dH,
         self.padT, self.padW, self.padH,
         scale or 1
      )
   else
      input.THNN.VolumetricConvolutionMM_accGradParameters(
         input:cdata(),
         gradOutput:cdata(),
         self.gradWeight:cdata(),
         THNN.optionalTensor(self.gradBias),
         self.finput:cdata(),
         self.kT, self.kW, self.kH,
         self.dT, self.dW, self.dH,
         self.padT, self.padW, self.padH,
         scale or 1
      )
   end
end

function VolumetricConvolution:type(type, tensorCache)
   if self.finput then self.finput:set() end
   if self.fgradInput then self.fgradInput:set() end
   return parent.type(self, type, tensorCache)
end

function VolumetricConvolution:clearState()
   nn.utils.clear(self, 'finput', 'fgradInput', '_input', '_gradOutput')
   return parent.clearState(self)
end

function VolumetricConvolution:__tostring__()
   local s = string.format('%s(%d -> %d, %dx%dx%d', torch.type(self),
         self.nInputPlane, self.nOutputPlane, self.kT, self.kW, self.kH)
   if self.dT ~= 1 or self.dW ~= 1 or self.dH ~= 1 or
      self.padT ~= 0 or self.padW ~= 0 or self.padH ~= 0 then
     s = s .. string.format(', %d,%d,%d', self.dT, self.dW, self.dH)
   end
   if (self.padT or self.padW or self.padH) and
      (self.padT ~=0 or self.padW ~= 0 or self.padH ~= 0) then
     s = s .. ', ' .. self.padT .. ',' .. self.padW .. ',' .. self.padH
   end
   return s .. ')'
end
