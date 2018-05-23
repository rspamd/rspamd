local THNN = require 'nn.THNN'
local SpatialDepthWiseConvolution, parent = torch.class('nn.SpatialDepthWiseConvolution', 'nn.Module')

function SpatialDepthWiseConvolution:__init(nInputPlane, nOutputPlane, kW, kH, dW, dH, padW, padH)
   parent.__init(self)

   dW = dW or 1
   dH = dH or 1

   self.nInputPlane = nInputPlane
   self.nOutputPlane = nOutputPlane
   self.kW = kW
   self.kH = kH

   self.dW = dW
   self.dH = dH
   self.padW = padW or 0
   self.padH = padH or self.padW

   self.weight = torch.Tensor(nOutputPlane, nInputPlane*kH*kW)
   self.bias = torch.Tensor(nOutputPlane, nInputPlane)
   self.gradWeight = torch.Tensor(nOutputPlane, nInputPlane*kH*kW)
   self.gradBias = torch.Tensor(nOutputPlane, nInputPlane)

   self:reset()
end

function SpatialDepthWiseConvolution:noBias()
   self.bias = nil
   self.gradBias = nil
   return self
end

function SpatialDepthWiseConvolution:reset(stdv)
   if stdv then
      stdv = stdv * math.sqrt(3)
   else
      stdv = 1/math.sqrt(self.kW*self.kH*self.nInputPlane)
   end
   if nn.oldSeed then
      self.weight:apply(function()
         return torch.uniform(-stdv, stdv)
      end)
      self.bias:apply(function()
         return torch.uniform(-stdv, stdv)
      end)
   else
      self.weight:uniform(-stdv, stdv)
      self.bias:uniform(-stdv, stdv)
   end
end

function SpatialDepthWiseConvolution:updateOutput(input)
   assert(input.THNN, torch.type(input)..'.THNN backend not imported')
   self.finput = self.finput or input.new()
   self.fgradInput = self.fgradInput or input.new()
   -- backward compatibility
   if self.padding then
      self.padW = self.padding
      self.padH = self.padding
      self.padding = nil
   end
   input.THNN.SpatialDepthWiseConvolution_updateOutput(
      input:cdata(),
      self.output:cdata(),
      self.weight:cdata(),
      THNN.optionalTensor(self.bias),
      self.finput:cdata(),
      self.fgradInput:cdata(),
      self.kW, self.kH,
      self.dW, self.dH,
      self.padW, self.padH
   )
   return self.output
end

function SpatialDepthWiseConvolution:updateGradInput(input, gradOutput)
   assert(input.THNN, torch.type(input)..'.THNN backend not imported')
   if self.gradInput then
      input.THNN.SpatialDepthWiseConvolution_updateGradInput(
         input:cdata(),
         gradOutput:cdata(),
         self.gradInput:cdata(),
         self.weight:cdata(),
         self.finput:cdata(),
         self.fgradInput:cdata(),
         self.kW, self.kH,
         self.dW, self.dH,
         self.padW, self.padH
      )
      return self.gradInput
   end
end

function SpatialDepthWiseConvolution:accGradParameters(input, gradOutput, scale)
   assert(input.THNN, torch.type(input)..'.THNN backend not imported')
   scale = scale or 1
   assert((self.bias and self.gradBias) or (self.bias == nil and self.gradBias == nil))
   input.THNN.SpatialDepthWiseConvolution_accGradParameters(
      input:cdata(),
      gradOutput:cdata(),
      self.gradWeight:cdata(),
      THNN.optionalTensor(self.gradBias),
      self.finput:cdata(),
      self.fgradInput:cdata(),
      self.kW, self.kH,
      self.dW, self.dH,
      self.padW, self.padH,
      scale
   )
end

function SpatialDepthWiseConvolution:type(type,tensorCache)
   self.finput = self.finput and torch.Tensor()
   self.fgradInput = self.fgradInput and torch.Tensor()
   return parent.type(self,type,tensorCache)
end

function SpatialDepthWiseConvolution:__tostring__()
   local s = string.format('%s(%d -> %d, %dx%d', torch.type(self),
         self.nInputPlane, self.nOutputPlane, self.kW, self.kH)
   if self.dW ~= 1 or self.dH ~= 1 or self.padW ~= 0 or self.padH ~= 0 then
     s = s .. string.format(', %d,%d', self.dW, self.dH)
   end
   if (self.padW or self.padH) and (self.padW ~= 0 or self.padH ~= 0) then
     s = s .. ', ' .. self.padW .. ',' .. self.padH
   end
   if self.bias then
      return s .. ')'
   else
      return s .. ') without bias'
   end
end

function SpatialDepthWiseConvolution:clearState()
   nn.utils.clear(self, 'finput', 'fgradInput', '_input', '_gradOutput')
   return parent.clearState(self)
end

