local SpatialConvolutionLocal, parent = torch.class('nn.SpatialConvolutionLocal', 'nn.Module')

function SpatialConvolutionLocal:__init(nInputPlane, nOutputPlane, iW, iH ,kW, kH, dW, dH, padW, padH)
   parent.__init(self)

   dW = dW or 1
   dH = dH or 1

   self.nInputPlane = nInputPlane
   self.nOutputPlane = nOutputPlane
   self.kW = kW
   self.kH = kH
   self.iW = iW
   self.iH = iH

   self.dW = dW
   self.dH = dH
   self.padW = padW or 0
   self.padH = padH or self.padW
   self.oW = math.floor((self.padW * 2 + iW - self.kW) / self.dW) + 1
   self.oH = math.floor((self.padH * 2 + iH - self.kH) / self.dH) + 1
   assert(1 <= self.oW and 1 <= self.oH, 'illegal configuration: output width or height less than 1')

   self.weight = torch.Tensor(self.oH, self.oW, nOutputPlane, nInputPlane, kH, kW)
   self.bias = torch.Tensor(nOutputPlane, self.oH, self.oW)
   self.gradWeight = torch.Tensor():resizeAs(self.weight)
   self.gradBias = torch.Tensor():resizeAs(self.bias)

   self:reset()
end

function SpatialConvolutionLocal:reset(stdv)
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

local function viewWeight(self)
   self.weight = self.weight:view(self.oH * self.oW, self.nOutputPlane, self.nInputPlane * self.kH * self.kW)
   if self.gradWeight and self.gradWeight:dim() > 0 then
      self.gradWeight = self.gradWeight:view(self.oH * self.oW, self.nOutputPlane, self.nInputPlane * self.kH * self.kW)
   end
end

local function unviewWeight(self)
   self.weight = self.weight:view(self.oH, self.oW, self.nOutputPlane, self.nInputPlane, self.kH, self.kW)
   if self.gradWeight and self.gradWeight:dim() > 0 then
      self.gradWeight = self.gradWeight:view(self.oH, self.oW, self.nOutputPlane, self.nInputPlane, self.kH, self.kW)
   end
end

local function checkInputSize(self, input)
   if input:nDimension() == 3 then
      if input:size(1) ~= self.nInputPlane or input:size(2) ~= self.iH or input:size(3) ~= self.iW then
         error(string.format('Given input size: (%dx%dx%d) inconsistent with expected input size: (%dx%dx%d).',
                             input:size(1), input:size(2), input:size(3), self.nInputPlane, self.iH, self.iW))
      end
   elseif input:nDimension() == 4 then
      if input:size(2) ~= self.nInputPlane or input:size(3) ~= self.iH or input:size(4) ~= self.iW then
         error(string.format('Given input size: (%dx%dx%dx%d) inconsistent with expected input size: (batchsize x%dx%dx%d).',
                              input:size(1), input:size(2), input:size(3), input:size(4), self.nInputPlane, self.iH, self.iW))
      end
   else
      error('3D or 4D(batch mode) tensor expected')
   end
end

local function checkOutputSize(self, input, output)
   if output:nDimension() ~= input:nDimension() then
      error('inconsistent dimension between output and input.')
   end
   if output:nDimension() == 3 then
      if output:size(1) ~= self.nOutputPlane or output:size(2) ~= self.oH or output:size(3) ~= self.oW then
         error(string.format('Given output size: (%dx%dx%d) inconsistent with expected output size: (%dx%dx%d).',
                             output:size(1), output:size(2), output:size(3), self.nOutputPlane, self.oH, self.oW))
      end
   elseif output:nDimension() == 4 then
      if output:size(2) ~= self.nOutputPlane or output:size(3) ~= self.oH or output:size(4) ~= self.oW then
         error(string.format('Given output size: (%dx%dx%dx%d) inconsistent with expected output size: (batchsize x%dx%dx%d).',
                              output:size(1), output:size(2), output:size(3), output:size(4), self.nOutputPlane, self.oH, self.oW))
      end
   else
      error('3D or 4D(batch mode) tensor expected')
   end
end

function SpatialConvolutionLocal:updateOutput(input)
   self.finput = self.finput or input.new()
   self.fgradInput = self.fgradInput or input.new()
   checkInputSize(self, input)
   viewWeight(self)
   input.THNN.SpatialConvolutionLocal_updateOutput(
      input:cdata(),
      self.output:cdata(),
      self.weight:cdata(),
      self.bias:cdata(),
      self.finput:cdata(),
      self.fgradInput:cdata(),
      self.kW, self.kH,
      self.dW, self.dH,
      self.padW, self.padH,
      self.iW, self.iH,
      self.oW, self.oH
   )
   unviewWeight(self)
   return self.output
end

function SpatialConvolutionLocal:updateGradInput(input, gradOutput)
   checkInputSize(self, input)
   checkOutputSize(self, input, gradOutput)
   if self.gradInput then
      viewWeight(self)
      input.THNN.SpatialConvolutionLocal_updateGradInput(
         input:cdata(),
         gradOutput:cdata(),
         self.gradInput:cdata(),
         self.weight:cdata(),
         self.finput:cdata(),
         self.fgradInput:cdata(),
         self.kW, self.kH,
         self.dW, self.dH,
         self.padW, self.padH,
         self.iW, self.iH,
         self.oW, self.oH
      )
      unviewWeight(self)
      return self.gradInput
   end
end

function SpatialConvolutionLocal:accGradParameters(input, gradOutput, scale)
   scale = scale or 1
   checkInputSize(self, input)
   checkOutputSize(self, input, gradOutput)
   viewWeight(self)
   input.THNN.SpatialConvolutionLocal_accGradParameters(
      input:cdata(),
      gradOutput:cdata(),
      self.gradWeight:cdata(),
      self.gradBias:cdata(),
      self.finput:cdata(),
      self.fgradInput:cdata(),
      self.kW, self.kH,
      self.dW, self.dH,
      self.padW, self.padH,
      self.iW, self.iH,
      self.oW, self.oH,
      scale
   )
   unviewWeight(self)
end

function SpatialConvolutionLocal:type(type,tensorCache)
   self.finput = self.finput and torch.Tensor()
   self.fgradInput = self.fgradInput and torch.Tensor()
   return parent.type(self,type,tensorCache)
end

function SpatialConvolutionLocal:__tostring__()
   local s = string.format('%s(%d -> %d, %dx%d, %dx%d', torch.type(self),
         self.nInputPlane, self.nOutputPlane, self.iW, self.iH, self.kW, self.kH)
   if self.dW ~= 1 or self.dH ~= 1 or self.padW ~= 0 or self.padH ~= 0 then
     s = s .. string.format(', %d,%d', self.dW, self.dH)
   end
   if (self.padW or self.padH) and (self.padW ~= 0 or self.padH ~= 0) then
     s = s .. ', ' .. self.padW .. ',' .. self.padH
   end
   return s .. ')'
end

function SpatialConvolutionLocal:clearState()
   nn.utils.clear(self, 'finput', 'fgradInput', '_input', '_gradOutput')
   return parent.clearState(self)
end
