local THNN = require 'nn.THNN'
local SpatialFullConvolution, parent = torch.class('nn.SpatialFullConvolution','nn.Module')

function SpatialFullConvolution:__init(nInputPlane, nOutputPlane,
                                       kW, kH, dW, dH, padW, padH, adjW, adjH)
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
   self.padH = padH or 0
   self.adjW = adjW or 0
   self.adjH = adjH or 0

   if self.adjW > self.dW - 1 or self.adjH > self.dH - 1 then
      error('adjW and adjH must be smaller than self.dW - 1' ..
            ' and self.dH - 1 respectively')
   end

   self.weight = torch.Tensor(nInputPlane, nOutputPlane, kH, kW)
   self.gradWeight = torch.Tensor(nInputPlane, nOutputPlane, kH, kW)
   self.bias = torch.Tensor(self.nOutputPlane)
   self.gradBias = torch.Tensor(self.nOutputPlane)

   self.ones = torch.Tensor()

   self:reset()
end

function SpatialFullConvolution:noBias()
	self.bias = nil
	self.gradBias = nil
	return self
end

function SpatialFullConvolution:reset(stdv)
   if stdv then
      stdv = stdv * math.sqrt(3)
   else
      local nInputPlane = self.nInputPlane
      local kH = self.kH
      local kW = self.kW
      stdv = 1/math.sqrt(kW*kH*nInputPlane)
   end
   self.weight:uniform(-stdv, stdv)
   if self.bias then
      self.bias:uniform(-stdv, stdv)
   end
end

local function calculateAdj(targetSize, ker, pad, stride)
  return (targetSize + 2 * pad - ker) % stride
end

function SpatialFullConvolution:backCompatibility()
  self.adjW = self.adjW or 0
  self.adjH = self.adjH or 0
end

function SpatialFullConvolution:updateOutput(input)
  self:backCompatibility()

  local inputTensor = input
  local adjW, adjH = self.adjW, self.adjH

  -- The input can be a table where the second element indicates the target
  -- output size, in which case the adj factors are computed automatically
  if type(inputTensor) == 'table' then
    inputTensor = input[1]
    local targetTensor = input[2]
    local tDims = targetTensor:dim()
    local tH = targetTensor:size(tDims-1)
    local tW = targetTensor:size(tDims)
    adjW = calculateAdj(tW, self.kW, self.padW, self.dW)
    adjH = calculateAdj(tH, self.kH, self.padH, self.dH)
    self.finput = self.finput or input[1].new()
    self.fgradInput = self.fgradInput or input[1].new()
  else
    self.finput = self.finput or input.new()
    self.fgradInput = self.fgradInput or input.new()
  end

  inputTensor.THNN.SpatialFullConvolution_updateOutput(
    inputTensor:cdata(),
    self.output:cdata(),
    self.weight:cdata(),
    THNN.optionalTensor(self.bias),
    self.finput:cdata(),
    self.fgradInput:cdata(),
    self.kW, self.kH,
    self.dW, self.dH,
    self.padW, self.padH,
    adjW, adjH
  )

  return self.output
end

function SpatialFullConvolution:updateGradInput(input, gradOutput)
  self:backCompatibility()

  if self.gradInput then

    local inputTensor = input
    local adjW, adjH = self.adjW, self.adjH

    -- The input can be a table where the second element indicates the target
    -- output size, in which case the adj factors are computed automatically
    if type(inputTensor) == 'table' then
      inputTensor = input[1]
      local targetTensor = input[2]
      local tDims = targetTensor:dim()
      local tH = targetTensor:size(tDims-1)
      local tW = targetTensor:size(tDims)
      adjW = calculateAdj(tW, self.kW, self.padW, self.dW)
      adjH = calculateAdj(tH, self.kH, self.padH, self.dH)
      -- Momentarily extract the gradInput tensor
      if type(self.gradInput) == 'table' then
        self.gradInput = self.gradInput[1] or inputTensor.new()
      end
    end

    inputTensor.THNN.SpatialFullConvolution_updateGradInput(
      inputTensor:cdata(),
      gradOutput:cdata(),
      self.gradInput:cdata(),
      self.weight:cdata(),
      self.finput:cdata(),
      self.kW, self.kH,
      self.dW, self.dH,
      self.padW, self.padH,
      adjW, adjH
    )

    if type(input) == 'table' then
     -- Create a zero tensor to be expanded and used as gradInput[2].
      self.zeroScalar = self.zeroScalar or input[2].new(1):zero()
      self.ones:resize(input[2]:dim()):fill(1)
      local zeroTensor =  self.zeroScalar
          :view(table.unpack(self.ones:totable()))
          :expandAs(input[2])
      self.gradInput = {self.gradInput, zeroTensor}
    end

    return self.gradInput
  end
end

function SpatialFullConvolution:accGradParameters(input, gradOutput, scale)
  scale = scale or 1
  self:backCompatibility()

  local inputTensor = input
  local adjW, adjH = self.adjW, self.adjH

  -- The input can be a table where the second element indicates the target
  -- output size, in which case the adj factors are computed automatically
  if type(inputTensor) == 'table' then
    inputTensor = input[1]
    local targetTensor = input[2]
    local tDims = targetTensor:dim()
    local tH = targetTensor:size(tDims-1)
    local tW = targetTensor:size(tDims)
    adjW = calculateAdj(tW, self.kW, self.padW, self.dW)
    adjH = calculateAdj(tH, self.kH, self.padH, self.dH)
  end

  inputTensor.THNN.SpatialFullConvolution_accGradParameters(
    inputTensor:cdata(),
    gradOutput:cdata(),
    self.gradWeight:cdata(),
    THNN.optionalTensor(self.gradBias),
    self.finput:cdata(),
    self.fgradInput:cdata(),
    self.kW, self.kH,
    self.dW, self.dH,
    self.padW, self.padH,
    adjW, adjH,
    scale
  )
end

function SpatialFullConvolution:type(type, tensorCache)
  self.finput = self.finput and torch.Tensor()
  self.fgradInput = self.fgradInput and torch.Tensor()
  return parent.type(self, type, tensorCache)
end

function SpatialFullConvolution:__tostring__()
  local s = string.format('%s(%d -> %d, %dx%d', torch.type(self),
  self.nInputPlane, self.nOutputPlane, self.kW, self.kH)
  if self.dW ~= 1 or self.dH ~= 1 or self.padW ~= 0 or self.padH ~= 0 then
    s = s .. string.format(', %d,%d', self.dW, self.dH)
  end
  if (self.padW or self.padH) and (self.padW ~= 0 or self.padH ~= 0) then
    s = s .. ', ' .. self.padW .. ',' .. self.padH
  end
  if (self.adjW or self.adjH) and (self.adjW ~= 0 or self.adjH ~= 0) then
    s = s .. ', ' .. self.adjW .. ',' .. self.adjH
  end
  if self.bias then
     return s .. ')'
  else
     return s .. ') without bias'
 end
end

function SpatialFullConvolution:clearState()
   nn.utils.clear(self, 'finput', 'fgradInput', '_input', '_gradOutput')
   return parent.clearState(self)
end

