local THNN = require 'nn.THNN'
local LookupTable, parent = torch.class('nn.LookupTable', 'nn.Module')

LookupTable.__version = 4

function LookupTable:__init(nIndex, nOutput, paddingValue, maxNorm, normType)
   parent.__init(self)

   self.weight = torch.Tensor(nIndex, nOutput)
   self.gradWeight = torch.Tensor(nIndex, nOutput):zero()
   self.paddingValue = paddingValue or 0
   self.maxNorm = maxNorm or nil
   self.normType = normType or nil

   self:reset()
end

function LookupTable:backCompatibility()
   self._count = self._count or torch.IntTensor()
   self._input = self._input or torch.LongTensor()

   if not self.shouldScaleGradByFreq then
      self.shouldScaleGradByFreq = false
   end
end

function LookupTable:accUpdateOnly()
   self.gradWeight = nil
   return self
end

function LookupTable:setPadding(paddingValue)
   self.paddingValue = paddingValue
   return self
end

function LookupTable:setMaxNorm(maxNorm)
   self.maxNorm = maxNorm
   return self
end

function LookupTable:setNormType(normType)
   self.normType = normType
   return self
end

function LookupTable:scaleGradByFreq()
   self.shouldScaleGradByFreq = true
   return self
end

function LookupTable:reset(stdv)
   stdv = stdv or 1
   self.weight:normal(0, stdv)
end

function LookupTable:makeInputContiguous(input)
   -- make sure input is a contiguous torch.LongTensor
   if (not input:isContiguous()) or torch.type(input) ~= torch.type(self._input) then
      self.copiedInput = true
      self._input:resize(input:size()):copy(input)
      return self._input
   end
   self.copiedInput = false
   return input
end

function LookupTable:updateOutput(input)
   self:backCompatibility()
   self:renorm(input)
   input = self:makeInputContiguous(input)
   if input:dim() == 1 then
      self.output:index(self.weight, 1, input)
   elseif input:dim() == 2 then
      self.output:index(self.weight, 1, input:view(-1))
      self.output = self.output:view(input:size(1), input:size(2), self.weight:size(2))
   else
      error("input must be a vector or matrix")
   end
   return self.output
end

function LookupTable:updateGradInput(input, gradOutput)
   -- the input can be of any type (as in the forward it's
   -- converted anyway to LongTensor) thus, need to allocate
   -- new memory each time the user changes the input type
   if torch.type(self.gradInput) ~= torch.type(input) then
      self.gradInput = input.new()
   end
   if not self.gradInput:isSameSizeAs(input) then
      self.gradInput:resizeAs(input):zero()
   end
   return self.gradInput
end

function LookupTable:accGradParameters(input, gradOutput, scale)
   self:backCompatibility()
   input = self.copiedInput and self._input or input
   if input:dim() == 2 then
      input = input:view(-1)
   elseif input:dim() ~= 1 then
      error("input must be a vector or matrix")
   end

   self.gradWeight.THNN.LookupTable_accGradParameters(
      input:cdata(),
      gradOutput:cdata(),
      self.gradWeight:cdata(),
      self._count:cdata(),
      THNN.optionalTensor(self._sorted),
      THNN.optionalTensor(self._indices),
      self.shouldScaleGradByFreq or false,
      self.paddingValue or 0,
      scale or 1
   )
end

function LookupTable:renorm(input)
   if not self.maxNorm then
      return
   end
   -- copy input into _input, so _input is continuous.
   -- The copied _input will be modified in the C code.
   self._input:resize(input:size()):copy(input)
   local row_idx = self._input
   if row_idx:dim() == 2 then
      row_idx = row_idx:view(-1)
   elseif row_idx:dim() ~= 1 then
      error("input must be a vector or matrix")
   end
   -- "row_idx" and "weight" will be modified in the C code
   self.weight.THNN.LookupTable_renorm(
      row_idx:cdata(),
      self.weight:cdata(),
      self.maxNorm,
      self.normType or 2
   )
end

function LookupTable:type(type, tensorCache)
   parent.type(self, type, tensorCache)

   if type and type:find('torch%.Cuda.*Tensor') then
      -- CUDA uses _sorted and _indices temporary tensors
      self._sorted = torch.CudaLongTensor and torch.CudaLongTensor.new() or torch.CudaTensor.new()
      self._indices = torch.CudaLongTensor and torch.CudaLongTensor.new() or torch.CudaTensor.new()
      self._count = torch.CudaLongTensor and torch.CudaLongTensor.new() or torch.CudaTensor.new()
      self._input = torch.CudaLongTensor and torch.CudaLongTensor.new() or torch.CudaTensor.new()
   else
      -- self._count and self._input should only be converted if using Cuda
      self._count = torch.IntTensor()
      self._input = torch.LongTensor()
   end

   return self
end

function LookupTable:clearState()
   nn.utils.clear(self, '_count', '_input')
   return parent.clearState(self)
end

function LookupTable:sharedAccUpdateGradParameters(input, gradOutput, lr)
   -- we do not need to accumulate parameters when sharing:
   self:defaultAccUpdateGradParameters(input, gradOutput, lr)
end
