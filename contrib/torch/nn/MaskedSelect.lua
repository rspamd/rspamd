local unpack = unpack or table.unpack

local MaskedSelect, parent = torch.class('nn.MaskedSelect', 'nn.Module')

--[[ Sets the provided mask value for the module. ]]
function MaskedSelect:__init()
  parent.__init(self)
  self._maskIndices = torch.LongTensor()
  self._maskIndexBuffer = torch.LongTensor()
  self._maskIndexBufferCPU = torch.FloatTensor()
  self._gradBuffer = torch.Tensor()
  self._gradMask = torch.ByteTensor()
end

--[[ Performs maskedSelect operation. ]]
function MaskedSelect:updateOutput(input)
  local input, mask = unpack(input)
  self.output:maskedSelect(input, mask)
  return self.output
end

--[[ Reverse maps unmasked gradOutput back to gradInput. ]]
function MaskedSelect:updateGradInput(input, gradOutput)
  local input, mask = unpack(input)
  if input:type() == 'torch.CudaTensor' then
    self._maskIndexBufferCPU:range(1, mask:nElement()):resize(mask:size())
    self._maskIndexBuffer:resize(
      self._maskIndexBufferCPU:size()):copy(self._maskIndexBufferCPU)
  else
    self._maskIndexBuffer:range(1, mask:nElement()):resize(mask:size())
  end
  self._maskIndices:maskedSelect(self._maskIndexBuffer, mask)
  self._gradBuffer:resize(input:nElement()):zero()
  self._gradBuffer:scatter(1, self._maskIndices, gradOutput)
  self._gradBuffer:resize(input:size())
  self.gradInput = {self._gradBuffer,
                    self._gradMask:resize(mask:size()):fill(0)}
  return self.gradInput
end

function MaskedSelect:type(type, tensorCache)
  if not type then
    return self._type
  end
  self._gradBuffer = self._gradBuffer:type(type)
  self.gradInput = self.gradInput:type(type)
  self.output = self.output:type(type)

  -- These casts apply when switching between cuda/non-cuda types
  if type ~= 'torch.CudaTensor' then
    self._maskIndexBuffer = self._maskIndexBuffer:long()
    self._maskIndices = self._maskIndices:long()
    self._gradMask = self._gradMask:byte()
  elseif  type == 'torch.CudaTensor' then
    self._maskIndexBuffer = self._maskIndexBuffer:cuda()
    self._maskIndices = self._maskIndices:cuda()
    self._gradMask = self._gradMask:cuda()
  end
  self._type = type
  return self
end

function MaskedSelect:clearState()
  return nn.utils.clear(self, {'output',
                               'gradInput',
                               '_maskIndexBuffer',
                               '_maskIndexBufferCPU',
                               '_maskIndices',
                               '_gradBuffer',
                               '_gradMask'})
end
