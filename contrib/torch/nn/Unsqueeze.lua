local Unsqueeze, parent = torch.class('nn.Unsqueeze', 'nn.Module')

local function _assertTensor(t)
   assert(torch.isTensor(t), "This module only works on tensor")
end

function Unsqueeze:__init(pos, numInputDims)
   parent.__init(self)
   self.pos = pos or error('the position to insert singleton dim not specified')
   self:setNumInputDims(numInputDims)
end

function Unsqueeze:setNumInputDims(numInputDims)
   self.numInputDims = numInputDims
   return self
end

function Unsqueeze:updateOutput(input)
   _assertTensor(input)
   local actualPos = self:_getActualPosition(input)
   nn.utils.addSingletonDimension(self.output, input, actualPos)
   return self.output
end

function Unsqueeze:updateGradInput(input, gradOutput)
   _assertTensor(input)
   _assertTensor(gradOutput)
   assert(input:nElement() == gradOutput:nElement())

   self.gradInput:view(gradOutput, input:size())
   return self.gradInput
end

function Unsqueeze:__tostring__()
   return torch.type(self)..'(dim ' .. self.pos .. ')'
end

function Unsqueeze:_getActualPosition(input)
   -- get valid dimesion offset for batchMode (if any)
   local inputDim = input:dim() -- data batch dim
   self.numInputDims = self.numInputDims or inputDim -- feature map dim
   local offsetDim = inputDim - self.numInputDims
   assert(offsetDim >= 0, "input feature map dim (numInputDims) must be <= input:dim()")

   -- the actual position; clearer error message for batchMode (if any)
   local actualPos = self.pos + offsetDim
   assert(actualPos >= 1 and actualPos <= (inputDim + 1),
      ("Invalid position: %d. input:dim() is %d, input feature map dim (numInputDims) is %d.")
      :format(self.pos, inputDim, self.numInputDims)
   )
   return actualPos
end
