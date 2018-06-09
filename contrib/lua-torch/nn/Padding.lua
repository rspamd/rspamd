local Padding, parent = torch.class('nn.Padding', 'nn.Module')

-- pad puts in [pad] amount of [value] over dimension [dim], starting at index [index] in that dimension. If pad<0, index counts from the left.  If pad>0 index counts from the right
-- index = 1 pads before index 1.  index = 2 pads starting before index 2 and after index 1 in dimension [dim]
function Padding:__init(dim, pad, nInputDim, value, index)
   self.value = value or 0
   self.index = index or 1
   self.dim = dim
   self.pad = pad
   self.nInputDim = nInputDim
   self.outputSize = torch.LongStorage()
   parent.__init(self)
end

function Padding:updateOutput(input)
   self.outputSize:resize(input:dim())
   self.outputSize:copy(input:size())
   local dim = self.dim
   if self.nInputDim and input:dim() ~= self.nInputDim then
      dim = dim + 1
   end
   self.outputSize[dim] = self.outputSize[dim] + math.abs(self.pad)
   self.output:resize(self.outputSize)
   self.output:fill(self.value)
   local index = self.index
   local pad = self.pad
   if pad > 0 then
      index = input:size(dim) - index + 2
   else
      pad = -pad
   end
   if index == 1 then
      self.output:narrow(dim, 1 + pad, input:size(dim)):copy(input)
   elseif index == input:size(dim) + 1 then
      self.output:narrow(dim, 1, input:size(dim)):copy(input)
   else
      self.output:narrow(dim, 1, index - 1):copy(input:narrow(dim, 1, index - 1))
      self.output:narrow(dim, index + pad, input:size(dim) - (index - 1)):copy(input:narrow(dim, index, input:size(dim) - (index - 1)))
   end
   return self.output
end

function Padding:updateGradInput(input, gradOutput)
   self.gradInput:resizeAs(input)
   local dim = self.dim
   if self.nInputDim and input:dim() ~= self.nInputDim then
      dim = dim + 1
   end
   local index = self.index
   local pad = self.pad
   if pad > 0 then
      index = input:size(dim) - index + 2
   else
      pad = -pad
   end
   if index == 1 then
      self.gradInput:copy(gradOutput:narrow(dim, 1 + pad, input:size(dim)))
   elseif index == input:size(dim) + 1 then
      self.gradInput:copy(gradOutput:narrow(dim, 1, input:size(dim)))
   else
      self.gradInput:narrow(dim, 1, index - 1):copy(gradOutput:narrow(dim, 1, index - 1))
      self.gradInput:narrow(dim, index, input:size(dim) - (index - 1)):copy(gradOutput:narrow(dim, index + pad, input:size(dim) - (index - 1)))
   end
   return self.gradInput
end
