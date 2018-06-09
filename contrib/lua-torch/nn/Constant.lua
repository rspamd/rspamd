------------------------------------------------------------------------
--[[ Constant ]]--
-- Outputs a constant value given an input.
-- If nInputDim is specified, uses the input to determine the size of
-- the batch. The value is then replicated over the batch.
-- You can use this with nn.ConcatTable() to append constant inputs to
-- an input : nn.ConcatTable():add(nn.Constant(v)):add(nn.Identity()) .
------------------------------------------------------------------------
local Constant, parent = torch.class("nn.Constant", "nn.Module")

function Constant:__init(value, nInputDim)
   self.value = value
   if torch.type(self.value) == 'number' then
      self.value = torch.Tensor{self.value}
   end
   assert(torch.isTensor(self.value), "Expecting number or tensor at arg 1")
   self.nInputDim = nInputDim
   parent.__init(self)
end

function Constant:updateOutput(input)
   if self.nInputDim and input:dim() > self.nInputDim then
      local vsize = self.value:size():totable()
      self.output:resize(input:size(1), table.unpack(vsize))
      local value = self.value:view(1, table.unpack(vsize))
      self.output:copy(value:expand(self.output:size()))
   else
      self.output:resize(self.value:size()):copy(self.value)
   end
   return self.output
end

function Constant:updateGradInput(input, gradOutput)
   self.gradInput:resizeAs(input):zero()
   return self.gradInput
end
