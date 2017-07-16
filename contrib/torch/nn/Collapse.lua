local Collapse, parent = torch.class('nn.Collapse', 'nn.Module')

-- collapses non-batch dims
function Collapse:__init(nInputDim)
   parent.__init(self)
   self.nInputDim = nInputDim
end

function Collapse:updateOutput(input)
   if not input:isContiguous() then
      self._input = self._input or input.new()
      self._input:resize(input:size()):copy(input)
      input = self._input
   end
   if input:dim() > self.nInputDim then
      self.output:view(input,input:size(1),-1)
   else
      self.output:view(input,-1)
   end
   return self.output
end

function Collapse:updateGradInput(input, gradOutput)
   self.gradInput:view(gradOutput, input:size())
   return self.gradInput
end

function Collapse:clearState()
   self._input = nil
end
