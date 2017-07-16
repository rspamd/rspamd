local ZeroGrad, parent = torch.class('nn.ZeroGrad', 'nn.Module')

function ZeroGrad:updateOutput(input)
   self.output:set(input)
   return self.output
end

-- the gradient is simply zeroed.
-- useful when you don't want to backpropgate through certain paths.
function ZeroGrad:updateGradInput(input, gradOutput)
   self.gradInput = nn.utils.recursiveResizeAs(self.gradInput, input)
   self.gradInput = nn.utils.recursiveFill(self.gradInput, 0)
   return self.gradInput
end
