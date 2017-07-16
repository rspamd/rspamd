local Exp = torch.class('nn.Exp', 'nn.Module')

function Exp:updateOutput(input)
  return self.output:exp(input)
end

function Exp:updateGradInput(input, gradOutput)
  return self.gradInput:cmul(self.output, gradOutput)
end
