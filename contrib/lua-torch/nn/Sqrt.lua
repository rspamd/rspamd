local Sqrt, parent = torch.class('nn.Sqrt','nn.Module')

function Sqrt:__init(b)
   parent.__init(self)
   self.eps = b or 0
end

function Sqrt:updateOutput(input)
   self.eps = self.eps or 0
   input.THNN.Sqrt_updateOutput(
      input:cdata(),
      self.output:cdata(),
      self.eps
   )
   return self.output
end

function Sqrt:updateGradInput(input, gradOutput)
   input.THNN.Sqrt_updateGradInput(
      input:cdata(),
      gradOutput:cdata(),
      self.gradInput:cdata(),
      self.output:cdata()
   )
   return self.gradInput
end
