local GatedLinearUnit, parent = torch.class('nn.GatedLinearUnit', 'nn.Module')

function GatedLinearUnit:__init(dim)
   parent.__init(self)
   self.dim = dim
end

function GatedLinearUnit:updateOutput(input)
   local dim = self.dim or input:dim()
   input.THNN.GatedLinear_updateOutput(
      input:cdata(),
      self.output:cdata(),
      dim
   )
   return self.output
end

function GatedLinearUnit:updateGradInput(input, gradOutput)
   local dim = self.dim or input:dim()
   input.THNN.GatedLinear_updateGradInput(
      input:cdata(),
      gradOutput:cdata(),
      self.gradInput:cdata(),
      dim
   )
   return self.gradInput
end
