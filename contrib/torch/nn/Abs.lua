local Abs, parent = torch.class('nn.Abs', 'nn.Module')

function Abs:__init()
   parent.__init(self)
end

function Abs:updateOutput(input)
   input.THNN.Abs_updateOutput(
      input:cdata(),
      self.output:cdata()
   )
   return self.output
end

function Abs:updateGradInput(input, gradOutput)
   input.THNN.Abs_updateGradInput(
      input:cdata(),
      gradOutput:cdata(),
      self.gradInput:cdata()
   )
   return self.gradInput
end
