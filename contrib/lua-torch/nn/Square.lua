local Square, parent = torch.class('nn.Square', 'nn.Module')

function Square:__init(args)
   parent.__init(self)
end

function Square:updateOutput(input)
   input.THNN.Square_updateOutput(
      input:cdata(),
      self.output:cdata()
   )
   return self.output
end

function Square:updateGradInput(input, gradOutput)
   input.THNN.Square_updateGradInput(
      input:cdata(),
      gradOutput:cdata(),
      self.gradInput:cdata()
   )
   return self.gradInput
end
