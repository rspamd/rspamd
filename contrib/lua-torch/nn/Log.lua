local Log, parent = torch.class('nn.Log', 'nn.Module')

function Log:__init()
   parent.__init(self)
end

function Log:updateOutput(input)
   self.output:resizeAs(input)
   self.output:copy(input)
   self.output:log()
   return self.output
end

function Log:updateGradInput(input, gradOutput)
   self.gradInput:resizeAs(input)
   self.gradInput:fill(1)
   self.gradInput:cdiv(input)
   self.gradInput:cmul(gradOutput)
   return self.gradInput
end
