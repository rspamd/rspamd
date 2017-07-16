local SoftSign, parent = torch.class('nn.SoftSign', 'nn.Module')

function SoftSign:updateOutput(input)
   self.temp = self.temp or input.new()
   self.temp:resizeAs(input):copy(input):abs():add(1)
   self.output:resizeAs(input):copy(input):cdiv(self.temp)
   return self.output
end

function SoftSign:updateGradInput(input, gradOutput)
   self.tempgrad = self.tempgrad or input.new()
   self.tempgrad:resizeAs(self.output):copy(input):abs():add(1):cmul(self.tempgrad)
   self.gradInput:resizeAs(input):copy(gradOutput):cdiv(self.tempgrad)
   return self.gradInput
end

function SoftSign:clearState()
   nn.utils.clear(self, 'temp', 'tempgrad')
   return parent.clearState(self)
end
