
local CDivTable, parent = torch.class('nn.CDivTable', 'nn.Module')

function CDivTable:__init()
   parent.__init(self)
   self.gradInput = {}
end

function CDivTable:updateOutput(input)
   self.output:resizeAs(input[1]):copy(input[1])
   self.output:cdiv(input[2])
   return self.output
end

function CDivTable:updateGradInput(input, gradOutput)
   self.gradInput[1] = self.gradInput[1] or input[1].new()
   self.gradInput[2] = self.gradInput[2] or input[1].new()
   self.gradInput[1]:resizeAs(input[1]):copy(gradOutput):cdiv(input[2])
   self.gradInput[2]:resizeAs(input[2]):zero():addcdiv(-1,self.gradInput[1],input[2]):cmul(input[1])

   for i=#input+1, #self.gradInput do
       self.gradInput[i] = nil
   end

   return self.gradInput
end
