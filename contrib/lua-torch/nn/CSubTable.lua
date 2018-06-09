
local CSubTable, parent = torch.class('nn.CSubTable', 'nn.Module')

function CSubTable:__init()
   parent.__init(self)
   self.gradInput = {}
end

function CSubTable:updateOutput(input)
   self.output:resizeAs(input[1]):copy(input[1])
   self.output:add(-1,input[2])
   return self.output
end

function CSubTable:updateGradInput(input, gradOutput)
   self.gradInput[1] = self.gradInput[1] or input[1].new()
   self.gradInput[2] = self.gradInput[2] or input[1].new()
   self.gradInput[1]:resizeAs(input[1]):copy(gradOutput)
   self.gradInput[2]:resizeAs(input[2]):copy(gradOutput):mul(-1)

   for i=#input+1, #self.gradInput do
       self.gradInput[i] = nil
   end

   return self.gradInput
end
