local ZipTable, parent = torch.class('nn.ZipTable', 'nn.Module')

-- input : { {a1,a2}, {b1,b2}, {c1,c2} }
-- output : { {a1,b1,c1}, {a2,b2,c2} }
function ZipTable:__init()
   parent.__init(self)
   self.output = {}
   self.gradInput = {}
end

function ZipTable:updateOutput(inputTable)
   self.output = {}
   for i,inTable in ipairs(inputTable) do
      for j,input in ipairs(inTable) do
         local output = self.output[j] or {}
         output[i] = input
         self.output[j] = output
      end
   end
   return self.output
end

function ZipTable:updateGradInput(inputTable, gradOutputTable)
   self.gradInput = {}
   for i,gradOutTable in ipairs(gradOutputTable) do
      for j,gradOutput in ipairs(gradOutTable) do
         local gradInput = self.gradInput[j] or {}
         gradInput[i] = gradOutput
         self.gradInput[j] = gradInput
      end
   end
   return self.gradInput
end

