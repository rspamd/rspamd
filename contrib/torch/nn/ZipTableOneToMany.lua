local ZipTableOneToMany, parent = torch.class('nn.ZipTableOneToMany', 'nn.Module')

-- based on ZipTable in dpnn

-- input : { v, {a, b, c} }
-- output : { {v,a}, {v,b}, {v,c} }
function ZipTableOneToMany:__init()
   parent.__init(self)
   self.output = {}
   self.gradInput = {}
   -- make buffer to update during forward/backward
   self.gradInputEl = torch.Tensor()
end

function ZipTableOneToMany:updateOutput(input)
   assert(#input == 2, "input must be table of element and table")
   local inputEl, inputTable = input[1], input[2]
   self.output = {}
   for i,v in ipairs(inputTable) do
      self.output[i] = {inputEl, v}
   end
   return self.output
end

function ZipTableOneToMany:updateGradInput(input, gradOutput)
   assert(#input == 2, "input must be table of element and table")
   local inputEl, inputTable = input[1], input[2]
   self.gradInputEl:resizeAs(inputEl):zero()
   local gradInputTable = {}
   for i,gradV in ipairs(gradOutput) do
      self.gradInputEl:add(gradV[1])
      gradInputTable[i] = gradV[2]
   end
   self.gradInput = {self.gradInputEl, gradInputTable}
   return self.gradInput
end

