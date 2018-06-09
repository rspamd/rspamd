local NarrowTable, parent = torch.class('nn.NarrowTable', 'nn.Module')

function NarrowTable:__init(offset, length)
   parent.__init(self)
   self.offset = offset
   self.length = length or 1
   if not offset then
      error('nn.NarrowTable(offset, length)')
   end

   self.output = {}
   self.gradInput = {}
end

function NarrowTable:updateOutput(input)
   for k,v in ipairs(self.output) do self.output[k] = nil end
   for i=1,self.length do
      self.output[i] = input[self.offset+i-1]
   end
   return self.output
end

function NarrowTable:updateGradInput(input, gradOutput)
   for i=1,#gradOutput do
      self.gradInput[self.offset+i-1] = gradOutput[i]
   end
   for i=1,#input do
      if (i < self.offset) or (i >= self.offset + self.length) then
         self.gradInput[i] = nn.utils.recursiveResizeAs(self.gradInput[i], input[i])
         nn.utils.recursiveFill(self.gradInput[i], 0)
      end
   end
   for i=#input+1,#self.gradInput do self.gradInput[i] = nil end
   return self.gradInput
end

function NarrowTable:type(type, tensorCache)
   self.output = {}
   self.gradInput = {}
   return parent.type(self, type, tensorCache)
end

NarrowTable.clearState = nn.Identity.clearState
