local CAddTable, parent = torch.class('nn.CAddTable', 'nn.Module')

function CAddTable:__init(ip)
   parent.__init(self)
   self.inplace = ip
   self.gradInput = {}
end

function CAddTable:updateOutput(input)
   if self.inplace then
      self.output:set(input[1])
   else
      self.output:resizeAs(input[1]):copy(input[1])
   end
   for i=2,#input do
      self.output:add(input[i])
   end
   return self.output
end

function CAddTable:updateGradInput(input, gradOutput)
   for i=1,#input do
      self.gradInput[i] = self.gradInput[i] or input[1].new()
      if self.inplace then
         self.gradInput[i]:set(gradOutput)
      else
         self.gradInput[i]:resizeAs(input[i]):copy(gradOutput)
      end
   end

   for i=#input+1, #self.gradInput do
       self.gradInput[i] = nil
   end

   return self.gradInput
end
