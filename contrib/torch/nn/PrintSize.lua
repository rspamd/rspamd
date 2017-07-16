local PrintSize, parent = torch.class('nn.PrintSize', 'nn.Module')

function PrintSize:__init(prefix)
   parent.__init(self)
   self.prefix = prefix or "PrintSize"
end

function PrintSize:updateOutput(input)
   self.output = input
   local size
   if torch.type(input) == 'table' then
      size = input
   elseif torch.type(input) == 'nil' then
      size = 'missing size'
   else
      size = input:size()
   end
   print(self.prefix..":input\n", size)
   return self.output
end


function PrintSize:updateGradInput(input, gradOutput)
   local size
   if torch.type(gradOutput) == 'table' then
      size = gradOutput
   elseif torch.type(gradOutput) == 'nil' then
      size = 'missing size'
   else
      size = gradOutput:size()
   end
   print(self.prefix..":gradOutput\n", size)
   self.gradInput = gradOutput
   return self.gradInput
end

