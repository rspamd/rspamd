local ReLU6, parent = torch.class('nn.ReLU6', 'nn.Module')

function ReLU6:__init(inplace)
   parent.__init(self)

   if inplace == nil then
      self.inplace = false
   else
      self.inplace = inplace
   end

   if (inplace and type(inplace) ~= 'boolean') then
      error('in-place flag must be boolean')
   end
end

function ReLU6:updateOutput(input)
   input.THNN.HardTanh_updateOutput(
      input:cdata(),
      self.output:cdata(),
      0, 6, self.inplace)
   return self.output
end

function ReLU6:updateGradInput(input, gradOutput)
   input.THNN.HardTanh_updateGradInput(
      input:cdata(),
      gradOutput:cdata(),
      self.gradInput:cdata(),
      0, 6, self.inplace)
   return self.gradInput
end
