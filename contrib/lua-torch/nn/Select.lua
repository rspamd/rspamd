local Select, parent = torch.class('nn.Select', 'nn.Module')

function Select:__init(dimension,index)
   parent.__init(self)
   self.dimension = dimension
   self.index = index
end

function Select:updateOutput(input)
   local dim = self.dimension < 0 and input:dim() + self.dimension + 1 or self.dimension
   local index = self.index < 0 and input:size(dim) + self.index + 1 or self.index
   local output = input:select(dim, index);
   self.output:resizeAs(output)
   return self.output:copy(output)
end

function Select:updateGradInput(input, gradOutput)
   local dim = self.dimension < 0 and input:dim() + self.dimension + 1 or self.dimension
   local index = self.index < 0 and input:size(dim) + self.index + 1 or self.index
   self.gradInput:resizeAs(input)
   self.gradInput:zero()
   self.gradInput:select(dim,index):copy(gradOutput)
   return self.gradInput
end
