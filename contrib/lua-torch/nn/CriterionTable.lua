local CriterionTable, parent = torch.class('nn.CriterionTable', 'nn.Module')

function CriterionTable:__init(criterion)
   parent.__init(self)
   self.criterion = criterion
   self.gradInput = {criterion.gradInput}
end

function CriterionTable:updateOutput(input)
   self.output = self.criterion:updateOutput(table.unpack(input))
   return self.output
end

function CriterionTable:updateGradInput(input, gradOutput)
  self.criterion:updateGradInput(table.unpack(input))
  return self.gradInput
end
