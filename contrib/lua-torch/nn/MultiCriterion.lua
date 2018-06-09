local MultiCriterion, parent = torch.class('nn.MultiCriterion', 'nn.Criterion')

function MultiCriterion:__init()
   parent.__init(self)
   self.criterions = {}
   self.weights = torch.DoubleStorage()
end

function MultiCriterion:add(criterion, weight)
   assert(criterion, 'no criterion provided')
   weight = weight or 1
   table.insert(self.criterions, criterion)
   self.weights:resize(#self.criterions, true)
   self.weights[#self.criterions] = weight
   return self
end

function MultiCriterion:updateOutput(input, target)
   self.output = 0
   for i=1,#self.criterions do
      self.output = self.output + self.weights[i]*self.criterions[i]:updateOutput(input, target)
   end
   return self.output
end

function MultiCriterion:updateGradInput(input, target)
   self.gradInput = nn.utils.recursiveResizeAs(self.gradInput, input)
   nn.utils.recursiveFill(self.gradInput, 0)
   for i=1,#self.criterions do
      nn.utils.recursiveAdd(self.gradInput, self.weights[i], self.criterions[i]:updateGradInput(input, target))
   end
   return self.gradInput
end

function MultiCriterion:type(type)
   for i,criterion in ipairs(self.criterions) do
      criterion:type(type)
   end
   return parent.type(self, type)
end
