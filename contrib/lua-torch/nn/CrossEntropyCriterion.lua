local CrossEntropyCriterion, Criterion = torch.class('nn.CrossEntropyCriterion', 'nn.Criterion')

function CrossEntropyCriterion:__init(weights, sizeAverage)
   Criterion.__init(self)
   self.lsm = nn.LogSoftMax()
   self.nll = nn.ClassNLLCriterion(weights, sizeAverage)
   self.sizeAverage = self.nll.sizeAverage
   self.oldSizeAverage = self.sizeAverage
end

function CrossEntropyCriterion:updateOutput(input, target)
   input = input:squeeze()
   target = type(target) == 'number' and target or target:squeeze()
   -- only propagate if value has changed to preserve old behavior
   -- of setting nll.sizeAverage directly
   if self.sizeAverage ~= self.oldSizeAverage then
      self.nll.sizeAverage = self.sizeAverage
   end
   self.lsm:updateOutput(input)
   self.nll:updateOutput(self.lsm.output, target)
   self.output = self.nll.output
   self.oldSizeAverage = self.sizeAverage
   return self.output
end

function CrossEntropyCriterion:updateGradInput(input, target)
   local size = input:size()
   input = input:squeeze()
   target = type(target) == 'number' and target or target:squeeze()
   -- only propagate if  value has changed to preserve old behavior
   -- of setting nll.sizeAverage directly
   if self.sizeAverage ~= self.oldSizeAverage then
      self.nll.sizeAverage = self.sizeAverage
   end
   self.nll:updateGradInput(self.lsm.output, target)
   self.lsm:updateGradInput(input, self.nll.gradInput)
   self.gradInput:view(self.lsm.gradInput, size)
   self.oldSizeAverage = self.sizeAverage
   return self.gradInput
end

return nn.CrossEntropyCriterion
