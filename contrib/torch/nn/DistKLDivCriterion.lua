local DistKLDivCriterion, parent = torch.class('nn.DistKLDivCriterion', 'nn.Criterion')

function DistKLDivCriterion:__init()
   parent.__init(self)
   self.sizeAverage = true
end

function DistKLDivCriterion:updateOutput(input, target)
   assert(input:dim() == target:dim() and
      torch.LongTensor(input:size()):eq(torch.LongTensor(target:size())):all(),
      'input and target should have the same size')
   self.output_tensor = self.output_tensor or input.new(1)
   input.THNN.DistKLDivCriterion_updateOutput(
      input:cdata(),
      target:cdata(),
      self.output_tensor:cdata(),
      self.sizeAverage
   )
   self.output = self.output_tensor[1]
   return self.output
end

function DistKLDivCriterion:updateGradInput(input, target)
   assert(input:dim() == target:dim() and
      torch.LongTensor(input:size()):eq(torch.LongTensor(target:size())):all(),
      'input and target should have the same size')
   input.THNN.DistKLDivCriterion_updateGradInput(
      input:cdata(),
      target:cdata(),
      self.gradInput:cdata(),
      self.sizeAverage
   )
   return self.gradInput
end
