local WeightedMSECriterion, parent = torch.class('nn.WeightedMSECriterion','nn.MSECriterion')

function WeightedMSECriterion:__init(w)
   parent.__init(self)
   self.weight = w:clone()
end

function WeightedMSECriterion:updateOutput(input,target)
   self.buffer = self.buffer or input.new()
   self.buffer:resizeAs(input):copy(target)
   if input:dim() - 1 == self.weight:dim() then
      for i=1,input:size(1) do
         self.buffer[i]:cmul(self.weight)
      end
   else
      self.buffer:cmul(self.weight)
   end
   self.output_tensor = self.output_tensor or input.new(1)
   input.THNN.MSECriterion_updateOutput(
      input:cdata(),
      self.buffer:cdata(),
      self.output_tensor:cdata(),
      self.sizeAverage
   )
   self.output = self.output_tensor[1]
   return self.output
end

function WeightedMSECriterion:updateGradInput(input, target)
   self.buffer:resizeAs(input):copy(target)
   if input:dim() - 1 == self.weight:dim() then
      for i=1,input:size(1) do
         self.buffer[i]:cmul(self.weight)
      end
   else
      self.buffer:cmul(self.weight)
   end
   input.THNN.MSECriterion_updateGradInput(
      input:cdata(),
      self.buffer:cdata(),
      self.gradInput:cdata(),
      self.sizeAverage
   )
   return self.gradInput
end
