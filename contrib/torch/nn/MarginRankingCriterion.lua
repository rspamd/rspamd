local MarginRankingCriterion, parent = torch.class('nn.MarginRankingCriterion', 'nn.Criterion')

function MarginRankingCriterion:__init(margin)
   parent.__init(self)
   margin=margin or 1
   self.margin = margin
   self.gradInput = {torch.Tensor(1), torch.Tensor(1)}
   self.sizeAverage = true
end

function MarginRankingCriterion:updateOutput(input, y)
    if torch.type(y) == 'number' then -- non-batch mode
      self.output = math.max(0, -y * (input[1][1] - input[2][1]) + self.margin)
   else
      self._output = self._output or input[1]:clone()
      self._output:resizeAs(input[1])
      self._output:copy(input[1])

      self._output:add(-1, input[2])
      self._output:mul(-1):cmul(y)
      self._output:add(self.margin)

      self._output:cmax(0)

      self.output = self._output:sum()

      if self.sizeAverage then
         self.output = self.output/y:size(1)
      end
   end

   return self.output
end

function MarginRankingCriterion:updateGradInput(input, y)
    if torch.type(y) == 'number' then -- non-batch mode
      local dist = -y * (input[1][1] - input[2][1]) + self.margin
      if dist < 0 then
         self.gradInput[1][1] = 0;
         self.gradInput[2][1] = 0;
      else
         self.gradInput[1][1] = -y
         self.gradInput[2][1] = y
      end
   else
      self.dist = self.dist or input[1].new()
      self.dist = self.dist:resizeAs(input[1]):copy(input[1])
      local dist = self.dist

      dist:add(-1, input[2])
      dist:mul(-1):cmul(y)
      dist:add(self.margin)

      self.mask = self.mask or input[1].new()
      self.mask = self.mask:resizeAs(input[1]):copy(dist)
      local mask = self.mask

      mask:ge(dist, 0)

      self.gradInput[1]:resize(dist:size())
      self.gradInput[2]:resize(dist:size())

      self.gradInput[1]:copy(mask)
      self.gradInput[1]:mul(-1):cmul(y)
      self.gradInput[2]:copy(mask)
      self.gradInput[2]:cmul(y)

      if self.sizeAverage then
         self.gradInput[1]:div(y:size(1))
         self.gradInput[2]:div(y:size(1))
      end

   end
   return self.gradInput
end
