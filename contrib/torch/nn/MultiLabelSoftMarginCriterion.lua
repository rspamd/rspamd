--[[
-- A MultiLabel multiclass criterion based on sigmoid:
--
-- the loss is:
-- l(x,y) = - sum_i y[i] * log(p[i]) + (1 - y[i]) * log (1 - p[i])
-- where p[i] = exp(x[i]) / (1 + exp(x[i]))
--
-- and with weights:
-- l(x,y) = - sum_i weights[i] (y[i] * log(p[i]) + (1 - y[i]) * log (1 - p[i]))
--
-- This uses the stable form of the loss and gradients.
--]]


local MultiLabelSoftMarginCriterion, parent = torch.class('nn.MultiLabelSoftMarginCriterion', 'nn.Criterion')


function MultiLabelSoftMarginCriterion:__init(weights, sizeAverage)
   parent.__init(self)
   if sizeAverage ~= nil then
      self.sizeAverage = sizeAverage
   else
      self.sizeAverage = true
   end
   if weights ~= nil then
      assert(weights:dim() == 1, "weights input should be 1-D Tensor")
      self.weights = weights
   end
   self.sigmoid = nn.Sigmoid()
end

function MultiLabelSoftMarginCriterion:updateOutput(input, target)
   local weights = self.weights
   if weights ~= nil and target:dim() ~= 1 then
      weights = self.weights:view(1, target:size(2)):expandAs(target)
   end

   local x = input:view(input:nElement())
   local t = target:view(target:nElement())

   self.sigmoid:updateOutput(x)

   self._buffer1 = self._buffer1 or input.new()
   self._buffer2 = self._buffer2 or input.new()

   self._buffer1:ge(x, 0) -- indicator

   -- log(1 + exp(x - cmul(x, indicator):mul(2)))
   self._buffer2:cmul(x, self._buffer1):mul(-2):add(x):exp():add(1):log()
   -- cmul(x, t - indicator)
   self._buffer1:mul(-1):add(t):cmul(x)
   -- log(1 + exp(x - cmul(x, indicator):mul(2))) - cmul(x, t - indicator)
   self._buffer2:add(-1, self._buffer1)

   if weights ~= nil then
      self._buffer2:cmul(weights)
   end

   self.output = self._buffer2:sum()

   if self.sizeAverage then
      self.output = self.output / input:nElement()
   end

   return self.output
end

function MultiLabelSoftMarginCriterion:updateGradInput(input, target)
   local weights = self.weights
   if weights ~= nil and target:dim() ~= 1 then
      weights = self.weights:view(1, target:size(2)):expandAs(target)
   end

   self.gradInput:resizeAs(input):copy(self.sigmoid.output)
   self.gradInput:add(-1, target)

   if weights ~= nil then
      self.gradInput:cmul(weights)
   end

   if self.sizeAverage then
      self.gradInput:div(target:nElement())
   end

   return self.gradInput
end
