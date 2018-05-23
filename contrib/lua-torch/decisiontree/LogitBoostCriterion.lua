local dt = require "decisiontree._env"

-- Ref: slide 17 in https://homes.cs.washington.edu/~tqchen/pdf/BoostedTree.pdf

-- equivalent to nn.Sigmoid() + nn.BCECriterion()
local LogitBoostCriterion, parent = torch.class("nn.LogitBoostCriterion", "nn.Criterion")

function LogitBoostCriterion:__init(sizeAverage)
   parent.__init(self)
   self.sizeAverage = sizeAverage
   self.hessInput = self.gradInput.new()
   self._output = torch.Tensor()
end

function LogitBoostCriterion:updateOutput(input, target)
   input.nn.LogitBoostCriterion_updateOutput(input, target, self._output, self.sizeAverage)
   self.output = self._output[1]
   return self.output
end

function LogitBoostCriterion:updateGradInput(input, target)
   input.nn.LogitBoostCriterion_updateGradInput(input, target, self.gradInput)
   return self.gradInput
end

function LogitBoostCriterion:updateHessInput(input, target)
   input.nn.LogitBoostCriterion_updateHessInput(input, target, self.hessInput)
   return self.hessInput
end

-- returns gradInput and hessInput
function LogitBoostCriterion:backward2(input, target)
   return self:updateGradInput(input, target), self:updateHessInput(input, target)
end

local gradWrapper = function(input, target, grad)
   input.nn.LogitBoostCriterion_updateGradInput(input, target, grad)
end
local hessianWrapper = function(input, target, hessian)
   input.nn.LogitBoostCriterion_updateHessInput(input, target, hessian)
end

function LogitBoostCriterion:getWrappers()
   return gradWrapper, hessianWrapper
end
