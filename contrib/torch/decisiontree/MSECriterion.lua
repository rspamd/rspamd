local dt = require "decisiontree._env"

function nn.MSECriterion.updateHessianInput(self, input, target)
   self.hessInput = self.hessInput or input.new()
   self.hessInput:resize(input:size()):fill(2)
   return self.hessInput
end

-- returns gradInput and hessInput
function nn.MSECriterion.backward2(self, input, target)
   return self:updateGradInput(input, target), self:updateHessInput(input, target)
end

