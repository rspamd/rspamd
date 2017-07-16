--[[
   Probabilistic Criterion for Triplet Siamese Model for learning embedding.
   Ref: https://arxiv.org/pdf/1610.00243.pdf

   loss = -log( exp(-X) / ( exp(-X) + exp(-Y) ) )
   where
   X : Distance between similar samples
   Y : Distance between dissimilar samples

   The loss could be break down to following log expansion

   loss = -log( exp(-X) ) - (-log( exp(-X) + exp(-Y) ))
        = -log( exp(-X) ) + log( exp(-X) + exp(-Y) )
        = -(-X) + log( exp(-X) + exp(-Y) )
        = X + log( exp(-X) + exp(-Y) )

   Gradients:
      dLoss/dX = 1 + 1 / (exp(-X) + exp(-Y)) * -1 * exp(-X)
               = 1 - exp(-X) / (exp(-X) + exp(-Y))

      dLoss/dY = 0 + 1 / (exp(-X) + exp(-Y)) * -1 * exp(-Y)
               = -exp(-Y) / (exp(-X) + exp(-Y))

--]]

local DistanceRatioCriterion, parent = torch.class('nn.DistanceRatioCriterion',
                                                   'nn.Criterion')

function DistanceRatioCriterion:__init(sizeAverage)
   parent.__init(self)
   if sizeAverage ~= nil then
     self.sizeAverage = sizeAverage
   else
     self.sizeAverage = true
   end
end

-- Forward
--[[
-- X : Distance between similar samples
-- Y : Distance between dissimilar samples
   loss = -log( exp(-X) ) - (-log( exp(-X) + exp(-Y) ))
        = -log( exp(-X) ) + log( exp(-X) + exp(-Y) )
        = -(-X) + log( exp(-X) + exp(-Y) )
        = X + log( exp(-X) + exp(-Y) )
--]]
function DistanceRatioCriterion:updateOutput(input)
   assert(#input == 2, "Invalid number of inputs")

   local X = input[1]
   local Y = input[2]

   assert(X:nElement() == Y:nElement(), "Number of distances don't match.")
   assert(X:size(1) == Y:size(1), "Invalid distances' size.")

   -- Compute exp(-X) and exp(-Y)
   self._expMinusX = self._expMinusX or X.new()
   self._expMinusY = self._expMinusY or Y.new()

   -- Compute ( exp(-X) + exp(-Y) )
   self._expMinusX:resizeAs(X):copy(X):mul(-1):exp()
   self._expMinusY:resizeAs(Y):copy(Y):mul(-1):exp()

   self._sumExpMinusXY = self.sumExpMinusExp or X.new()
   self._sumExpMinusXY:resizeAs(self._expMinusX):copy(self._expMinusX)
                     :add(self._expMinusY)

   -- Compute log( exp(-X) + exp(-Y) )
   self._logSumExpMinusXY = self._logSumExpMinusXY or self._sumExpMinusXY.new()
   self._logSumExpMinusXY:resizeAs(self._sumExpMinusXY)
                         :copy(self._sumExpMinusXY):log()

   -- Compute log( exp(-X) + exp(-Y) )
   self.loss = self.loss or self._logSumExpMinusXY.new()
   self.loss:resizeAs(X):copy(X):add(self._logSumExpMinusXY)

   if self.sizeAverage then
      return self.loss:sum()/X:size(1)
   else
      return self.loss:sum()
   end
end

-- Backward
--[[
-- X : Distance between similar samples
-- Y : Distance between dissimilar samples

   Gradients:
      dLoss/dX = 1 + 1 / (exp(-X) + exp(-Y)) * -1 * exp(-X)
               = 1 - exp(-X) / (exp(-X) + exp(-Y))

      dLoss/dY = 0 + 1 / (exp(-X) + exp(-Y)) * -1 * exp(-Y)
               = -exp(-Y) / (exp(-X) + exp(-Y))

--]]
function DistanceRatioCriterion:updateGradInput(input)
   assert(#input == 2, "Invalid number of inputs")
   local X = input[1]
   local Y = input[2]
   assert(X:nElement() == Y:nElement(), "Number of distances don't match.")
   assert(X:size(1) == Y:size(1), "Invalid distances' size.")

   -- dLoss/dX
   -- -exp(-X)
   self.dX = self.dX or X.new()
   self.dX:resizeAs(self._expMinusX):copy(self._expMinusX):mul(-1)

   -- -exp(-X) / (exp(-X) + exp(-Y))
   self.dX:cdiv(self._sumExpMinusXY)

   -- 1 - exp(-X) / (exp(-X) + exp(-Y))
   self.dX:add(1)

   -- dLoss/dY
   -- -exp(-Y)
   self.dY = self.dY or Y.new()
   self.dY:resizeAs(self._expMinusY):copy(self._expMinusY):mul(-1)

   -- -exp(-Y) / (exp(-X) + exp(-Y))
   self.dY:cdiv(self._sumExpMinusXY)

   if self.sizeAverage then
      self.dX:div(X:size(1))
      self.dY:div(X:size(1))
   end

   return {self.dX, self.dY}
end

function DistanceRatioCriterion:type(type, tensorCache)
   if type then
      self._expMinusX = nil
      self._expMinusY = nil
      self._sumExpMinusXY = nil
      self._logSumExpMinusXY = nil
      self.loss = nil
      self.dX = nil
      self.dY = nil
   end
   return parent.type(self, type, tensorCache)
end
