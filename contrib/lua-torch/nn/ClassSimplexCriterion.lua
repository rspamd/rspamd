local ClassSimplexCriterion, parent
    = torch.class('nn.ClassSimplexCriterion', 'nn.MSECriterion')

--[[
    This file implements a criterion for multi-class classification.
    It learns an embedding per class, where each class' embedding
    is a point on an (N-1)-dimensional simplex, where N is
    the number of classes.
    For example usage of this class, look at doc/criterion.md

    Reference: http://arxiv.org/abs/1506.08230

]]--


--[[
    function regsplex(n):
    regsplex returns the coordinates of the vertices of a
    regular simplex centered at the origin.
    The Euclidean norms of the vectors specifying the vertices are
    all equal to 1. The input n is the dimension of the vectors;
    the simplex has n+1 vertices.

    input:
    n -- dimension of the vectors specifying the vertices of the simplex

    output:
    a -- tensor dimensioned (n+1,n) whose rows are
         vectors specifying the vertices

    reference:
    http://en.wikipedia.org/wiki/Simplex#Cartesian_coordinates_for_regular_n-dimensional_simplex_in_Rn
--]]
local function regsplex(n)
    local a = torch.zeros(n+1,n)

    for k = 1,n do
        -- determine the last nonzero entry in the vector for the k-th vertex
        if k==1 then a[k][k] = 1 end
        if k>1 then a[k][k] = math.sqrt( 1 - a[{ {k},{1,k-1} }]:norm()^2 ) end

        -- fill the k-th coordinates for the vectors of the remaining vertices
        local c = (a[k][k]^2 - 1 - 1/n) / a[k][k]
        a[{ {k+1,n+1},{k} }]:fill(c)
    end

    return a
end


function ClassSimplexCriterion:__init(nClasses)
    parent.__init(self)
    assert(nClasses and nClasses > 1 and nClasses == (nClasses -(nClasses % 1)),
           "Required positive integer argument nClasses > 1")
    self.nClasses = nClasses

    -- embedding the simplex in a space of dimension strictly greater than
    -- the minimum possible (nClasses-1) is critical for effective training.
    local simp = regsplex(nClasses - 1)
    self.simplex = torch.cat(simp,
                             torch.zeros(simp:size(1), nClasses -simp:size(2)),
                             2)
    self._target = torch.Tensor(nClasses)
end

-- handle target being both 1D tensor, and
-- target being 2D tensor (2D tensor means don't do anything)
local function transformTarget(self, target)
    if torch.type(target) == 'number' then
        self._target:resize(self.nClasses)
        self._target:copy(self.simplex[target])
    elseif torch.isTensor(target) then
        assert(target:dim() == 1, '1D tensors only!')
        local nSamples = target:size(1)
        self._target:resize(nSamples, self.nClasses)
        for i=1,nSamples do
            self._target[i]:copy(self.simplex[target[i]])
        end
    end
end

function ClassSimplexCriterion:updateOutput(input, target)
    transformTarget(self, target)
    assert(input:nElement() == self._target:nElement())
    self.output_tensor = self.output_tensor or input.new(1)
    input.THNN.MSECriterion_updateOutput(
      input:cdata(),
      self._target:cdata(),
      self.output_tensor:cdata(),
      self.sizeAverage
    )
    self.output = self.output_tensor[1]
    return self.output
end

function ClassSimplexCriterion:updateGradInput(input, target)
    assert(input:nElement() == self._target:nElement())
    input.THNN.MSECriterion_updateGradInput(
      input:cdata(),
      self._target:cdata(),
      self.gradInput:cdata(),
      self.sizeAverage
    )
    return self.gradInput
end

function ClassSimplexCriterion:getPredictions(input)
    if input:dim() == 1 then
        input = input:view(1, -1)
    end
    return torch.mm(input, self.simplex:t())
end

function ClassSimplexCriterion:getTopPrediction(input)
    local prod = self:getPredictions(input)
    local _, maxs = prod:max(prod:nDimension())
    return maxs:view(-1)
end
