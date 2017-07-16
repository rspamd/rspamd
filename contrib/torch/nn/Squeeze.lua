local Squeeze, parent = torch.class('nn.Squeeze', 'nn.Module')

function Squeeze:__init(dim, numInputDims)
    parent.__init(self)
    self.dim = dim
    self:setNumInputDims(numInputDims)
end

function Squeeze:setNumInputDims(numInputDims)
   self.numInputDims = numInputDims
   return self
end

function Squeeze:updateOutput(input)
    assert(input and torch.isTensor(input), 'Squeeze only works on tensors')
    local dim    = self.dim
    local addone = false
    if self.numInputDims and input:dim()==(self.numInputDims+1) then
        if dim then
            dim = dim + 1
        elseif input:size(1) == 1 then
            addone = true -- in case of minibatch of size 1.
        end
    end
    self.output:set(dim and input:squeeze(dim) or input:squeeze())
    if addone then
        local s = self.output:size():totable{}
        table.insert(s, 1, 1)
        self.output:set(self.output:view(torch.LongStorage(s)))
    end
    return self.output
end

function Squeeze:updateGradInput(input, gradOutput)
    assert(input and torch.isTensor(input), 'Squeeze only works on tensors')
    assert(gradOutput and torch.isTensor(gradOutput), 'Squeeze only works on tensors')
    assert(input:nElement() == gradOutput:nElement())
    self.gradInput:set(gradOutput:view(input:size()))
    return self.gradInput
end
