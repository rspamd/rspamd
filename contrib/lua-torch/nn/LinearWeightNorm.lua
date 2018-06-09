local LinearWeightNorm, parent = torch.class('nn.LinearWeightNorm', 'nn.Linear')

function LinearWeightNorm:__init(inputSize, outputSize, bias, eps)
    nn.Module.__init(self) -- Skip nn.Linear constructor

    local bias = ((bias == nil) and true) or bias

    self.eps = eps or 1e-16

    self.outputSize = outputSize
    self.inputSize = inputSize

    self.v = torch.Tensor(outputSize, inputSize)
    self.gradV = torch.Tensor(outputSize, inputSize)

    self.weight = torch.Tensor(outputSize, inputSize)

    self.g = torch.Tensor(outputSize,1)
    self.gradG = torch.Tensor(outputSize,1)

    self.norm = torch.Tensor(outputSize,1)
    self.scale = torch.Tensor(outputSize,1)

    if bias then
        self.bias = torch.Tensor(outputSize)
        self.gradBias = torch.Tensor(outputSize)
    end

    self:reset()
end

function LinearWeightNorm:evaluate()
    if self.train ~= false then
        self:updateWeightMatrix()
    end

    parent.evaluate(self)
end

function LinearWeightNorm:initFromWeight(weight)
    weight = weight or self.weight

    self.g:norm(weight,2,2):clamp(self.eps,math.huge)
    self.v:copy(weight)

    return self
end

function LinearWeightNorm.fromLinear(linear)
    local module = nn.LinearWeightNorm(linear.weight:size(2), linear.weight:size(1), torch.isTensor(linear.bias))
    module.weight:copy(linear.weight)
    module:initFromWeight()

    if linear.bias then
        module.bias:copy(linear.bias)
    end

    return module
end

function LinearWeightNorm:toLinear()
    self:updateWeightMatrix()

    local module = nn.Linear(self.inputSize, self.outputSize, torch.isTensor(self.bias))

    module.weight:copy(self.weight)
    if self.bias then
        module.bias:copy(self.bias)
    end

    return module
end

function LinearWeightNorm:parameters()
    if self.bias then
        return {self.v, self.g, self.bias}, {self.gradV, self.gradG, self.gradBias}
    else
        return {self.v, self.g}, {self.gradV, self.gradG}
    end
end

function LinearWeightNorm:reset(stdv)
    if stdv then
        stdv = stdv * math.sqrt(3)
    else
        stdv = 1 / math.sqrt(self.inputSize)
    end

    self.weight:uniform(-stdv,stdv)
    self:initFromWeight()

    if self.bias then
        self.bias:uniform(-stdv,stdv)
    end
end

function LinearWeightNorm:updateWeightMatrix()
    if self.norm:dim() == 0 then self.norm:resizeAs(self.g) end
    if self.scale:dim() == 0 then self.scale:resizeAs(self.g) end
    if self.weight:dim() == 0 then self.weight:resizeAs(self.v) end

    self.norm:norm(self.v,2,2):clamp(self.eps,math.huge)
    self.scale:cdiv(self.g,self.norm)
    self.weight:cmul(self.v,self.scale:expandAs(self.v))
end

function LinearWeightNorm:updateOutput(input)
    if self.train ~= false then
        self:updateWeightMatrix()
    end

    return parent.updateOutput(self, input)
end

function LinearWeightNorm:accGradParameters(input, gradOutput, scale)
    scale = scale or 1
    if input:dim() == 1 then
        self.gradV:addr(scale, gradOutput, input)
        if self.bias then self.gradBias:add(scale, gradOutput) end
    elseif input:dim() == 2 then
        self.gradV:addmm(scale, gradOutput:t(), input)
        if self.bias then
            -- update the size of addBuffer if the input is not the same size as the one we had in last updateGradInput
            self:updateAddBuffer(input)
            self.gradBias:addmv(scale, gradOutput:t(), self.addBuffer)
        end
    end

    local scale = self.scale:expandAs(self.v)
    local norm = self.norm:expandAs(self.v)

    self.weight:cmul(self.gradV,self.v):cdiv(norm)
    self.gradG:sum(self.weight,2)

    self.gradV:cmul(scale)

    self.weight:cmul(self.v,scale):cdiv(norm)
    self.weight:cmul(self.gradG:expandAs(self.weight))

    self.gradV:add(-1,self.weight)
end

function LinearWeightNorm:defaultAccUpdateGradParameters(input, gradOutput, lr)
    local gradV = self.gradV
    local gradG = self.gradG
    local gradBias = self.gradBias

    self.gradV = self.v
    self.gradG = self.g
    self.gradBias = self.bias

    self:accGradParameters(input, gradOutput, -lr)

    self.gradV = gradV
    self.gradG = gradG
    self.gradBias = gradBias
end

function LinearWeightNorm:clearState()
    nn.utils.clear(self, 'weight', 'norm', 'scale')
    return parent.clearState(self)
end

function LinearWeightNorm:__tostring__()
    return torch.type(self) ..
        string.format('(%d -> %d)', self.inputSize, self.outputSize) ..
        (self.bias == nil and ' without bias' or '')
end