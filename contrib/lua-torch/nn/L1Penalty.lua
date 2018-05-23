local L1Penalty, parent = torch.class('nn.L1Penalty','nn.Module')

--This module acts as an L1 latent state regularizer, adding the
--[gradOutput] to the gradient of the L1 loss. The [input] is copied to
--the [output].

function L1Penalty:__init(l1weight, sizeAverage, provideOutput)
    parent.__init(self)
    self.l1weight = l1weight
    self.sizeAverage = sizeAverage or false
    if provideOutput == nil then
       self.provideOutput = true
    else
       self.provideOutput = provideOutput
    end
end

function L1Penalty:updateOutput(input)
    local m = self.l1weight
    if self.sizeAverage == true then
      m = m/input:nElement()
    end
    local loss = m*input:norm(1)
    self.loss = loss
    self.output = input
    return self.output
end

function L1Penalty:updateGradInput(input, gradOutput)
    local m = self.l1weight
    if self.sizeAverage == true then
      m = m/input:nElement()
    end

    self.gradInput:resizeAs(input):copy(input):sign():mul(m)

    if self.provideOutput == true then
        self.gradInput:add(gradOutput)
    end

    return self.gradInput
end
