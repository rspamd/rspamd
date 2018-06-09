local WhiteNoise, parent = torch.class('nn.WhiteNoise', 'nn.Module')

function WhiteNoise:__init(mean, std)
   parent.__init(self)
   self.mean = mean or 0
   self.std = std or 0.1
   self.noise = torch.Tensor()
end

function WhiteNoise:updateOutput(input)
   self.output:resizeAs(input):copy(input)
   if self.train ~= false then
      self.noise:resizeAs(input)
      self.noise:normal(self.mean, self.std)
      self.output:add(self.noise)
   else
      if self.mean ~= 0 then
         self.output:add(self.mean)
      end
   end
   return self.output
end

function WhiteNoise:updateGradInput(input, gradOutput)
   if self.train ~= false then
      -- Simply return the gradients.
      self.gradInput:resizeAs(gradOutput):copy(gradOutput)
   else
      error('backprop only defined while training')
   end
   return self.gradInput
end

function WhiteNoise:clearState()
   self.noise:set()
end

function WhiteNoise:__tostring__()
  return string.format('%s mean: %f, std: %f', torch.type(self), self.mean, self.std)
end
