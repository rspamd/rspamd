local SpatialDropout, Parent = torch.class('nn.SpatialDropout', 'nn.Module')

function SpatialDropout:__init(p,stochasticInference)
   Parent.__init(self)
   self.p = p or 0.5
   self.train = true
   self.stochastic_inference = stochasticInference or false
   self.noise = torch.Tensor()
end

function SpatialDropout:updateOutput(input)
   self.output:resizeAs(input):copy(input)
   if self.train or self.stochastic_inference then
      if input:dim() == 4 then
        self.noise:resize(input:size(1), input:size(2), 1, 1)
      elseif input:dim() == 3 then
        self.noise:resize(input:size(1), 1, 1)
      else
        error('Input must be 4D (nbatch, nfeat, h, w) or 3D (nfeat, h, w)')
      end
      self.noise:bernoulli(1-self.p)
      -- We expand the random dropouts to the entire feature map because the
      -- features are likely correlated across the map and so the dropout
      -- should also be correlated.
      self.output:cmul(torch.expandAs(self.noise, input))
   else
      self.output:mul(1-self.p)
   end
   return self.output
end

function SpatialDropout:updateGradInput(input, gradOutput)
   if self.train then
      self.gradInput:resizeAs(gradOutput):copy(gradOutput)
      self.gradInput:cmul(torch.expandAs(self.noise, input)) -- simply mask the gradients with the noise vector
   else
      error('backprop only defined while training')
   end
   return self.gradInput
end

function SpatialDropout:setp(p)
   self.p = p
end

function SpatialDropout:__tostring__()
  return string.format('%s(%f)', torch.type(self), self.p)
end

function SpatialDropout:clearState()
  if self.noise then
    self.noise:set()
  end
  return Parent.clearState(self)
end
