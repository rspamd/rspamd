local Criterion = torch.class('nn.Criterion')

function Criterion:__init()
   self.gradInput = torch.Tensor()
   self.output = 0
end

function Criterion:updateOutput(input, target)
end

function Criterion:forward(input, target)
   return self:updateOutput(input, target)
end

function Criterion:backward(input, target)
   return self:updateGradInput(input, target)
end

function Criterion:updateGradInput(input, target)
end

function Criterion:clone()
   local f = torch.MemoryFile("rw"):binary()
   f:writeObject(self)
   f:seek(1)
   local clone = f:readObject()
   f:close()
   return clone
end

function Criterion:type(type, tensorCache)
   assert(type, 'Criterion: must provide a type to convert to')
   -- find all tensors and convert them
   for key,param in pairs(self) do
      self[key] = nn.utils.recursiveType(param, type, tensorCache)
   end
   return self
end

function Criterion:float()
   return self:type('torch.FloatTensor')
end

function Criterion:double()
   return self:type('torch.DoubleTensor')
end

function Criterion:cuda()
   return self:type('torch.CudaTensor')
end

function Criterion:cudaHalf()
   return self:type('torch.CudaHalfTensor')
end

function Criterion:cudaDouble()
   return self:type('torch.CudaDoubleTensor')
end

function Criterion:__call__(input, target)
   self.output = self:forward(input, target)
   self.gradInput = self:backward(input, target)
   return self.output, self.gradInput
end
