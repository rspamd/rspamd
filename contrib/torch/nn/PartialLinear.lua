local PartialLinear, Module = torch.class('nn.PartialLinear', 'nn.Module')

--[[

PartialLinear is a Linear layer that allows the user to a set a collection of
column indices. When the column indices are set, the layer will behave like a
Linear layer that only has those columns. Meanwhile, all parameters are
preserved, so resetting the PartialLinear layer will result in a module that
behaves just like a regular Linear layer.

This module is useful, for instance, when you want to do forward-backward on
only a subset of a Linear layer during training but use the full Linear layer
at test time.

]]--

function PartialLinear:__init(inputsize, outputsize, bias)
   local bias = ((bias == nil) and true) or bias
   Module.__init(self)

   -- define the layer as a small network:
   local pt = nn.ParallelTable()
   pt:add(nn.Identity()):add(nn.LookupTable(outputsize, inputsize))
   self.network = nn.Sequential():add(pt):add(nn.MM(false, true))
   if bias then
      self.bias     = torch.Tensor(1, outputsize):zero()
      self.gradBias = torch.Tensor(1, outputsize):zero()
   end

   -- set partition:
   self.inputsize  = inputsize
   self.outputsize = outputsize
   self.allcolumns = torch.range(1, self.outputsize)
   self:resetPartition()
end

function PartialLinear:setPartition(indices)
   self.partition = indices:type(self.allcolumns:type())
end

function PartialLinear:resetPartition()
   self.partition = self.allcolumns
end

function PartialLinear:parameters()
   return {self.network:get(1):get(2).weight,     self.bias},
          {self.network:get(1):get(2).gradWeight, self.gradBias}
end  -- should return only the relevant partition?

function PartialLinear:updateOutput(input)
   self.output:set(self.network:forward{input, self.partition})
   if self.bias then
      self.output:add(
         self.bias:index(2, self.partition:long()):expandAs(self.output)
      )
      self.addBuffer = self.addBuffer or input.new()
      if self.addBuffer:nElement() ~= input:size(1) then
         self.addBuffer:resize(input:size(1)):fill(1)
      end
   end
   return self.output
end

function PartialLinear:updateGradInput(input, gradOutput)
   if self.gradInput then
      self.network:updateGradInput({input, self.partition}, gradOutput)
      self.gradInput:set(self.network.gradInput[1])
   end
   return self.gradInput
end

function PartialLinear:accGradParameters(input, gradOutput, scale)
   local scale = scale or 1
   self.network:accGradParameters({input, self.partition}, gradOutput, scale)
   if self.bias then
      self.buffer = self.buffer or input.new()
      self.buffer:resize(gradOutput:size(2))
      self.buffer:mv(gradOutput:t(), self.addBuffer):mul(scale)
      self.gradBias:indexAdd(
         2, self.partition:long(), self.buffer:view(1, self.buffer:nElement())
      )
   end
end

function PartialLinear:accUpdateGradParameters(input, gradOutput, lr)
   local gradWeight = self.network:get(1):get(2).gradWeight
   local gradBias = self.gradBias
   self.network:get(1):get(2).gradWeight = self.network:get(1):get(2).weight
   self.gradBias = self.bias
   self:accGradParameters(input, gradOutput, -lr)
   self.network:get(1):get(2).gradWeight = gradWeight
   self.gradBias = gradBias
end

function PartialLinear:zeroGradParameters()
   self.network:zeroGradParameters()
   self.gradBias:zero()
end

function PartialLinear:updateParameters(learningRate)
   self.network:updateParameters(learningRate)
   self.bias:add(-learningRate, self.gradBias)
end

function PartialLinear:sharedAccUpdateGradParameters(input, gradOutput, lr)
   -- we do not need to accumulate parameters when sharing:
   self:defaultAccUpdateGradParameters(input, gradOutput, lr)
end

function PartialLinear:__tostring__()
   return torch.type(self) ..
      string.format('(%d -> %d)', self.inputsize, self.outputsize) ..
      (self.bias == nil and ' without bias' or '')
end
