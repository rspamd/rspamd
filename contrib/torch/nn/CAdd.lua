local CAdd, parent = torch.class("nn.CAdd", "nn.Module")

function CAdd:__init(...)
   parent.__init(self)

   local arg = {...}

   self.size = torch.LongStorage()
   local n = #arg
   if n == 1 and torch.type(arg[1]) == 'torch.LongStorage' then
      self.size:resize(#arg[1]):copy(arg[1])
   else
     self.size:resize(n)
     for i=1,n do
         self.size[i] = arg[i]
     end
   end

   self.bias = torch.Tensor(self.size)
   self.gradBias = torch.Tensor(self.size)

   self.output:resize(self.size)

   self:reset()
end

function CAdd:reset(stdv)
   if stdv then
      --std of uniform distribution on interval [-a,a] = a/sqrt(3)
      stdv = stdv * math.sqrt(3)
   else
      stdv = 1.0/math.sqrt(self.bias:nElement())
   end
   self.bias:uniform(-stdv,stdv)
end

function CAdd:updateOutput(input)
   self._output = self._output or input.new()
   self._bias = self._bias or input.new()
   self._expand = self._expand or input.new()
   self._repeat = self._repeat or input.new()

   self.output:resizeAs(input):copy(input)
   if input:nElement() == self.bias:nElement() then
      self.output:add(self.bias)
   else
      if self.bias:dim() == input:dim() then
         self._output:set(self.output)
         self._bias:set(self.bias)
      else
         local batchSize = input:size(1)
         self._output:view(self.output, batchSize, -1)
         self._bias:view(self.bias, 1, -1)
      end

      self._expand:expandAs(self._bias, self._output)

      --expandAs uses stride 0 and self._expand is not contiguous
      --cuda ops may assume contiguous input
      if torch.type(input) == 'torch.CudaTensor' then
         self._repeat:resizeAs(self._expand):copy(self._expand)
         self._output:add(self._repeat)
      else
         self._output:add(self._expand)
      end
   end

   return self.output
end

function CAdd:updateGradInput(input, gradOutput)
   self.gradInput = self.gradInput or input.new()
   self.gradInput:resizeAs(gradOutput):copy(gradOutput)

   return self.gradInput
end

function CAdd:accGradParameters(input, gradOutput, scale)
   scale = scale or 1

   self._gradBias = self._gradBias or gradOutput.new()
   self._gradOutput = self._gradOutput or gradOutput.new()
   self._repeat = self._repeat or gradOutput.new()

   if self.bias:nElement() == gradOutput:nElement() then
      self.gradBias:add(scale, gradOutput)
   else
      if self.bias:dim() == gradOutput:dim() then
         self._gradBias:set(self.gradBias)
         self._gradOutput:set(gradOutput)
      else
         local batchSize = input:size(1)
         self._gradBias:view(self.gradBias, 1, -1)
         self._gradOutput:view(gradOutput, batchSize, -1)
      end

      self._gradBias:expandAs(self._gradBias, self._gradOutput)

      --expandAs uses stride 0 and self._gradBias is not contiguous
      --cuda ops may assume contiguous input
      if torch.type(self._gradBias) == 'torch.CudaTensor' then
         self._repeat:resizeAs(self._gradBias):copy(self._gradBias)
         self._repeat:add(scale, self._gradOutput)
         self._gradBias:copy(self._repeat)
      else
         self._gradBias:add(scale, self._gradOutput)
      end
   end
end

function CAdd:type(type, tensorCache)
   if type then
      self:clearState()
   end
   return parent.type(self, type, tensorCache)
end

function CAdd:clearState()
   nn.utils.clear(self, {
      '_gradBias',
      '_expand',
      '_output',
      '_bias',
      '_repeat'
   })
   return parent.clearState(self)
end
