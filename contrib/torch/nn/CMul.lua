local CMul, parent = torch.class('nn.CMul', 'nn.Module')

function CMul:__init(...)
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

   self.weight = torch.Tensor(self.size)
   self.gradWeight = torch.Tensor(self.size)

   self.output:resize(self.size)

   self:reset()
end

function CMul:reset(stdv)
   if stdv then
      stdv = stdv * math.sqrt(3)
   else
      stdv = 1./math.sqrt(self.weight:nElement())
   end
   self.weight:uniform(-stdv,stdv)
end

function CMul:updateOutput(input)
   -- lazy-initialize
   self._output = self._output or input.new()
   self._weight = self._weight or input.new()
   self._expand = self._expand or input.new()
   self._repeat = self._repeat or input.new()

   self.output:resizeAs(input):copy(input)
   if input:nElement() == self.weight:nElement() then
      self._output:view(self.output, -1)
      self._weight:view(self.weight, -1)

      self._output:cmul(self._weight)
   else
      if self.weight:dim() == input:dim() then
         self._output:set(self.output)
         self._weight:set(self.weight)
      else
         local batchSize = input:size(1)
         self._output:view(self.output, batchSize, -1)
         self._weight:view(self.weight, 1, -1)
      end

      self._expand:expandAs(self._weight, self._output)

      if torch.type(input) == 'torch.CudaTensor' then
         self._repeat:resizeAs(self._expand):copy(self._expand)
         self._output:cmul(self._repeat)
      else
         self._output:cmul(self._expand)
      end
   end

   return self.output
end

function CMul:updateGradInput(input, gradOutput)
   if not self.gradInput then
      return
   end

   self._gradOutput = self._gradOutput or input.new()
   self._gradInput = self._gradInput or input.new()

   self.gradInput:resizeAs(input):zero()
   if self.weight:nElement() == gradOutput:nElement() then
      self.gradInput:addcmul(1, self.weight, gradOutput)
   else
      if self.weight:dim() == input:dim() then
         nn.utils.contiguousView(self._gradOutput, gradOutput, gradOutput:size())
         nn.utils.contiguousView(self._gradInput, self.gradInput, self.gradInput:size())
         self._weight:set(self.weight)
      else
         local batchSize = input:size(1)
         nn.utils.contiguousView(self._gradOutput, gradOutput, batchSize, -1)
         nn.utils.contiguousView(self._gradInput, self.gradInput, batchSize, -1)
         self._weight:view(self.weight, 1, -1)
      end

      self._expand:expandAs(self._weight, self._gradOutput)

      if torch.type(input) == 'torch.CudaTensor' then
         self._repeat:resizeAs(self._expand):copy(self._expand)
         self._gradInput:addcmul(1, self._repeat, self._gradOutput)
      else
         self._gradInput:addcmul(1, self._expand, self._gradOutput)
      end
   end

   return self.gradInput
end

function CMul:accGradParameters(input, gradOutput, scale)
   scale = scale or 1

   self._input = self._input or input.new()
   self._gradWeight = self._gradWeight or input.new()
   self._sum = self._sum or input.new()

   if self.weight:nElement() == gradOutput:nElement() then
      self.gradWeight:addcmul(scale, input, gradOutput)
   else
      if self.weight:dim() == input:dim() then
         nn.utils.contiguousView(self._input, input, input:size())
         nn.utils.contiguousView(self._gradOutput, gradOutput, gradOutput:size())
         self._gradWeight:set(self.gradWeight)

         self._repeat:cmul(self._input, self._gradOutput)
         local sumInto = self._sum
         local sumFrom = self._repeat
         for i=1,self.weight:dim() do
            if self.weight:size(i) ~= input:size(i) then
               sumInto:sum(sumFrom, i)
               sumInto = sumFrom
               sumFrom = sumFrom == self._repeat and self._sum or self._repeat
            end
         end
         self._gradWeight:add(scale, sumFrom)
      else
         local batchSize = input:size(1)
         nn.utils.contiguousView(self._input, input, batchSize, -1)
         nn.utils.contiguousView(self._gradOutput, gradOutput, batchSize, -1)
         self._gradWeight:view(self.gradWeight, 1, -1)

         self._repeat:cmul(self._input, self._gradOutput)
         self._sum:sum(self._repeat, 1)
         self._gradWeight:add(scale, self._sum)
      end

   end
end

function CMul:type(type, tensorCache)
   if type then
      self:clearState()
   end
   return parent.type(self, type, tensorCache)
end

function CMul:clearState()
   nn.utils.clear(self, {
      '_input',
      '_output',
      '_weight',
      '_gradWeight',
      '_expand',
      '_repeat',
      '_sum',
   })
   return parent.clearState(self)
end
