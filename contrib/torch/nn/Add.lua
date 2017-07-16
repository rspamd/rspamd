local Add, parent = torch.class('nn.Add', 'nn.Module')

function Add:__init(inputSize,scalar)
   parent.__init(self)

   local size = inputSize
   if scalar then size=1 end
   self.scalar = scalar
   self.bias = torch.Tensor(size)
   self.gradBias = torch.Tensor(size)

   self._ones = torch.Tensor{1}

   self:reset()
end

function Add:reset(stdv)
   if stdv then
      stdv = stdv * math.sqrt(3)
   else
      stdv = 1./math.sqrt(self.bias:size(1))
   end

   self.bias:uniform(-stdv, stdv)
end

function Add:updateOutput(input)
   self.output:resizeAs(input):copy(input)
   if self.scalar then
      self.output:add(self.bias[1]);
   else
      if input:isSameSizeAs(self.bias) then
         self.output:add(self.bias)
      else
         local batchSize = input:size(1)
         if self._ones:size(1) ~= batchSize then
            self._ones:resize(batchSize):fill(1)
         end
         local bias = self.bias:view(-1)
         local output = self.output:view(batchSize, -1)
         output:addr(1, self._ones, bias)
      end
   end
   return self.output
end

function Add:updateGradInput(input, gradOutput)
   if self.gradInput then
      self.gradInput:resizeAs(gradOutput):copy(gradOutput)
      return self.gradInput
   end
end

function Add:accGradParameters(input, gradOutput, scale)
   scale = scale or 1
   if self.gradBias:size(1) == 1 then
      self.gradBias[1] = self.gradBias[1] + scale*gradOutput:sum();
   else
      if input:isSameSizeAs(self.bias) then
         self.gradBias:add(scale, gradOutput)
      else
         local gradOutput = gradOutput:view(input:size(1), -1)
         self.gradBias:view(-1):addmv(scale, gradOutput:t(), self._ones)
      end
   end
end
