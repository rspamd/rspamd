local Cosine, parent = torch.class('nn.Cosine', 'nn.Module')

function Cosine:__init(inputSize,outputSize)
   parent.__init(self)

   self.weight = torch.Tensor(outputSize,inputSize)
   self.gradWeight = torch.Tensor(outputSize,inputSize)

   self:reset()
end

function Cosine:reset(stdv)
   if stdv then
      stdv = stdv * math.sqrt(3)
   else
      stdv = 1./math.sqrt(self.weight:size(1))
   end
   self.weight:uniform(-stdv, stdv)
end

function Cosine:updateOutput(input)
   local inputSize = self.weight:size(2)
   local outputSize = self.weight:size(1)

   self._weightNorm = self._weightNorm or self.weight.new()
   self._inputNorm = self._inputNorm or self.weight.new()

   -- y_j = (w_j * x) / ( || w_j || * || x || )

   self._weightNorm:norm(self.weight,2,2):add(1e-12)
   if input:dim() == 1 then
      self.output:resize(outputSize):zero()
      self.output:addmv(1, self.weight, input)
      self.__norm = input:norm()+1e-12
      self.output:cdiv(self._weightNorm:view(outputSize)):div(self.__norm)
   elseif input:dim() == 2 then
      local batchSize = input:size(1)
      local nElement = self.output:nElement()
      self.output:resize(batchSize, outputSize)
      if self.output:nElement() ~= nElement then
         self.output:zero()
      end
      self.output:addmm(0, self.output, 1, input, self.weight:t())

      self._inputNorm:norm(input,2,2):add(1e-12)
      self.output:cdiv(self._weightNorm:view(1,outputSize):expandAs(self.output))
      self.output:cdiv(self._inputNorm:expandAs(self.output))
   else
      error('input must be vector or matrix')
   end

   return self.output
end

function Cosine:updateGradInput(input, gradOutput)
   if not self.gradInput then
      return
   end

   local inputSize = self.weight:size(2)
   local outputSize = self.weight:size(1)

   --[[
   dy_j           w_ji                   x_i
   ---- = -------------------  -  y_j ---------
   dx_i   || w_j || * || x ||         || x ||^2
   --]]

   local nElement = self.gradInput:nElement()
   self.gradInput:resizeAs(input)
   if self.gradInput:nElement() ~= nElement then
      self.gradInput:zero()
   end

   if input:dim() == 1 then
      self._weight = self._weight or input.new()
      self._weight:resizeAs(self.weight):copy(self.weight)
      self._weight:cdiv(self._weightNorm:expandAs(self.weight))
      self._weight:div(self.__norm)
      self._weight:addr(1, self._weight, -1/(self.__norm*self.__norm), self.output, input)
      self.gradInput:addmv(0, 1, self._weight:t(), gradOutput)
   elseif input:dim() == 2 then
      local inputNorm = self._inputNorm:expandAs(input)
      local weightNorm = self._weightNorm:view(1,outputSize):expandAs(gradOutput)

      self.gradInput:copy(input):cdiv(inputNorm)
      self._gradOutput = self._gradOutput or gradOutput.new()
      self._gradOutput:resizeAs(gradOutput):copy(gradOutput)
      self._gradOutput:cmul(self.output)
      self._sum = self._sum or input.new()
      self._sum:sum(self._gradOutput, 2)
      self.gradInput:cmul(self._sum:expandAs(input))

      self._gradOutput:resizeAs(gradOutput):copy(gradOutput)
      self._gradOutput:cdiv(weightNorm)
      self.gradInput:addmm(-1, self.gradInput, 1, self._gradOutput, self.weight)

      self.gradInput:cdiv(inputNorm)
   end

   return self.gradInput
end

function Cosine:accGradParameters(input, gradOutput, scale)
   scale = scale or 1
   local inputSize = self.weight:size(2)
   local outputSize = self.weight:size(1)

   --[[
   dy_j            x_i                     w_ji
   ----- = -------------------  -  y_j -----------
   dw_ji   || w_j || * || x ||         || w_j ||^2
   --]]

   if input:dim() == 1 then
      self._gradOutput = self._gradOutput or gradOutput.new()
      self._gradOutput:resizeAs(gradOutput):copy(gradOutput)
      local weightNorm = self._weightNorm:view(outputSize)
      self._gradOutput:cdiv(weightNorm)
      self.gradWeight:addr(scale/self.__norm, self._gradOutput, input)

      self._gradOutput:cdiv(weightNorm)
      self._gradOutput:cmul(self.output)
      self._weight = self._weight or self.weight.new()
      self._weight:resizeAs(self._weight):copy(self.weight)
      self._weight:cmul(self._gradOutput:view(outputSize, 1):expandAs(self.weight))
      self.gradWeight:add(-1, self._weight)
   elseif input:dim() == 2 then
      self._weight = self._weight or self.weight.new()
      self._weight:resizeAs(self.weight):copy(self.weight)
      self._gradOutput = self._gradOutput or gradOutput.new()
      self._gradOutput:resizeAs(gradOutput):copy(gradOutput)
      self._gradOutput:cmul(self.output)
      self._sum = self._sum or input.new()
      self._sum:sum(self._gradOutput, 1)
      local grad = self._sum[1]
      grad:cdiv(self._weightNorm:select(2,1))
      self._weight:cmul(grad:view(outputSize,1):expandAs(self._weight))

      local input_ = self._gradOutput
      input_:resizeAs(input):copy(input)
      input_:cdiv(self._inputNorm:expandAs(input))
      self._weight:addmm(-1, self._weight, 1, gradOutput:t(), input_)

      self._weight:cdiv(self._weightNorm:expandAs(self._weight))
      self.gradWeight:add(self._weight)
   else
      error"1D or 2D input expected"
   end
end

function Cosine:type(type, tensorCache)
   if type then
      -- prevent premature memory allocations
      self._input = nil
      self._weight = nil
      self._inputNorm = nil
      self._weightNorm = nil
      self._gradOutput = nil
      self._sum = nil
   end
   return parent.type(self, type, tensorCache)
end

function Cosine:clearState()
   nn.utils.clear(self, {
      '_input',
      '_weight',
      '_gradOutput',
      '_sum',
      '_inputNorm',
      '_weightNorm',
   })
   return parent.clearState(self)
end
