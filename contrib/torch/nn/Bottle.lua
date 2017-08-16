local Bottle, parent = torch.class("nn.Bottle", "nn.Decorator")
local unpack = unpack or table.unpack

function Bottle:__init(module, nInputDim, nOutputDim)
   parent.__init(self, module)
   self.nInputDim = nInputDim or 2
   self.nOutputDim = nOutputDim or self.nInputDim
   self.dimDelta = self.nInputDim - self.nOutputDim
   -- Used to reshape the gradients
   self.inShape = torch.Tensor(self.nInputDim)
   self.outShape = torch.Tensor(self.nOutputDim)
end

function Bottle:updateOutput(input)
   -- first batchDims dimensions will be fused
   local batchDims = input:dim() - self.nInputDim + 1
   -- see if bottle is required
   if batchDims > 1 then
      -- bottle the first dims
      local inSize = torch.LongTensor(input:size())
      local squeezeSize = inSize[{{1, batchDims - 1}}]:prod()
      self.inShape:copy(inSize[{{batchDims, input:dim()}}])
      self.inShape[{{1}}]:mul(squeezeSize)
      -- Forward with the module's dimension
      local newInput = input:view(unpack(self.inShape:totable()))
      local output = self.modules[1]:updateOutput(newInput)
      assert(output:dim() == self.nOutputDim,
	     "Wrong number of output dims on module. Expected: " ..
		self.nOutputDim .. ' but got ' ..
		tostring(output and output:dim()))
      self.outShape:copy(torch.LongTensor(output:size()))
      if math.abs(self.dimDelta) > 0 then
         inSize:resize(inSize:size(1) - self.dimDelta)
      end
      inSize[{{batchDims, inSize:size(1)}}]:copy(self.outShape)
      inSize[{{batchDims}}]:div(squeezeSize)
      -- unbottle
      self.output:set(output:view(unpack(torch.totable(inSize))))
   else
      self.output:set(self.modules[1]:updateOutput(input))
   end
   return self.output
end

function Bottle:updateGradInput(input, gradOutput)
   if input:dim() > self.nInputDim then
      local input_ = input:view(unpack(self.inShape:totable()))
      local gradOutput_ = gradOutput:view(unpack(self.outShape:totable()))
      self.modules[1]:updateGradInput(input_, gradOutput_)
      if self.modules[1].gradInput then
         self.gradInput:set(self.modules[1].gradInput:viewAs(input))
      else
         self.gradInput = nil
      end
   else
      if self.modules[1].gradInput then
         self.gradInput:set(self.modules[1]:updateGradInput(input, gradOutput))
      else
         self.gradInput = nil
      end
   end
   return self.gradInput
end

function Bottle:accGradParameters(input, gradOutput, scale)
   if input:dim() > self.nInputDim then
      input = input:view(unpack(self.inShape:totable()))
      gradOutput = gradOutput:view(unpack(self.outShape:totable()))
   end
   self.modules[1]:accGradParameters(input, gradOutput, scale)
end
