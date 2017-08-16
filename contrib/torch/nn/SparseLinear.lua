local THNN = require 'nn.THNN'
local SparseLinear, parent = torch.class('nn.SparseLinear', 'nn.Module')

local NO_LAST_INPUT = 0
local ONE_LAST_INPUT = 1
local ACC_MULTIPLE_TIMES = 2

function SparseLinear:__init(inputSize, outputSize, doGradInput)
   parent.__init(self)

   self.weightDecay = 0
   self.doGradInput = doGradInput or false
   self.weight = torch.Tensor(outputSize, inputSize):zero()
   self.bias = torch.Tensor(outputSize):zero()
   self.gradWeight = torch.Tensor(outputSize, inputSize):zero()
   self.gradBias = torch.Tensor(outputSize):zero()

   assert(type(self.doGradInput) == type(true))

   self.lastInput = nil
   self.sparseUpdate = NO_LAST_INPUT
   self.formatted_input = nil

   -- state
   self.gradInput = {}
   self.output:resize(outputSize)

   self:reset()
end

function SparseLinear:reset(stdv)
   if stdv then
      stdv = stdv * math.sqrt(3)
   else
      stdv = 1./math.sqrt(self.weight:size(2))
   end
   self.weight:uniform(-stdv, stdv)
   self.bias:uniform(-stdv, stdv):mul(0.000001)
end

function SparseLinear:reshapeInput(input)
   if type(input) == 'table' then
      return input, true, false
   else
      if input:dim() == 2 then
         return {input}, false, false
      else
         return input, true, true
      end
   end
end

function SparseLinear:updateOutput(input)
   if self.sparseUpdate == ONE_LAST_INPUT then
      self.sparseUpdate = ACC_MULTIPLE_TIMES
   end
   local input, batchMode, legacyMode = self:reshapeInput(input)
   self.legacyMode = legacyMode

   if legacyMode then
      input.THNN.SparseLinear_legacyUpdateOutput(
         input:cdata(),
         self.output:cdata(),
         self.weight:cdata(),
         self.bias:cdata()
      )
   else
      local nbatches = #input
      if nbatches == 0 then
         self.output:copy(self.bias)
         return self.output
      end

      local size = 0
      local marker = 1
      self.formatted_input = self.formatted_input or input[1].new()

      for i,v in ipairs(input) do size = size + input[i]:size(1) end
      self.formatted_input:resize(size, 3)
      for i,v in ipairs(input) do
         local buf = self.formatted_input:narrow(1, marker, input[i]:size(1))
         buf:narrow(2,2,2):copy(input[i])
         buf:select(2,1):fill(i)
         marker = marker + input[i]:size(1)
      end

      self.output:resize(nbatches, self.weight:size(1))
      input[1].THNN.SparseLinear_updateOutput(
         self.formatted_input:cdata(),
         self.output:cdata(),
         self.weight:cdata(),
         self.bias:cdata()
      )

      -- fix output size for batchSize = 1
      if not batchMode then
         self.output = self.output[1]
      end
   end

   return self.output
end

function SparseLinear:accGradParameters(input, gradOutput, scale)
   local input, batchMode, legacyMode = self:reshapeInput(input)
   self.legacyMode = legacyMode
   self.lastInput = self.lastInput or gradOutput.new()
   if self.sparseUpdate == NO_LAST_INPUT then
      local v = self.formatted_input
      if self.legacyMode then v = input end
      self.lastInput:resizeAs(v):copy(v)
      self.sparseUpdate = ONE_LAST_INPUT
   elseif self.sparseUpdate == ONE_LAST_INPUT then
      self.sparseUpdate = ACC_MULTIPLE_TIMES
   end

   if legacyMode then
      input.THNN.SparseLinear_legacyAccGradParameters(
         input:cdata(),
         gradOutput:cdata(),
         self.gradWeight:cdata(),
         self.gradBias:cdata(),
         self.weight:cdata(),
         self.bias:cdata(),
         self.weightDecay or 0,
         scale or 1
      )
   else
      if not batchMode then
         gradOutput:resize(1, gradOutput:size(1))
      end

      local rows = self.formatted_input:select(2, 1)
      local cols = self.formatted_input:select(2, 2)
      local sortinds = cols * gradOutput:size(1) + rows
      local _, inds = sortinds:sort(1, false)
      local newinput = self.formatted_input:index(1, inds)
      input[1].THNN.SparseLinear_accGradParameters(
         newinput:cdata(),
         gradOutput:cdata(),
         self.gradWeight:cdata(),
         self.gradBias:cdata(),
         self.weight:cdata(),
         self.bias:cdata(),
         self.weightDecay or 0,
         scale or 1
      )
   end
end

function SparseLinear:updateGradInput(input, gradOutput)
   if self.legacyMode then
      if type(self.gradInput) ~= type(gradOutput) then self.gradInput = gradOutput.new() end
      self.gradInput:resizeAs(input)
   else
      self.gradInput = {}
   end
   if self.doGradInput then
      -- GradInput should be dense anyway
      local gi
      local batchMode = true
      if gradOutput:dim() == 1 then
         gi = self.weight:t()*gradOutput
         batchMode = false
      elseif gradOutput:dim() == 2 then
         gi = gradOutput*self.weight
      end
      local ini = self.weight:size(2)

      if self.legacyMode then
         local batches = self.gradInput:size(1)
         self.gradInput:resize(batches, ini, 2)
         self.gradInput:select(3,1):copy(torch.repeatTensor(torch.range(1, ini), batches, 1))
         self.gradInput:select(3,2):copy(gi)
      else
         local indicies = torch.range(1, ini)
         if not batchMode then gi:resize(1, ini) end
         for i = 1,gi:size(1) do
            self.gradInput[i] = gradOutput.new(ini, 2)
            self.gradInput[i]:select(2, 2):copy(gi[i])
            self.gradInput[i]:select(2, 1):range(1, ini)
         end
      end
   end
   return self.gradInput
end

-- These functions do sparse updates / zeros. However, if we accumulated
-- gradients multiple times, we can't depend on the last input to do sparse
-- updates.
function SparseLinear:updateParameters(learningRate)
   if self.lastInput and self.sparseUpdate == ONE_LAST_INPUT then
      if self.legacyMode then
         self.lastInput.THNN.SparseLinear_legacyUpdateParameters(
            self.weight:cdata(),
            self.bias:cdata(),
            self.gradWeight:cdata(),
            self.gradBias:cdata(),
            self.lastInput:cdata(),
            learningRate
         )
      else
         self.lastInput.THNN.SparseLinear_updateParameters(
            self.weight:cdata(),
            self.bias:cdata(),
            self.gradWeight:cdata(),
            self.gradBias:cdata(),
            self.lastInput:cdata(),
            learningRate
         )
      end
   else
      parent.updateParameters(self, learningRate)
   end
end

function SparseLinear:zeroGradParameters()
   if self.lastInput and self.sparseUpdate == ONE_LAST_INPUT then
      if self.legacyMode then
         self.lastInput.THNN.SparseLinear_legacyZeroGradParameters(
            self.gradWeight:cdata(),
            self.gradBias:cdata(),
            self.lastInput:cdata()
         )
      else
         self.lastInput.THNN.SparseLinear_zeroGradParameters(
            self.gradWeight:cdata(),
            self.gradBias:cdata(),
            self.lastInput:cdata()
         )
      end
   else
      parent.zeroGradParameters(self)
   end
   self.sparseUpdate = NO_LAST_INPUT
end

function SparseLinear:clearState()
   if self.lastInput then self.lastInput:set() end
   input.THNN.SparseLinear_cudaClearState()
   return parent.clearState(self)
end
