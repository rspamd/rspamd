local Euclidean, parent = torch.class('nn.Euclidean', 'nn.Module')

function Euclidean:__init(inputSize,outputSize)
   parent.__init(self)

   self.weight = torch.Tensor(inputSize,outputSize)
   self.gradWeight = torch.Tensor(inputSize,outputSize)

   -- state
   self.gradInput:resize(inputSize)
   self.output:resize(outputSize)

   self.fastBackward = true

   self:reset()
end

function Euclidean:reset(stdv)
   if stdv then
      stdv = stdv * math.sqrt(3)
   else
      stdv = 1./math.sqrt(self.weight:size(1))
   end
   if nn.oldSeed then
      for i=1,self.weight:size(2) do
         self.weight:select(2, i):apply(function()
            return torch.uniform(-stdv, stdv)
         end)
      end
   else
      self.weight:uniform(-stdv, stdv)
   end
end

local function view(res, src, ...)
   local args = {...}
   if src:isContiguous() then
      res:view(src, table.unpack(args))
   else
      res:reshape(src, table.unpack(args))
   end
end

function Euclidean:updateOutput(input)
   -- lazy initialize buffers
   self._input = self._input or input.new()
   self._weight = self._weight or self.weight.new()
   self._expand = self._expand or self.output.new()
   self._expand2 = self._expand2 or self.output.new()
   self._repeat = self._repeat or self.output.new()
   self._repeat2 = self._repeat2 or self.output.new()

   local inputSize, outputSize = self.weight:size(1), self.weight:size(2)

   -- y_j = || w_j - x || = || x - w_j ||
   if input:dim() == 1 then
      view(self._input, input, inputSize, 1)
      self._expand:expandAs(self._input, self.weight)
      self._repeat:resizeAs(self._expand):copy(self._expand)
      self._repeat:add(-1, self.weight)
      self.output:norm(self._repeat, 2, 1)
      self.output:resize(outputSize)
   elseif input:dim() == 2 then
      local batchSize = input:size(1)

      view(self._input, input, batchSize, inputSize, 1)
      self._expand:expand(self._input, batchSize, inputSize, outputSize)
      -- make the expanded tensor contiguous (requires lots of memory)
      self._repeat:resizeAs(self._expand):copy(self._expand)

      self._weight:view(self.weight, 1, inputSize, outputSize)
      self._expand2:expandAs(self._weight, self._repeat)

      if torch.type(input) == 'torch.CudaTensor' then
         -- requires lots of memory, but minimizes cudaMallocs and loops
         self._repeat2:resizeAs(self._expand2):copy(self._expand2)
         self._repeat:add(-1, self._repeat2)
      else
         self._repeat:add(-1, self._expand2)
      end

      self.output:norm(self._repeat, 2, 2)
      self.output:resize(batchSize, outputSize)
   else
      error"1D or 2D input expected"
   end

   return self.output
end

function Euclidean:updateGradInput(input, gradOutput)
   if not self.gradInput then
      return
   end

   self._div = self._div or input.new()
   self._output = self._output or self.output.new()
   self._gradOutput = self._gradOutput or input.new()
   self._expand3 = self._expand3 or input.new()

   if not self.fastBackward then
      self:updateOutput(input)
   end

   local inputSize, outputSize = self.weight:size(1), self.weight:size(2)

   --[[
   dy_j   -2 * (w_j - x)     x - w_j
   ---- = ---------------  = -------
    dx    2 || w_j - x ||      y_j
   --]]

   -- to prevent div by zero (NaN) bugs
   self._output:resizeAs(self.output):copy(self.output):add(0.0000001)
   view(self._gradOutput, gradOutput, gradOutput:size())
   self._div:cdiv(gradOutput, self._output)
   if input:dim() == 1 then
      self._div:resize(1, outputSize)
      self._expand3:expandAs(self._div, self.weight)

      if torch.type(input) == 'torch.CudaTensor' then
         self._repeat2:resizeAs(self._expand3):copy(self._expand3)
         self._repeat2:cmul(self._repeat)
      else
         self._repeat2:cmul(self._repeat, self._expand3)
      end

      self.gradInput:sum(self._repeat2, 2)
      self.gradInput:resizeAs(input)
   elseif input:dim() == 2 then
      local batchSize = input:size(1)

      self._div:resize(batchSize, 1, outputSize)
      self._expand3:expand(self._div, batchSize, inputSize, outputSize)

      if torch.type(input) == 'torch.CudaTensor' then
         self._repeat2:resizeAs(self._expand3):copy(self._expand3)
         self._repeat2:cmul(self._repeat)
      else
         self._repeat2:cmul(self._repeat, self._expand3)
      end

      self.gradInput:sum(self._repeat2, 3)
      self.gradInput:resizeAs(input)
   else
      error"1D or 2D input expected"
   end

   return self.gradInput
end

function Euclidean:accGradParameters(input, gradOutput, scale)
   local inputSize, outputSize = self.weight:size(1), self.weight:size(2)
   scale = scale or 1

   --[[
   dy_j    2 * (w_j - x)     w_j - x
   ---- = ---------------  = -------
   dw_j   2 || w_j - x ||      y_j
   --]]
   -- assumes a preceding call to updateGradInput
   if input:dim() == 1 then
      self.gradWeight:add(-scale, self._repeat2)
   elseif input:dim() == 2 then
      self._sum = self._sum or input.new()
      self._sum:sum(self._repeat2, 1)
      self._sum:resize(inputSize, outputSize)
      self.gradWeight:add(-scale, self._sum)
   else
      error"1D or 2D input expected"
   end
end

function Euclidean:type(type, tensorCache)
   if type then
      -- prevent premature memory allocations
      self:clearState()
   end
   return parent.type(self, type, tensorCache)
end

function Euclidean:clearState()
   nn.utils.clear(self, {
      '_input',
      '_output',
      '_gradOutput',
      '_weight',
      '_div',
      '_sum',
      '_expand',
      '_expand2',
      '_expand3',
      '_repeat',
      '_repeat2',
   })
   return parent.clearState(self)
end
