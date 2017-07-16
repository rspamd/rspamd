local ParallelTable, parent = torch.class('nn.ParallelTable', 'nn.Container')

function ParallelTable:__init()
   parent.__init(self)
   self.modules = {}
   self.output = {}
   self.gradInput = {}
end

function ParallelTable:updateOutput(input)
   for i=1,#self.modules do
      self.output[i] = self:rethrowErrors(self.modules[i], i, 'updateOutput', input[i])
   end
   return self.output
end

function ParallelTable:updateGradInput(input, gradOutput)
   for i,module in ipairs(self.modules) do
      self.gradInput[i] = self:rethrowErrors(module, i, 'updateGradInput', input[i], gradOutput[i])
   end
   return self.gradInput
end

function ParallelTable:accGradParameters(input, gradOutput, scale)
   scale = scale or 1
   for i,module in ipairs(self.modules) do
      self:rethrowErrors(module, i, 'accGradParameters', input[i], gradOutput[i], scale)
   end
end

function ParallelTable:accUpdateGradParameters(input, gradOutput, lr)
   lr = lr or 1
   for i,module in ipairs(self.modules) do
      self:rethrowErrors(module, i, 'accUpdateGradParameters', input[i], gradOutput[i], lr)
   end
end

function ParallelTable:__tostring__()
   local tab = '  '
   local line = '\n'
   local next = '  |`-> '
   local lastNext = '   `-> '
   local ext = '  |    '
   local extlast = '       '
   local last = '   ... -> '
   local str = torch.type(self)
   str = str .. ' {' .. line .. tab .. 'input'
   for i=1,#self.modules do
      if i == #self.modules then
         str = str .. line .. tab .. lastNext .. '(' .. i .. '): ' .. tostring(self.modules[i]):gsub(line, line .. tab .. extlast)
      else
         str = str .. line .. tab .. next .. '(' .. i .. '): ' .. tostring(self.modules[i]):gsub(line, line .. tab .. ext)
      end
   end
   str = str .. line .. tab .. last .. 'output'
   str = str .. line .. '}'
   return str
end
