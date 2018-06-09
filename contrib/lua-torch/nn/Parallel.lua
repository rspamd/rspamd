local Parallel, parent = torch.class('nn.Parallel', 'nn.Container')

function Parallel:__init(inputDimension,outputDimension)
   parent.__init(self)
   self.modules = {}
   self.inputDimension = inputDimension
   self.outputDimension = outputDimension
end

function Parallel:updateOutput(input)
   local nModule=input:size(self.inputDimension)
   local outputs = {}
   self.totalOutputSize = self.totalOutputSize or torch.LongStorage()
   local totalOutputSize = self.totalOutputSize

   for i=1,nModule do
      local currentInput = input:select(self.inputDimension,i)
      local currentOutput = self:rethrowErrors(self.modules[i], i, 'updateOutput', currentInput)
      table.insert(outputs, currentOutput)
      local outputSize = currentOutput:size(self.outputDimension)

      if i == 1 then
         totalOutputSize:resize(currentOutput:dim()):copy(currentOutput:size())
      else
         totalOutputSize[self.outputDimension] = totalOutputSize[self.outputDimension] + outputSize
      end

   end
   self.output:resize(totalOutputSize)

   local offset = 1
   for i=1,nModule do
      local currentOutput = outputs[i]
      local outputSize = currentOutput:size(self.outputDimension)
      self.output:narrow(self.outputDimension, offset, outputSize):copy(currentOutput)
      offset = offset + currentOutput:size(self.outputDimension)
   end
   return self.output
end

function Parallel:updateGradInput(input, gradOutput)
   local nModule=input:size(self.inputDimension)
   self.gradInput:resizeAs(input)

   local offset = 1
   for i=1,nModule do
      local module=self.modules[i]
      local currentInput = input:select(self.inputDimension,i)
      local currentOutput = module.output
      local outputSize = currentOutput:size(self.outputDimension)
      local currentGradOutput = gradOutput:narrow(self.outputDimension, offset, outputSize)

      local currentGradInput = self:rethrowErrors(module, i, 'updateGradInput', currentInput, currentGradOutput)

      self.gradInput:select(self.inputDimension,i):copy(currentGradInput)
      offset = offset + outputSize
   end
   return self.gradInput
end

function Parallel:accGradParameters(input, gradOutput, scale)
   local nModule=input:size(self.inputDimension)

   local offset = 1
   for i=1,nModule do
      local module = self.modules[i]
      local currentOutput = module.output
      local outputSize = currentOutput:size(self.outputDimension)

      self:rethrowErrors(module, i, 'accGradParameters',
          input:select(self.inputDimension,i),
          gradOutput:narrow(self.outputDimension, offset,outputSize),
          scale)

      offset = offset + outputSize
   end
end

function Parallel:accUpdateGradParameters(input, gradOutput, lr)
   local nModule=input:size(self.inputDimension)

   local offset = 1
   for i=1,nModule do
      local module = self.modules[i];
      local currentOutput = module.output
      self:rethrowErrors(module, i, 'accUpdateGradParameters',
          input:select(self.inputDimension,i),
          gradOutput:narrow(self.outputDimension, offset,
                            currentOutput:size(self.outputDimension)),
          lr)

      offset = offset + currentOutput:size(self.outputDimension)
   end
end

function Parallel:__tostring__()
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
