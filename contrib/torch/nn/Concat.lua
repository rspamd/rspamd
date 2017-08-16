local Concat, parent = torch.class('nn.Concat', 'nn.Container')

function Concat:__init(dimension)
   parent.__init(self)
   self.outputSize = torch.LongStorage()
   self.dimension = dimension
end

function Concat:updateOutput(input)
   self.outputSize = self.outputSize or torch.LongStorage()

   local outs = {}
   for i=1,#self.modules do
      local currentOutput = self:rethrowErrors(self.modules[i], i, 'updateOutput', input)
      outs[i] = currentOutput
      if i == 1 then
         self.outputSize:resize(currentOutput:dim()):copy(currentOutput:size())
      else
         self.outputSize[self.dimension] = self.outputSize[self.dimension] + currentOutput:size(self.dimension)
      end
   end
   self.output:resize(self.outputSize)

   local offset = 1
   for i,module in ipairs(self.modules) do
      local currentOutput = outs[i]
      self.output:narrow(self.dimension, offset, currentOutput:size(self.dimension)):copy(currentOutput)
      offset = offset + currentOutput:size(self.dimension)
   end
   return self.output
end

local function retable(t1, t2, f)
   for k, v in ipairs(t2) do
      if (torch.type(v) == "table") then
         t1[k] = retable(t1[k] or {}, t2[k], f)
      else
         f(t1, k, v)
      end
   end
   for i=#t2+1, #t1 do
      t1[i] = nil
   end
   return t1
end

local function backward(self, method, input, gradOutput, scale)
   local isTable = torch.type(input) == 'table'
   local wasTable = torch.type(self.gradInput) == 'table'
   scale = scale or 1

   if isTable then
      local offset = 1
      for i,module in ipairs(self.modules) do
         local currentOutput = module.output
         local currentGradInput = self:rethrowErrors(module, i, method, input,
                                                     gradOutput:narrow(self.dimension, offset, currentOutput:size(self.dimension)), scale)
         if torch.type(currentGradInput) ~= 'table' then
            error"currentGradInput is not a table!"
         end
         if #input ~= #currentGradInput then
            error("table size mismatch: "..#input.." ~= "..#currentGradInput)
         end
         if i == 1 then
            self.gradInput = wasTable and self.gradInput or {}
            retable(self.gradInput, currentGradInput,
                    function(t, k, v)
                       t[k] = t[k] or v:clone()
                       t[k]:resizeAs(v)
                       t[k]:copy(v)
                    end
            )
         else
            retable(self.gradInput, currentGradInput,
                    function(t, k, v)
                       if t[k] then
                          t[k]:add(v)
                       else
                          t[k] = v:clone()
                       end
                    end
            )
         end
         offset = offset + currentOutput:size(self.dimension)
      end
   else
      self.gradInput = (not wasTable) and self.gradInput:resizeAs(input) or input:clone()
      local offset = 1
      for i,module in ipairs(self.modules) do
         local currentOutput = module.output
         local currentGradInput = self:rethrowErrors(module, i, method, input,
                                                     gradOutput:narrow(self.dimension, offset, currentOutput:size(self.dimension)), scale)
         if currentGradInput then -- if the module does not produce a gradInput (for example first layer), then ignore it and move on.
            if i==1 then
               self.gradInput:copy(currentGradInput)
            else
               self.gradInput:add(currentGradInput)
            end
         end
         offset = offset + currentOutput:size(self.dimension)
      end
   end
   return self.gradInput
end

function Concat:updateGradInput(input, gradOutput)
   return backward(self, 'updateGradInput', input, gradOutput)
end

function Concat:backward(input, gradOutput, scale)
   return backward(self, 'backward', input, gradOutput, scale)
end

function Concat:accGradParameters(input, gradOutput, scale)
   scale = scale or 1
   local offset = 1
   for i,module in ipairs(self.modules) do
      local currentOutput = module.output
      self:rethrowErrors(module, i, 'accGradParameters', input,
          gradOutput:narrow(self.dimension, offset, currentOutput:size(self.dimension)),
          scale)
      offset = offset + currentOutput:size(self.dimension)
   end
end

function Concat:accUpdateGradParameters(input, gradOutput, lr)
   local offset = 1
   for i,module in ipairs(self.modules) do
      local currentOutput = module.output
      self:rethrowErrors(module, i, 'accUpdateGradParameters',
          input,
          gradOutput:narrow(self.dimension, offset, currentOutput:size(self.dimension)),
          lr)
      offset = offset + currentOutput:size(self.dimension)
   end
end

function Concat:__tostring__()
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
