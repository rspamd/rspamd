local ConcatTable, parent = torch.class('nn.ConcatTable', 'nn.Container')

function ConcatTable:__init()
   parent.__init(self)
   self.modules = {}
   self.output = {}
end

function ConcatTable:updateOutput(input)
   for i=1,#self.modules do
      self.output[i] = self:rethrowErrors(self.modules[i], i, 'updateOutput', input)
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
   if isTable then
      for i,module in ipairs(self.modules) do
         local currentGradInput = self:rethrowErrors(module, i, method, input, gradOutput[i], scale)
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
                  t[k]:resize(v:size())
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
      end
   else
      self.gradInput = (not wasTable) and self.gradInput or input:clone()
      for i,module in ipairs(self.modules) do
         local currentGradInput = self:rethrowErrors(module, i, method, input, gradOutput[i], scale)
         if i == 1 then
            self.gradInput:resize(currentGradInput:size()):copy(currentGradInput)
         else
            self.gradInput:add(currentGradInput)
         end
      end
   end
   return self.gradInput
end

function ConcatTable:updateGradInput(input, gradOutput)
   return backward(self, 'updateGradInput', input, gradOutput)
end

function ConcatTable:backward(input, gradOutput, scale)
   return backward(self, 'backward', input, gradOutput, scale)
end

function ConcatTable:accGradParameters(input, gradOutput, scale)
   scale = scale or 1
   for i,module in ipairs(self.modules) do
      self:rethrowErrors(module, i, 'accGradParameters', input, gradOutput[i], scale)
   end
end

function ConcatTable:accUpdateGradParameters(input, gradOutput, lr)
   for i,module in ipairs(self.modules) do
      self:rethrowErrors(module, i, 'accUpdateGradParameters', input, gradOutput[i], lr)
   end
end

function ConcatTable:__tostring__()
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
