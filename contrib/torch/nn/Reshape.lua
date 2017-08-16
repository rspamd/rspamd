local Reshape, parent = torch.class('nn.Reshape', 'nn.Module')

function Reshape:__init(...)
   parent.__init(self)
   local arg = {...}

   self.size = torch.LongStorage()
   self.batchsize = torch.LongStorage()
   if torch.type(arg[#arg]) == 'boolean' then
      self.batchMode = arg[#arg]
      table.remove(arg, #arg)
   end
   local n = #arg
   if n == 1 and torch.typename(arg[1]) == 'torch.LongStorage' then
      self.size:resize(#arg[1]):copy(arg[1])
   else
      self.size:resize(n)
      for i=1,n do
         self.size[i] = arg[i]
      end
   end

   self.nelement = 1
   self.batchsize:resize(#self.size+1)
   for i=1,#self.size do
      self.nelement = self.nelement * self.size[i]
      self.batchsize[i+1] = self.size[i]
   end
end

function Reshape:updateOutput(input)
   if not input:isContiguous() then
      self._input = self._input or input.new()
      self._input:resizeAs(input)
      self._input:copy(input)
      input = self._input
   end

   if (self.batchMode == false) or (
         (self.batchMode == nil) and
         (input:nElement() == self.nelement and input:size(1) ~= 1)
      ) then
      self.output:view(input, self.size)
   else
      self.batchsize[1] = input:size(1)
      self.output:view(input, self.batchsize)
   end
   return self.output
end

function Reshape:updateGradInput(input, gradOutput)
   if not gradOutput:isContiguous() then
      self._gradOutput = self._gradOutput or gradOutput.new()
      self._gradOutput:resizeAs(gradOutput)
      self._gradOutput:copy(gradOutput)
      gradOutput = self._gradOutput
   end

   self.gradInput:viewAs(gradOutput, input)
   return self.gradInput
end


function Reshape:__tostring__()
  return torch.type(self) .. '(' ..
      table.concat(self.size:totable(), 'x') .. ')'
end

function Reshape:clearState()
   nn.utils.clear(self, '_input', '_gradOutput')
   return parent.clearState(self)
end
