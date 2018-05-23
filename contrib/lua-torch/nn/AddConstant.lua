local AddConstant, parent = torch.class('nn.AddConstant', 'nn.Module')

function AddConstant:__init(constant_scalar,ip)
   parent.__init(self)
   self.constant_scalar = constant_scalar

  -- default for inplace is false
   self.inplace = ip or false
   if (ip and type(ip) ~= 'boolean') then
      error('in-place flag must be boolean')
   end
end

function AddConstant:updateOutput(input)
   assert(type(self.constant_scalar) == 'number' or
      (torch.isTensor(self.constant_scalar) and input:nDimension() <= 2 and
      input:size(input:nDimension()) == self.constant_scalar:size(1)),
      'input is not scalar or doesn\'t match with the dimension of constant!')
   local tmp
   if torch.isTensor(self.constant_scalar) and input:nDimension() == 2 then
      local nOutput = self.constant_scalar:size(1)
      tmp = self.constant_scalar.new()
      tmp:resize(1,nOutput)
      tmp:copy(self.constant_scalar)
      tmp = tmp:expand(input:size(1),nOutput)
   else
      tmp = self.constant_scalar
   end
   if self.inplace then
      input:add(tmp)
      self.output:set(input)
   else
      self.output:resizeAs(input)
      self.output:copy(input)
      self.output:add(tmp)
   end
   return self.output
end

function AddConstant:updateGradInput(input, gradOutput)
   if self.inplace then
      self.gradInput:set(gradOutput)
      -- restore previous input value
      input:add(-self.constant_scalar)
   else
      self.gradInput:resizeAs(gradOutput)
      self.gradInput:copy(gradOutput)
   end
   return self.gradInput
end
