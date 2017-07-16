------------------------------------------------------------------------
--[[ GPU ]]--
-- Decorates a module such that its parameters are
-- hosted on a specified GPU device.
-- The operations are also executed on that device.
-- Arguments input and gradOutput are converted to the specified device
-- before being fed to the decorated module.
-- Returned output is on the specified outdevice (defaults to device).
-- Returned gradInput is allocated on the same device as the input.
-- The unit test is located in cunn.
------------------------------------------------------------------------
local GPU, parent = torch.class("nn.GPU", "nn.Container")

function GPU:__init(module, device, outdevice)
   parent.__init(self)
   assert(torch.type(device) == 'number')
   self.device = device
   self.outdevice = outdevice or device

   assert(torch.isTypeOf(module, 'nn.Module'))
   self.modules[1] = module

   if module:type():find('torch%.Cuda.*Tensor') then
      self:type(module:type())
   end
end

function GPU.recursiveModuleDevice(obj, device)
   if type(obj) == 'table' and not torch.isTypeOf(obj, 'nn.GPU') and not obj.__noGPU__ then
      for k,v in pairs(obj) do
         obj[k] = GPU.recursiveModuleDevice(v, device)
      end
   elseif torch.type(obj):match('torch.Cuda.*Tensor') then
      if obj:getDevice() ~= device then
         obj = obj:clone() -- this will reallocate it to device
         local newdevice = obj:getDevice()
         -- when nElement() == 0 newdevice is 0
         assert(newdevice == device or newdevice == 0)
      end
   end
   assert(obj ~= nil)
   return obj
end

-- set the device of the decorated module
function GPU:setDevice(device)
   self.device = device or self.device

   assert(self.modules[1])
   self.modules[1] = cutorch.withDevice(self.device, function()
      return self.recursiveModuleDevice(self.modules[1], self.device)
   end)
   return self
end

-- when proto is a device number, returns a dst that has device device for each element in src
-- otherwise, if proto is a table/tensor, makes sure dst is a identical to src, yet on the same device as proto
function GPU.recursiveSetDevice(dst, src, proto)
   local device, prototable
   if torch.isTensor(proto) then
      device = proto:getDevice()
   elseif torch.type(proto) == 'number' then
      device = proto
   elseif torch.type(proto) == 'table' then
      prototable = true
   else
      error"Expecting number, table or tensor for arg 3 (proto)"
   end
   if torch.type(src) == 'table' then
      dst = torch.type(dst) == 'table' and dst or {}
      for k,v in ipairs(src) do
         dst[k] = GPU.recursiveSetDevice(dst[k], v, prototable and proto[k] or device)
      end
      for k=#src+1,#dst do
         dst[k] = nil
      end
   elseif torch.type(src):match('torch.Cuda.*Tensor') and src:getDevice() ~= device and src:getDevice() ~= 0 then
      if not (torch.type(dst):match('torch.Cuda.*Tensor') and dst:getDevice() == device) then
         dst = src.new()
      end
      cutorch.withDevice(device, function() dst:resizeAs(src):copy(src) end)
   else
      dst = src
   end
   return dst
end

function GPU:updateOutput(input)
   if self._type:find('torch%.Cuda.*Tensor') then
      self._input = self.recursiveSetDevice(self._input, input, self.device)

      local output = cutorch.withDevice(self.device, function()
         return self.modules[1]:updateOutput(self._input)
      end)

      if self.device ~= self.outdevice then
         self.output = self.recursiveSetDevice(self.output, output, self.outdevice)
      else
         self.output = output
      end
   else
      self.output = self.modules[1]:updateOutput(input)
   end

   return self.output
end

function GPU:updateGradInput(input, gradOutput)
   if self._type:find('torch%.Cuda.*Tensor') then
      self._gradOutput = self.recursiveSetDevice(self._gradOutput, gradOutput, self.device)

      local gradInput = cutorch.withDevice(self.device, function()
         return self.modules[1]:updateGradInput(self._input, self._gradOutput)
      end)

      self.gradInput = self.recursiveSetDevice(self.gradInput, gradInput, input)
   else
      self.gradInput = self.modules[1]:updateGradInput(input, gradOutput)
   end

   return self.gradInput
end

function GPU:accGradParameters(input, gradOutput, scale)
   if self._type:find('torch%.Cuda.*Tensor') then
      cutorch.withDevice(self.device, function()
         self.modules[1]:accGradParameters(self._input, self._gradOutput, scale)
      end)
   else
      self.modules[1]:accGradParameters(input, gradOutput, scale)
   end
end

function GPU:apply(callback)
   if self._type:find('torch%.Cuda.*Tensor') then
      cutorch.withDevice(self.device, function() parent.apply(self, callback) end)
   else
      parent.apply(self, callback)
   end
end

function GPU:type(type, typecache)
   if type and type:find('torch%.Cuda.*Tensor') then
      cutorch.withDevice(self.device, function() parent.type(self, type, typecache) end)
      self:setDevice()
   else
      self.output = nil
      self.gradInput = nil
      self._input = nil
      self._gradOutput = nil
      parent.type(self, type, typecache)
   end
   return self
end

function GPU:clearState()
   nn.utils.clear(self, 'output', 'gradInput')
   self._input = nil
   self._gradOutput = nil
   if self._type:find('torch%.Cuda.*Tensor') then
      cutorch.withDevice(self.device, function() parent.clearState(self) end)
   else
      parent.clearState(self)
   end
end

function GPU:zeroGradParameters()
   if self._type:find('torch%.Cuda.*Tensor') then
      cutorch.withDevice(self.device, function() parent.zeroGradParameters(self) end)
   else
      parent.zeroGradParameters(self)
   end
end

function GPU:updateParameters(lr)
   if self._type:find('torch%.Cuda.*Tensor') then
      cutorch.withDevice(self.device, function() parent.updateParameters(self, lr) end)
   else
      parent.updateParameters(self, lr)
   end
end

function GPU:training()
   if self._type:find('torch%.Cuda.*Tensor') then
      cutorch.withDevice(self.device, function() parent.training(self) end)
   else
      parent.training(self)
   end
end

function GPU:evaluate()
   if self._type:find('torch%.Cuda.*Tensor') then
      cutorch.withDevice(self.device, function() parent.evaluate(self) end)
   else
      parent.evaluate(self)
   end
end

function GPU:share(mlp, ...)
   local args = {...}
   if self._type:find('torch%.Cuda.*Tensor') then
      cutorch.withDevice(self.device, function() parent.share(self, mlp, unpack(args)) end)
   else
      parent.share(self, mlp, unpack(args))
   end
   return self
end

function GPU:reset(...)
   local args = {...}
   if self._type:find('torch%.Cuda.*Tensor') then
      cutorch.withDevice(self.device, function() parent.reset(self, unpack(args)) end)
   else
      parent.reset(self, unpack(args))
   end
   return self
end

function GPU:clone(...)
   local args = {...}
   if self._type:find('torch%.Cuda.*Tensor') then
      return cutorch.withDevice(self.device, function() parent.clone(self, unpack(args)) end)
   else
      return parent.clone(self, unpack(args))
   end
end

function GPU:write(file)
   -- Write all values in the object as a table.
   local object = {}
   for k, v in pairs(self) do
      object[k] = v
   end
   local header = {self._type, self.device}
   file:writeObject(header)
   file:writeObject(object)
end

function GPU:read(file)
   local header = file:readObject()
   local object
   if header[1] and header[1]:find('torch%.Cuda.*Tensor') then
      local device = header[2]
      if device > cutorch.getDeviceCount() then
         print"Warning : model was saved with more devices than available on current host."
         print"Attempting to load module onto device 1"
         device = 1
      end
      object = cutorch.withDevice(device, function() return file:readObject() end)
   else
      object = file:readObject()
   end

   for k, v in pairs(object) do
      self[k] = v
   end
end

function GPU:__tostring__()
   if self.modules[1].__tostring__ then
      return torch.type(self) .. '(' .. self.device ..') @ ' .. self.modules[1]:__tostring__()
   else
      return torch.type(self) .. '(' .. self.device ..') @ ' .. torch.type(self.modules[1])
   end
end

function GPU:accUpdateGradParameters(input, gradOutput, lr)
   error("Not Implemented for "..torch.type(self))
end

function GPU:sharedAccUpdateGradParameters(input, gradOutput, lr)
   error("Not Implemented for "..torch.type(self))
end
