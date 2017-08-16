local Module = torch.class('nn.Module')

function Module:__init()
   self.gradInput = torch.Tensor()
   self.output = torch.Tensor()
   self._type = self.output:type()
end

function Module:parameters()
   if self.weight and self.bias then
      return {self.weight, self.bias}, {self.gradWeight, self.gradBias}
   elseif self.weight then
      return {self.weight}, {self.gradWeight}
   elseif self.bias then
      return {self.bias}, {self.gradBias}
   else
      return
   end
end

function Module:updateOutput(input)
   return self.output
end

function Module:forward(input)
   return self:updateOutput(input)
end

function Module:backward(input, gradOutput, scale)
   scale = scale or 1
   self:updateGradInput(input, gradOutput)
   self:accGradParameters(input, gradOutput, scale)
   return self.gradInput
end

function Module:backwardUpdate(input, gradOutput, lr)
   self:updateGradInput(input, gradOutput)
   self:accUpdateGradParameters(input, gradOutput, lr)
   return self.gradInput
end

function Module:updateGradInput(input, gradOutput)
   return self.gradInput
end

function Module:accGradParameters(input, gradOutput, scale)
end

function Module:accUpdateGradParameters(input, gradOutput, lr)
   if self.shared then
      self:sharedAccUpdateGradParameters(input, gradOutput, lr)
   else
      self:defaultAccUpdateGradParameters(input, gradOutput, lr)
   end
end

function Module:defaultAccUpdateGradParameters(input, gradOutput, lr)
   local gradWeight = self.gradWeight
   local gradBias = self.gradBias
   self.gradWeight = self.weight
   self.gradBias = self.bias
   self:accGradParameters(input, gradOutput, -lr)
   self.gradWeight = gradWeight
   self.gradBias = gradBias
end

function Module:sharedAccUpdateGradParameters(input, gradOutput, lr)
   if self:parameters() then
      self:zeroGradParameters()
      self:accGradParameters(input, gradOutput, 1)
      self:updateParameters(lr)
   end
end

function Module:zeroGradParameters()
   local _,gradParams = self:parameters()
   if gradParams then
      for i=1,#gradParams do
         gradParams[i]:zero()
      end
   end
end

function Module:updateParameters(learningRate)
   local params, gradParams = self:parameters()
   if params then
      for i=1,#params do
         params[i]:add(-learningRate, gradParams[i])
      end
   end
end

function Module:training()
   self.train = true
end

function Module:evaluate()
   self.train = false
end

function Module:share(mlp, ...)
   local arg = {...}
   for i,v in ipairs(arg) do
      if self[v] ~= nil then
         self[v]:set(mlp[v])
         self.shared = true
         mlp.shared = true
      end
   end
   return self
end

local function sharedWrite(...)
   local arg = {...}
   local shared = {}
   for i,v in ipairs(arg) do
       shared[v] = true
   end
   return function(self, file)
      local object = {}
      for k, v in pairs(self) do
         if shared[k] then
            assert(torch.isTensor(v), 'Shared parameters have to be Tensors')
            object[k] = v.new()
         else
            object[k] = v
         end
      end
      file:writeObject(object)
   end
end

function Module:clone(...)
   local oldWrite = nn.Module.write
   nn.Module.write = sharedWrite(...)

   local f = torch.MemoryFile("rw"):binary()
   f:writeObject(self)
   f:seek(1)
   local clone = f:readObject()
   f:close()

   nn.Module.write = oldWrite

   if select('#',...) > 0 then
      clone:share(self,...)
   end
   return clone
end

function Module:type(type, tensorCache)
   if not type then
      return self._type
   end

   tensorCache = tensorCache or {}

   -- find all tensors and convert them
   for key,param in pairs(self) do
      self[key] = nn.utils.recursiveType(param, type, tensorCache)
   end

   self._type = type
   return self
end

function Module:float(...)
   return self:type('torch.FloatTensor',...)
end

function Module:double(...)
   return self:type('torch.DoubleTensor',...)
end

function Module:cuda(...)
   return self:type('torch.CudaTensor',...)
end

function Module:reset()
end

function Module:write(file)
  -- Write all values in the object as a table.
  local object = {}
  for k, v in pairs(self) do
    object[k] = v
  end
  file:writeObject(object)
end

function Module:read(file)
  local object = file:readObject()
  for k, v in pairs(object) do
    self[k] = v
  end
end

-- This function is not easy to understand. It works as follows:
--
-- - gather all parameter tensors for this module (and children);
--   count all parameter values (floats)
-- - create one ginormous memory area (Storage object) with room for all
--   parameters
-- - remap each parameter tensor to point to an area within the ginormous
--   Storage, and copy it there
--
-- It has the effect of making all parameters point to the same memory area,
-- which is then returned.
--
-- The purpose is to allow operations over all parameters (such as momentum
-- updates and serialization), but it assumes that all parameters are of
-- the same type (and, in the case of CUDA, on the same device), which
-- is not always true. Use for_each() to iterate over this module and
-- children instead.
--
-- Module._flattenTensorBuffer can be used by other packages (e.g. cunn)
-- to specify the type of temporary buffers. For example, the temporary
-- buffers for CudaTensor could be FloatTensor, to avoid GPU memory usage.
--
-- TODO: This logically belongs to torch.Tensor, not nn.
Module._flattenTensorBuffer = {}
function Module.flatten(parameters)

   -- returns true if tensor occupies a contiguous region of memory (no holes)
   local function isCompact(tensor)
      local sortedStride, perm = torch.sort(
            torch.LongTensor(tensor:nDimension()):set(tensor:stride()), 1, true)
      local sortedSize = torch.LongTensor(tensor:nDimension()):set(
            tensor:size()):index(1, perm)
      local nRealDim = torch.clamp(sortedStride, 0, 1):sum()
      sortedStride = sortedStride:narrow(1, 1, nRealDim):clone()
      sortedSize   = sortedSize:narrow(1, 1, nRealDim):clone()
      local t = tensor.new():set(tensor:storage(), 1,
                                 sortedSize:storage(),
                                 sortedStride:storage())
      return t:isContiguous()
   end

   if not parameters or #parameters == 0 then
      return torch.Tensor()
   end
   local Tensor = parameters[1].new
   local TmpTensor = Module._flattenTensorBuffer[torch.type(parameters[1])] or Tensor

   -- 1. construct the set of all unique storages referenced by parameter tensors
   local storages = {}
   local nParameters = 0
   local parameterMeta = {}
   for k = 1,#parameters do
      local param = parameters[k]
      local storage = parameters[k]:storage()
      local storageKey = torch.pointer(storage)

      if not storages[storageKey] then
         storages[storageKey] = {storage, nParameters}
         nParameters = nParameters + storage:size()
      end

      parameterMeta[k] = {storageOffset = param:storageOffset() +
                                          storages[storageKey][2],
                          size          = param:size(),
                          stride        = param:stride()}
   end

   -- 2. construct a single tensor that will hold all the parameters
   local flatParameters = TmpTensor(nParameters):zero()

   -- 3. determine if there are elements in the storage that none of the
   --    parameter tensors reference ('holes')
   local tensorsCompact = true
   for k = 1,#parameters do
      local meta = parameterMeta[k]
      local tmp = TmpTensor():set(
         flatParameters:storage(), meta.storageOffset, meta.size, meta.stride)
      tmp:fill(1)
      tensorsCompact = tensorsCompact and isCompact(tmp)
   end

   local maskParameters  = flatParameters:byte():clone()
   local compactOffsets  = flatParameters:long():cumsum(1)
   local nUsedParameters = compactOffsets[-1]

   -- 4. copy storages into the flattened parameter tensor
   for _, storageAndOffset in pairs(storages) do
      local storage, offset = table.unpack(storageAndOffset)
      flatParameters[{{offset+1,offset+storage:size()}}]:copy(Tensor():set(storage))
   end

   -- 5. allow garbage collection
   storages = nil
   for k = 1,#parameters do
       parameters[k]:set(Tensor())
   end

   -- 6. compact the flattened parameters if there were holes
   if nUsedParameters ~= nParameters then
      assert(tensorsCompact,
         "Cannot gather tensors that are not compact")

      flatParameters = TmpTensor(nUsedParameters):copy(
            flatParameters:maskedSelect(maskParameters))
      for k = 1,#parameters do
        parameterMeta[k].storageOffset =
              compactOffsets[parameterMeta[k].storageOffset]
      end
   end

   if TmpTensor ~= Tensor then
      flatParameters = Tensor(flatParameters:nElement()):copy(flatParameters)
   end

   -- 7. fix up the parameter tensors to point at the flattened parameters
   for k = 1,#parameters do
      parameters[k]:set(flatParameters:storage(),
          parameterMeta[k].storageOffset,
          parameterMeta[k].size,
          parameterMeta[k].stride)
   end

   return flatParameters
end

function Module:getParameters()
   -- get parameters
   local parameters,gradParameters = self:parameters()
   local p, g = Module.flatten(parameters), Module.flatten(gradParameters)
   assert(p:nElement() == g:nElement(),
      'check that you are sharing parameters and gradParameters')
   if parameters then
      for i=1,#parameters do
         assert(parameters[i]:storageOffset() == gradParameters[i]:storageOffset(),
            'misaligned parameter at ' .. tostring(i))
      end
   end
   return p, g
end

function Module:__call__(input, gradOutput)
   self:forward(input)
   if gradOutput then
      self:backward(input, gradOutput)
      return self.output, self.gradInput
   else
      return self.output
   end
end

-- Run a callback (called with the module as an argument) in preorder over this
-- module and its children.
--
function Module:apply(callback)
    callback(self)

    if self.modules then
        for _, module in ipairs(self.modules) do
            module:apply(callback)
        end
    end
end

function Module:findModules(typename, container)
  container = container or self
  local nodes = {}
  local containers = {}
  local mod_type = torch.typename(self)
  if mod_type == typename then
    nodes[#nodes+1] = self
    containers[#containers+1] = container
  end
  -- Recurse on nodes with 'modules'
  if (self.modules ~= nil) then
    if (torch.type(self.modules) == 'table') then
      for i = 1, #self.modules do
        local child = self.modules[i]
        local cur_nodes, cur_containers =
          child:findModules(typename, self)
        assert(#cur_nodes == #cur_containers,
          'Internal error: incorrect return length')  -- This shouldn't happen
        -- add the list items from our child to our list (ie return a
        -- flattened table of the return nodes).
        for j = 1, #cur_nodes do
          nodes[#nodes+1] = cur_nodes[j]
          containers[#containers+1] = cur_containers[j]
        end
      end
    end
  end
  return nodes, containers
end

-- returns a list of modules
function Module:listModules()
   local function tinsert(to, from)
      if torch.type(from) == 'table' then
         for i=1,#from do
            tinsert(to,from[i])
         end
      else
         table.insert(to,from)
      end
   end
   -- include self first
   local modules = {self}
   if self.modules then
      for i=1,#self.modules do
         local modulas = self.modules[i]:listModules()
         if modulas then
            tinsert(modules,modulas)
         end
      end
   end
   return modules
end

function Module:clearState()
   return nn.utils.clear(self, 'output', 'gradInput')
end

-- similar to apply, recursively goes over network and calls
-- a callback function which returns a new module replacing the old one
function nn.Module:replace(callback)
   local out = callback(self)
   if self.modules then
      for i, module in ipairs(self.modules) do
         self.modules[i] = module:replace(callback)
      end
   end
   return out
end
