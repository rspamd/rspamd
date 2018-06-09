local S2D, parent = torch.class("nn.Sparse2Dense", "nn.Module")
local dt = require 'decisiontree._env'

function S2D:__init(features)
   parent.__init(self)
   if torch.type(features) == 'table' then
      assert(#features > 0)
      features = torch.LongTensor(features)
   end
   assert(torch.isTensor(features))
   self.features = features
   self.featureMap = nil
   self.masks = {}
   self.mappedKeys = {}
end

function S2D:updateOutput(input)
   if not self.featureMap then
      self.featureMap = dt.HashMap()
      self.featureMap:fill(self.features)
   end
   local batched, keys, values
   if torch.isTensor(input[1]) then
      keys = {input[1]}
      values = {input[2]}
      batched = false
   else
      keys = input[1]
      values = input[2]
      batched = true
   end
   assert(#keys == #values)

   local masks = self.masks
   local mappedKeys = self.mappedKeys
   local nKeys = #keys
   local nMasks = #masks
   if nMasks < nKeys then
      for i=nMasks+1,nKeys do
         masks[i] = torch.ByteTensor()
         mappedKeys[i] = torch.LongTensor()
      end
   elseif nMasks > nKeys then
      for i=nKeys+1,nMasks do
         masks[i] = nil
         mappedKeys[i] = nil
      end
   end

   self.featureMap:get(keys, mappedKeys, masks)
   self.output = self.output or torch.Tensor():type(self._type)
   self.output.nn.S2D_computeOutput(self.output, mappedKeys, values, masks, self.features)
   if not batched then
      self.output = self.output:view(-1)
   end
   return self.output
end

function S2D:type(type, tensorCache)
   if type then
      local features = self.features
      self.features = nil
      parent.type(self, type, tensorCache)
      self.features = features
      return self
   else
      return parent.type(self)
   end
end

function S2D:updateGradInput(input, gradOutput)
   error"Not Implemented"
end

function S2D:reset()
   parent.reset(self)
   self.featureMap = nil
end

function S2D:write(file)
   self.featureMap = nil
   parent.write(self, file)
end

function S2D:read(file)
   self.featureMap = nil
   parent.read(self, file)
end
