
local SparseTensor = torch.class("torch.SparseTensor")

function SparseTensor:__init(keys, values)
   if keys and values then
      assert(torch.typename(keys):find('torch%..*LongTensor'))
      assert(torch.isTensor(values))
      assert(keys:nElement() == values:nElement(), "Expecting key and value tensors of same size")
      self.keys = keys
      self.values = values
   elseif not (keys or values) then
      self.keys = torch.LongTensor()
      self.values = torch.Tensor()
   else
      error"Expecting zero or two args"
   end
end

function SparseTensor:buildIndex(overwrite)
   if self._map and not overwrite then return end
   assert(self.keys and self.keys:dim() == 1)
   assert(self.values and self.values:dim() == 1)
   -- hash table
   self._map = {}
   for i=1,self.keys:size(1) do
      self._map[self.keys[i]] = i
   end
end

function SparseTensor:deleteIndex()
   self._map = nil
end

local __index = SparseTensor.__index
function SparseTensor:__index(key)
   if key == nil then
      error"Attempt to index using a nil key"
   elseif torch.type(key) ~= 'number' then
      return __index(self, key)
   end

   if self._map then
      assert(torch.type(self._map) == 'table')
      local idx = self._map[key]
      return idx and self.values[idx] or nil
   elseif self.keys:nElement() > 0 then
      for i=1,self.keys:size(1) do
         if self.keys[i] == key then
            return self.values[i]
         end
      end
   end
   return nil
end