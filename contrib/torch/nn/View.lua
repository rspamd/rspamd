local View, parent = torch.class('nn.View', 'nn.Module')

function View:resetSize(...)
   if select('#', ...) == 1 and torch.typename(select(1, ...)) == 'torch.LongStorage' then
      self.size = select(1, ...)
   else
      self.size = torch.LongStorage({...})
   end

   self.numElements = 1
   local inferdim = false
   for i = 1,#self.size do
      local szi = self.size[i]
      if szi >= 0 then
         self.numElements = self.numElements * self.size[i]
      else
         assert(szi == -1, 'size should be positive or -1')
         assert(not inferdim, 'only one dimension can be at -1')
         inferdim = true
      end
   end

   return self
end

function View:__init(...)
   parent.__init(self)
   self:resetSize(...)
   self.numInputDims = nil
end

function View:setNumInputDims(numInputDims)
   self.numInputDims = numInputDims
   return self
end

local function batchsize(input, size, numInputDims, numElements)
   local ind = input:nDimension()
   local isz = input:size()
   local maxdim = numInputDims and numInputDims or ind
   local ine = 1
   for i=ind,ind-maxdim+1,-1 do
      ine = ine * isz[i]
   end

   if ine % numElements ~= 0 then
      error(string.format(
               'input view (%s) and desired view (%s) do not match',
               table.concat(input:size():totable(), 'x'),
               table.concat(size:totable(), 'x')))
   end

   -- the remainder is either the batch...
   local bsz = ine / numElements

   -- ... or the missing size dim
   for i=1,size:size() do
      if size[i] == -1 then
         bsz = 1
         break
      end
   end

   -- for dim over maxdim, it is definitively the batch
   for i=ind-maxdim,1,-1 do
      bsz = bsz * isz[i]
   end

   -- special card
   if bsz == 1 and (not numInputDims or input:nDimension() <= numInputDims) then
      return
   end

   return bsz
end

function View:updateOutput(input)
   self.output = self.output or input.new()
   local bsz = batchsize(input, self.size, self.numInputDims, self.numElements)
   if bsz then
      self.output:view(input, bsz, table.unpack(self.size:totable()))
   else
      self.output:view(input, self.size)
   end
   return self.output
end

function View:updateGradInput(input, gradOutput)
   self.gradInput = self.gradInput or gradOutput.new()
   self.gradInput:view(gradOutput, input:size())
   return self.gradInput
end

function View:__tostring__()
   return torch.type(self)..'('..table.concat(self.size:totable(), ', ')..')'
end
