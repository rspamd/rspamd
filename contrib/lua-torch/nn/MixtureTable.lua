local MixtureTable, parent = torch.class('nn.MixtureTable', 'nn.Module')

function MixtureTable:__init(dim)
   parent.__init(self)
   self.dim = dim
   self.size = torch.LongStorage()
   self.batchSize = 0
   self.size2 = torch.LongStorage()
   self.backwardSetup = false
   self.gradInput = {}
end

function MixtureTable:updateOutput(input)
   local gaterInput, expertInputs = table.unpack(input)

   -- buffers
   self._gaterView = self._gaterView or input[1].new()
   self._expert = self._expert or input[1].new()
   self._expertView = self._expertView or input[1].new()

   self.dimG = 2
   local batchSize = gaterInput:size(1)
   if gaterInput:dim() < 2 then
      self.dimG = 1
      self.dim = self.dim or 1
      batchSize = 1
   end
   self.dim = self.dim or 2

   if self.table or torch.type(expertInputs) == 'table' then
      -- expertInputs is a Table :
      self.table = true
      if gaterInput:size(self.dimG) ~= #expertInputs then
         error"Should be one gater output per expert"
      end
      local expertInput = expertInputs[1]
      self.size:resize(expertInput:dim()+1):fill(1)
      if self.dimG > 1 then
         self.size[1] = gaterInput:size(1)
      end
      self.size[self.dim] = gaterInput:size(self.dimG)
      self.output:resizeAs(expertInput)
      self.batchSize = batchSize
      self._gaterView:view(gaterInput, self.size)
      self.output:zero()
      -- multiply accumulate gater outputs by their commensurate expert
      for i,expertInput in ipairs(expertInputs) do
         local gate = self._gaterView:select(self.dim,i):expandAs(expertInput)
         self.output:addcmul(expertInput, gate)
      end
   else
      -- expertInputs is a Tensor :
      self.size:resize(expertInputs:dim()):fill(1)
      if self.dimG > 1 then
         self.size[1] = gaterInput:size(1)
      end
      self.size[self.dim] = gaterInput:size(self.dimG)
      self.output:resizeAs(expertInputs:select(self.dim, 1))
      self.batchSize = batchSize
      self._gaterView:view(gaterInput, self.size)
      self._expert:cmul(self._gaterView:expandAs(expertInputs), expertInputs)
      self.output:sum(self._expert, self.dim)
      self.output:resizeAs(expertInputs:select(self.dim, 1))
   end

   return self.output
end

function MixtureTable:updateGradInput(input, gradOutput)
   local gaterInput, expertInputs = table.unpack(input)
   nn.utils.recursiveResizeAs(self.gradInput, input)
   local gaterGradInput, expertGradInputs = table.unpack(self.gradInput)

   -- buffers
   self._sum = self._sum or input[1].new()
   self._expertView2 = self._expertView2 or input[1].new()
   self._expert2 = self._expert2 or input[1].new()

   if self.table then
      for i,expertInput in ipairs(expertInputs) do
         local expertGradInput = expertGradInputs[i] or expertInput:clone()
         expertGradInput:resizeAs(expertInput)
         expertGradInputs[i] = expertGradInput
      end
      gaterGradInput:resizeAs(gaterInput)

      -- Clear invalid gradients
      if #expertGradInputs > #expertInputs then
         for i=#expertInputs+1, #expertGradInputs do
            expertGradInputs[i] = nil
         end
      end

      -- like CMulTable, but with broadcasting
      for i,expertGradInput in ipairs(expertGradInputs) do
         -- gater updateGradInput
         self._expert:cmul(gradOutput, expertInputs[i])
         if self.dimG == 1 then
            self._expertView:view(self._expert, -1)
         else
            self._expertView:view(self._expert, gradOutput:size(1), -1)
         end
         self._sum:sum(self._expertView, self.dimG)
         if self.dimG == 1 then
            gaterGradInput[i] = self._sum:select(self.dimG,1)
         else
            gaterGradInput:select(self.dimG,i):copy(self._sum:select(self.dimG,1))
         end

         -- expert updateGradInput
         local gate = self._gaterView:select(self.dim,i):expandAs(expertGradInput)
         expertGradInput:cmul(gate, gradOutput)
      end
   else
      self.size2:resize(expertInputs:dim())
      self.size2:copy(expertInputs:size())
      self.size2[self.dim] = 1
      gaterGradInput:resizeAs(gaterInput)

      -- gater updateGradInput
      self._expertView:view(gradOutput, self.size2)
      local gradOutput = self._expertView:expandAs(expertInputs)
      self._expert:cmul(gradOutput, expertInputs)
      local expert = self._expert:transpose(self.dim, self.dimG)
      if not expert:isContiguous() then
         self._expert2:resizeAs(expert)
         self._expert2:copy(expert)
         expert = self._expert2
      end
      if self.dimG == 1 then
         self._expertView2:view(expert, gaterInput:size(1), -1)
      else
         self._expertView2:view(expert, gaterInput:size(1), gaterInput:size(2), -1)
      end
      gaterGradInput:sum(self._expertView2, self.dimG+1)
      gaterGradInput:resizeAs(gaterInput)

      -- expert updateGradInput
      expertGradInputs:cmul(self._gaterView:expandAs(expertInputs), gradOutput)
   end

   return self.gradInput
end

function MixtureTable:type(type, tensorCache)
   self._gaterView = nil
   self._expert = nil
   self._expertView = nil
   self._sum = nil
   self._expert2 = nil
   self._expertView2 = nil
   return parent.type(self, type, tensorCache)
end

function MixtureTable:clearState()
   nn.utils.clear(self, {
     '_gaterView',
     '_expert',
     '_expertView',
     '_sum',
     '_expert2',
     '_expertView2',
   })
   return parent.clearState(self)
end
