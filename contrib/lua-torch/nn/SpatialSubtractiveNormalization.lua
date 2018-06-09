local SpatialSubtractiveNormalization, parent = torch.class('nn.SpatialSubtractiveNormalization','nn.Module')

function SpatialSubtractiveNormalization:__init(nInputPlane, kernel)
   parent.__init(self)

   -- get args
   self.nInputPlane = nInputPlane or 1
   self.kernel = kernel or torch.Tensor(9,9):fill(1)
   local kdim = self.kernel:nDimension()

   -- check args
   if kdim ~= 2 and kdim ~= 1 then
      error('<SpatialSubtractiveNormalization> averaging kernel must be 2D or 1D')
   end
   if (self.kernel:size(1) % 2) == 0 or (kdim == 2 and (self.kernel:size(2) % 2) == 0) then
      error('<SpatialSubtractiveNormalization> averaging kernel must have ODD dimensions')
   end

   -- normalize kernel
   self.kernel:div(self.kernel:sum() * self.nInputPlane)

   -- padding values
   local padH = math.floor(self.kernel:size(1)/2)
   local padW = padH
   if kdim == 2 then
      padW = math.floor(self.kernel:size(2)/2)
   end

   -- create convolutional mean extractor
   self.meanestimator = nn.Sequential()
   self.meanestimator:add(nn.SpatialZeroPadding(padW, padW, padH, padH))
   if kdim == 2 then
      self.meanestimator:add(nn.SpatialConvolution(self.nInputPlane, 1, self.kernel:size(2), self.kernel:size(1)))
   else
      self.meanestimator:add(nn.SpatialConvolutionMap(nn.tables.oneToOne(self.nInputPlane), self.kernel:size(1), 1))
      self.meanestimator:add(nn.SpatialConvolution(self.nInputPlane, 1, 1, self.kernel:size(1)))
   end
   self.meanestimator:add(nn.Replicate(self.nInputPlane,1,3))

   -- set kernel and bias
   if kdim == 2 then
      for i = 1,self.nInputPlane do
         self.meanestimator.modules[2].weight[1][i] = self.kernel
      end
      self.meanestimator.modules[2].bias:zero()
   else
      for i = 1,self.nInputPlane do
         self.meanestimator.modules[2].weight[i]:copy(self.kernel)
         self.meanestimator.modules[3].weight[1][i]:copy(self.kernel)
      end
      self.meanestimator.modules[2].bias:zero()
      self.meanestimator.modules[3].bias:zero()
   end

   -- other operation
   self.subtractor = nn.CSubTable()
   self.divider = nn.CDivTable()

   -- coefficient array, to adjust side effects
   self.coef = torch.Tensor(1,1,1)
end

function SpatialSubtractiveNormalization:updateOutput(input)
   -- compute side coefficients
   local dim = input:dim()
   if input:dim()+1 ~= self.coef:dim() or (input:size(dim) ~= self.coef:size(dim)) or (input:size(dim-1) ~= self.coef:size(dim-1)) then
      self.ones = self.ones or input.new()
      self._coef = self._coef or self.coef.new()
      if dim == 4 then
         -- batch mode
         self.ones:resizeAs(input[1]):fill(1)
         local coef = self.meanestimator:updateOutput(self.ones)
         self._coef:resizeAs(coef):copy(coef) -- make contiguous for view
         local size = coef:size():totable()
         table.insert(size,1,input:size(1))
         self.coef = self._coef:view(1,table.unpack(self._coef:size():totable())):expand(table.unpack(size))
      else
         self.ones:resizeAs(input):fill(1)
         local coef = self.meanestimator:updateOutput(self.ones)
         self._coef:resizeAs(coef):copy(coef) -- copy meanestimator.output as it will be used below
         self.coef = self._coef
      end

   end

   -- compute mean
   self.localsums = self.meanestimator:updateOutput(input)
   self.adjustedsums = self.divider:updateOutput{self.localsums, self.coef}
   self.output = self.subtractor:updateOutput{input, self.adjustedsums}

   -- done
   return self.output
end

function SpatialSubtractiveNormalization:updateGradInput(input, gradOutput)
   -- resize grad
   self.gradInput:resizeAs(input):zero()

   -- backprop through all modules
   local gradsub = self.subtractor:updateGradInput({input, self.adjustedsums}, gradOutput)
   local graddiv = self.divider:updateGradInput({self.localsums, self.coef}, gradsub[2])
   local size = self.meanestimator:updateGradInput(input, graddiv[1]):size()
   self.gradInput:add(self.meanestimator:updateGradInput(input, graddiv[1]))
   self.gradInput:add(gradsub[1])

   -- done
   return self.gradInput
end

function SpatialSubtractiveNormalization:clearState()
   if self.ones then self.ones:set() end
   if self._coef then self._coef:set() end
   self.meanestimator:clearState()
   return parent.clearState(self)
end
