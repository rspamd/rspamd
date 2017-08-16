local SpatialDivisiveNormalization, parent = torch.class('nn.SpatialDivisiveNormalization','nn.Module')

function SpatialDivisiveNormalization:__init(nInputPlane, kernel, threshold, thresval)
   parent.__init(self)

   -- get args
   self.nInputPlane = nInputPlane or 1
   self.kernel = kernel or torch.Tensor(9,9):fill(1)
   self.threshold = threshold or 1e-4
   self.thresval = thresval or threshold or 1e-4
   local kdim = self.kernel:nDimension()

   -- check args
   if kdim ~= 2 and kdim ~= 1 then
      error('<SpatialDivisiveNormalization> averaging kernel must be 2D or 1D')
   end
   if (self.kernel:size(1) % 2) == 0 or (kdim == 2 and (self.kernel:size(2) % 2) == 0) then
      error('<SpatialDivisiveNormalization> averaging kernel must have ODD dimensions')
   end

   -- padding values
   local padH = math.floor(self.kernel:size(1)/2)
   local padW = padH
   if kdim == 2 then
      padW = math.floor(self.kernel:size(2)/2)
   end

   -- create convolutional mean estimator
   self.meanestimator = nn.Sequential()
   self.meanestimator:add(nn.SpatialZeroPadding(padW, padW, padH, padH))
   if kdim == 2 then
      self.meanestimator:add(nn.SpatialConvolution(self.nInputPlane, 1, self.kernel:size(2), self.kernel:size(1)))
   else
      self.meanestimator:add(nn.SpatialConvolutionMap(nn.tables.oneToOne(self.nInputPlane), self.kernel:size(1), 1))
      self.meanestimator:add(nn.SpatialConvolution(self.nInputPlane, 1, 1, self.kernel:size(1)))
   end
   self.meanestimator:add(nn.Replicate(self.nInputPlane,1,3))

   -- create convolutional std estimator
   self.stdestimator = nn.Sequential()
   self.stdestimator:add(nn.Square())
   self.stdestimator:add(nn.SpatialZeroPadding(padW, padW, padH, padH))
   if kdim == 2 then
      self.stdestimator:add(nn.SpatialConvolution(self.nInputPlane, 1, self.kernel:size(2), self.kernel:size(1)))
   else
      self.stdestimator:add(nn.SpatialConvolutionMap(nn.tables.oneToOne(self.nInputPlane), self.kernel:size(1), 1))
      self.stdestimator:add(nn.SpatialConvolution(self.nInputPlane, 1, 1, self.kernel:size(1)))
   end
   self.stdestimator:add(nn.Replicate(self.nInputPlane,1,3))
   self.stdestimator:add(nn.Sqrt())

   -- set kernel and bias
   if kdim == 2 then
      self.kernel:div(self.kernel:sum() * self.nInputPlane)
      for i = 1,self.nInputPlane do
         self.meanestimator.modules[2].weight[1][i] = self.kernel
         self.stdestimator.modules[3].weight[1][i] = self.kernel
      end
      self.meanestimator.modules[2].bias:zero()
      self.stdestimator.modules[3].bias:zero()
   else
      self.kernel:div(self.kernel:sum() * math.sqrt(self.nInputPlane))
      for i = 1,self.nInputPlane do
         self.meanestimator.modules[2].weight[i]:copy(self.kernel)
         self.meanestimator.modules[3].weight[1][i]:copy(self.kernel)
         self.stdestimator.modules[3].weight[i]:copy(self.kernel)
         self.stdestimator.modules[4].weight[1][i]:copy(self.kernel)
      end
      self.meanestimator.modules[2].bias:zero()
      self.meanestimator.modules[3].bias:zero()
      self.stdestimator.modules[3].bias:zero()
      self.stdestimator.modules[4].bias:zero()
   end

   -- other operation
   self.normalizer = nn.CDivTable()
   self.divider = nn.CDivTable()
   self.thresholder = nn.Threshold(self.threshold, self.thresval)

   -- coefficient array, to adjust side effects
   self.coef = torch.Tensor(1,1,1)
end

function SpatialDivisiveNormalization:updateOutput(input)

   self.localstds = self.stdestimator:updateOutput(input)

   -- compute side coefficients
   local dim = input:dim()
   if self.localstds:dim() ~= self.coef:dim() or (input:size(dim) ~= self.coef:size(dim)) or (input:size(dim-1) ~= self.coef:size(dim-1)) then
      self.ones = self.ones or input.new()
      if dim == 4 then
         -- batch mode
         self.ones:resizeAs(input[1]):fill(1)
         local coef = self.meanestimator:updateOutput(self.ones)
         self._coef = self._coef or input.new()
         self._coef:resizeAs(coef):copy(coef) -- make contiguous for view
         self.coef = self._coef:view(1,table.unpack(self._coef:size():totable())):expandAs(self.localstds)
      else
         self.ones:resizeAs(input):fill(1)
         self.coef = self.meanestimator:updateOutput(self.ones)
      end

   end

   -- normalize std dev
   self.adjustedstds = self.divider:updateOutput{self.localstds, self.coef}
   self.thresholdedstds = self.thresholder:updateOutput(self.adjustedstds)
   self.output = self.normalizer:updateOutput{input, self.thresholdedstds}

   -- done
   return self.output
end

function SpatialDivisiveNormalization:updateGradInput(input, gradOutput)
   -- resize grad
   self.gradInput:resizeAs(input):zero()

   -- backprop through all modules
   local gradnorm = self.normalizer:updateGradInput({input, self.thresholdedstds}, gradOutput)
   local gradadj = self.thresholder:updateGradInput(self.adjustedstds, gradnorm[2])
   local graddiv = self.divider:updateGradInput({self.localstds, self.coef}, gradadj)
   self.gradInput:add(self.stdestimator:updateGradInput(input, graddiv[1]))
   self.gradInput:add(gradnorm[1])

   -- done
   return self.gradInput
end

function SpatialDivisiveNormalization:clearState()
   if self.ones then self.ones:set() end
   if self._coef then self._coef:set() end
   self.meanestimator:clearState()
   self.stdestimator:clearState()
   return parent.clearState(self)
end
