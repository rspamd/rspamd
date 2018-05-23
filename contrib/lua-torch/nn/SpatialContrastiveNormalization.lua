local SpatialContrastiveNormalization, parent = torch.class('nn.SpatialContrastiveNormalization','nn.Module')

function SpatialContrastiveNormalization:__init(nInputPlane, kernel, threshold, thresval)
   parent.__init(self)

   -- get args
   self.nInputPlane = nInputPlane or 1
   self.kernel = kernel or torch.Tensor(9,9):fill(1)
   self.threshold = threshold or 1e-4
   self.thresval = thresval or threshold or 1e-4
   local kdim = self.kernel:nDimension()

   -- check args
   if kdim ~= 2 and kdim ~= 1 then
      error('<SpatialContrastiveNormalization> averaging kernel must be 2D or 1D')
   end
   if (self.kernel:size(1) % 2) == 0 or (kdim == 2 and (self.kernel:size(2) % 2) == 0) then
      error('<SpatialContrastiveNormalization> averaging kernel must have ODD dimensions')
   end

   -- instantiate sub+div normalization
   self.normalizer = nn.Sequential()
   self.normalizer:add(nn.SpatialSubtractiveNormalization(self.nInputPlane, self.kernel))
   self.normalizer:add(nn.SpatialDivisiveNormalization(self.nInputPlane, self.kernel,
                                                       self.threshold, self.thresval))
end

function SpatialContrastiveNormalization:updateOutput(input)
   self.output = self.normalizer:forward(input)
   return self.output
end

function SpatialContrastiveNormalization:updateGradInput(input, gradOutput)
   self.gradInput = self.normalizer:backward(input, gradOutput)
   return self.gradInput
end
