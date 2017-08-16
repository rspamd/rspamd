local PixelShuffle, parent = torch.class("nn.PixelShuffle", "nn.Module")

-- Shuffles pixels after upscaling with a ESPCNN model
-- Converts a [batch x channel*r^2 x m x p] tensor to [batch x channel x r*m x r*p]
-- tensor, where r is the upscaling factor.
-- @param upscaleFactor - the upscaling factor to use
function PixelShuffle:__init(upscaleFactor)
   parent.__init(self)
   self.upscaleFactor = upscaleFactor
   self.upscaleFactorSquared = self.upscaleFactor * self.upscaleFactor
end

-- Computes the forward pass of the layer i.e. Converts a
-- [batch x channel*r^2 x m x p] tensor to [batch x channel x r*m x r*p] tensor.
-- @param input - the input tensor to be shuffled of size [b x c*r^2 x m x p]
-- @return output - the shuffled tensor of size [b x c x r*m x r*p]
function PixelShuffle:updateOutput(input)
   self._intermediateShape = self._intermediateShape or torch.LongStorage(6)
   self._outShape = self.outShape or torch.LongStorage()
   self._shuffleOut = self._shuffleOut or input.new()

   local batched = false
   local batchSize = 1
   local inputStartIdx = 1
   local outShapeIdx = 1
   if input:nDimension() == 4 then
      batched = true
      batchSize = input:size(1)
      inputStartIdx = 2
      outShapeIdx = 2
      self._outShape:resize(4)
      self._outShape[1] = batchSize
   else
      self._outShape:resize(3)
   end

   --input is of size h/r w/r, rc output should be h, r, c
   local channels = input:size(inputStartIdx) / self.upscaleFactorSquared
   local inHeight = input:size(inputStartIdx + 1)
   local inWidth = input:size(inputStartIdx + 2)

   self._intermediateShape[1] = batchSize
   self._intermediateShape[2] = channels
   self._intermediateShape[3] = self.upscaleFactor
   self._intermediateShape[4] = self.upscaleFactor
   self._intermediateShape[5] = inHeight
   self._intermediateShape[6] = inWidth

   self._outShape[outShapeIdx] = channels
   self._outShape[outShapeIdx + 1] = inHeight * self.upscaleFactor
   self._outShape[outShapeIdx + 2] = inWidth * self.upscaleFactor

   local inputView = torch.view(input, self._intermediateShape)

   self._shuffleOut:resize(inputView:size(1), inputView:size(2), inputView:size(5),
                           inputView:size(3), inputView:size(6), inputView:size(4))
   self._shuffleOut:copy(inputView:permute(1, 2, 5, 3, 6, 4))

   self.output = torch.view(self._shuffleOut, self._outShape)

   return self.output
end

-- Computes the backward pass of the layer, given the gradient w.r.t. the output
-- this function computes the gradient w.r.t. the input.
-- @param input - the input tensor of shape [b x c*r^2 x m x p]
-- @param gradOutput - the tensor with the gradients w.r.t. output of shape [b x c x r*m x r*p]
-- @return gradInput - a tensor of the same shape as input, representing the gradient w.r.t. input.
function PixelShuffle:updateGradInput(input, gradOutput)
   self._intermediateShape = self._intermediateShape or torch.LongStorage(6)
   self._shuffleIn = self._shuffleIn or input.new()

   local batchSize = 1
   local inputStartIdx = 1
   if input:nDimension() == 4 then
      batchSize = input:size(1)
      inputStartIdx = 2
   end

   local channels = input:size(inputStartIdx) / self.upscaleFactorSquared
   local height = input:size(inputStartIdx + 1)
   local width = input:size(inputStartIdx + 2)

   self._intermediateShape[1] = batchSize
   self._intermediateShape[2] = channels
   self._intermediateShape[3] = height
   self._intermediateShape[4] = self.upscaleFactor
   self._intermediateShape[5] = width
   self._intermediateShape[6] = self.upscaleFactor

   local gradOutputView = torch.view(gradOutput, self._intermediateShape)

   self._shuffleIn:resize(gradOutputView:size(1), gradOutputView:size(2), gradOutputView:size(4),
                          gradOutputView:size(6), gradOutputView:size(3), gradOutputView:size(5))
   self._shuffleIn:copy(gradOutputView:permute(1, 2, 4, 6, 3, 5))

   self.gradInput = torch.view(self._shuffleIn, input:size())

   return self.gradInput
end


function PixelShuffle:clearState()
   nn.utils.clear(self, {
      "_intermediateShape",
      "_outShape",
      "_shuffleIn",
      "_shuffleOut",
   })
   return parent.clearState(self)
end
