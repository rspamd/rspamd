local SpatialFractionalMaxPooling, parent =
   torch.class('nn.SpatialFractionalMaxPooling', 'nn.Module')

-- Usage:
-- nn.SpatialFractionalMaxPooling(poolSizeW, poolSizeH, outW, outH)
--   the output should be the exact size (outH x outW)
-- nn.SpatialFractionalMaxPooling(poolSizeW, poolSizeH, ratioW, ratioH)
--   the output should be the size (floor(inH x ratioH) x floor(inW x ratioW))
--   ratios are numbers between (0, 1) exclusive
function SpatialFractionalMaxPooling:__init(poolSizeW, poolSizeH, arg1, arg2)
   parent.__init(self)
   assert(poolSizeW >= 2)
   assert(poolSizeH >= 2)

   -- Pool size (how wide the pooling for each output unit is)
   self.poolSizeW = poolSizeW
   self.poolSizeH = poolSizeH

   -- Random samples are drawn for all
   -- batch * plane * (height, width; i.e., 2) points. This determines
   -- the 2d "pseudorandom" overlapping pooling regions for each
   -- (batch element x input plane). A new set of random samples is
   -- drawn every updateOutput call, unless we disable it via
   -- :fixPoolingRegions().
   self.randomSamples = nil

   -- Flag to disable re-generation of random samples for producing
   -- a new pooling. For testing purposes
   self.newRandomPool = false

   if arg1 >= 1 and arg2 >= 1 then
      -- Desired output size: the input tensor will determine the reduction
      -- ratio
      self.outW = arg1
      self.outH = arg2
   else
      -- Reduction ratio specified per each input
      -- This is the reduction ratio that we use
      self.ratioW = arg1
      self.ratioH = arg2

      -- The reduction ratio must be between 0 and 1
      assert(self.ratioW > 0 and self.ratioW < 1)
      assert(self.ratioH > 0 and self.ratioH < 1)
   end
end

function SpatialFractionalMaxPooling:getBufferSize_(input)
   local batchSize = 0
   local planeSize = 0

   if input:nDimension() == 3 then
      batchSize = 1
      planeSize = input:size(1)
   elseif input:nDimension() == 4 then
      batchSize = input:size(1)
      planeSize = input:size(2)
   else
      error('input must be dim 3 or 4')
   end

   return torch.LongStorage({batchSize, planeSize, 2})
end

function SpatialFractionalMaxPooling:initSampleBuffer_(input)
   local sampleBufferSize = self:getBufferSize_(input)

   if self.randomSamples == nil then
      self.randomSamples = input.new():resize(sampleBufferSize):uniform()
   elseif (self.randomSamples:size(1) ~= sampleBufferSize[1] or
           self.randomSamples:size(2) ~= sampleBufferSize[2]) then
      self.randomSamples:resize(sampleBufferSize):uniform()
   else
      if not self.newRandomPool then
         -- Create new pooling windows, since this is a subsequent call
         self.randomSamples:uniform()
      end
   end
end

function SpatialFractionalMaxPooling:getOutputSizes_(input)
   local outW = self.outW
   local outH = self.outH
   if self.ratioW ~= nil and self.ratioH ~= nil then
      if input:nDimension() == 4 then
         outW = math.floor(input:size(4) * self.ratioW)
         outH = math.floor(input:size(3) * self.ratioH)
      elseif input:nDimension() == 3 then
         outW = math.floor(input:size(3) * self.ratioW)
         outH = math.floor(input:size(2) * self.ratioH)
      else
         error('input must be dim 3 or 4')
      end

      -- Neither can be smaller than 1
      assert(outW > 0, 'reduction ratio or input width too small')
      assert(outH > 0, 'reduction ratio or input height too small')
   else
      assert(outW ~= nil and outH ~= nil)
   end

   return outW, outH
end

-- Call this to turn off regeneration of random pooling regions each
-- updateOutput call.
function SpatialFractionalMaxPooling:fixPoolingRegions(val)
   if val == nil then
      val = true
   end

   self.newRandomPool = val
   return self
end

function SpatialFractionalMaxPooling:updateOutput(input)
   self.indices = self.indices or torch.LongTensor()
   if torch.typename(input):find('torch%.Cuda.*Tensor') then
      self.indices = torch.CudaLongTensor and self.indices:cudaLong() or self.indices
   else
      self.indices = self.indices:long()
   end
   self:initSampleBuffer_(input)
   local outW, outH = self:getOutputSizes_(input)

   input.THNN.SpatialFractionalMaxPooling_updateOutput(
      input:cdata(),
      self.output:cdata(),
      outW, outH, self.poolSizeW, self.poolSizeH,
      self.indices:cdata(), self.randomSamples:cdata())
   return self.output
end

function SpatialFractionalMaxPooling:updateGradInput(input, gradOutput)
   assert(self.randomSamples ~= nil,
          'must call updateOutput/forward first')

   local outW, outH = self:getOutputSizes_(input)

   input.THNN.SpatialFractionalMaxPooling_updateGradInput(
      input:cdata(),
      gradOutput:cdata(),
      self.gradInput:cdata(),
      outW, outH, self.poolSizeW, self.poolSizeH,
      self.indices:cdata())
   return self.gradInput
end

-- backward compat
function SpatialFractionalMaxPooling:empty()
   self:clearState()
end

function SpatialFractionalMaxPooling:clearState()
   self.indices = nil
   self.randomSamples = nil
   return parent.clearState(self)
end

function SpatialFractionalMaxPooling:__tostring__()
   return string.format('%s(%dx%d, %d,%d)', torch.type(self),
                        self.outW and self.outW or self.ratioW,
                        self.outH and self.outH or self.ratioH,
                        self.poolSizeW, self.poolSizeH)
end
