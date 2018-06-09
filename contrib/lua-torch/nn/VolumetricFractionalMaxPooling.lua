local VolumetricFractionalMaxPooling, parent =
   torch.class('nn.VolumetricFractionalMaxPooling', 'nn.Module')

-- Usage:
-- nn.VolumetricFractionalMaxPooling(poolSizeT, poolSizeW, poolSizeH, outT, outW, outH)
--   the output should be the exact size (outT x outH x outW)
-- nn.VolumetricFractionalMaxPooling(poolSizeT, poolSizeW, poolSizeH, ratioT, ratioW, ratioH)
--   the output should be the size (floor(inT x ratioT) x floor(inH x ratioH) x floor(inW x ratioW))
--   ratios are numbers between (0, 1) exclusive
function VolumetricFractionalMaxPooling:__init(poolSizeT, poolSizeW, poolSizeH, arg1, arg2, arg3)
   parent.__init(self)
   assert(poolSizeT >= 2)
   assert(poolSizeW >= 2)
   assert(poolSizeH >= 2)

   -- Pool size (how wide the pooling for each output unit is)
   self.poolSizeT = poolSizeT
   self.poolSizeW = poolSizeW
   self.poolSizeH = poolSizeH

   -- Random samples are drawn for all
   -- batch * plane * (time, height, width; i.e., 3) points. This determines
   -- the 3d "pseudorandom" overlapping pooling regions for each
   -- (batch element x input plane). A new set of random samples is
   -- drawn every updateOutput call, unless we disable it via
   -- :fixPoolingRegions().
   self.randomSamples = nil

   -- Flag to disable re-generation of random samples for producing
   -- a new pooling. For testing purposes
   self.newRandomPool = false

   if arg1 >= 1 and arg2 >= 1 and arg3 >= 1 then
      -- Desired output size: the input tensor will determine the reduction
      -- ratio
      self.outT = arg1
      self.outW = arg2
      self.outH = arg3
   else
      -- Reduction ratio specified per each input
      -- This is the reduction ratio that we use
      self.ratioT = arg1
      self.ratioW = arg2
      self.ratioH = arg3

      -- The reduction ratio must be between 0 and 1
      assert(self.ratioT > 0 and self.ratioT < 1)
      assert(self.ratioW > 0 and self.ratioW < 1)
      assert(self.ratioH > 0 and self.ratioH < 1)
   end
end

function VolumetricFractionalMaxPooling:getBufferSize_(input)
   local batchSize = 0
   local planeSize = 0

   if input:nDimension() == 4 then
      batchSize = 1
      planeSize = input:size(1)
   elseif input:nDimension() == 5 then
      batchSize = input:size(1)
      planeSize = input:size(2)
   else
      error('input must be dim 4 or 5')
   end

   return torch.LongStorage({batchSize, planeSize, 3})
end

function VolumetricFractionalMaxPooling:initSampleBuffer_(input)
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

function VolumetricFractionalMaxPooling:getOutputSizes_(input)
   local outT = self.outT
   local outW = self.outW
   local outH = self.outH
   if self.ratioW ~= nil and self.ratioH ~= nil then
      if input:nDimension() == 5 then
         outT = math.floor(input:size(5) * self.ratioT)
         outW = math.floor(input:size(4) * self.ratioW)
         outH = math.floor(input:size(3) * self.ratioH)
      elseif input:nDimension() == 4 then
         outT = math.floor(input:size(4) * self.ratioT)
         outW = math.floor(input:size(3) * self.ratioW)
         outH = math.floor(input:size(2) * self.ratioH)
      else
         error('input must be dim 4 or 5')
      end

      -- Neither can be smaller than 1
      assert(outT > 0, 'reduction ratio or input time too small')
      assert(outW > 0, 'reduction ratio or input width too small')
      assert(outH > 0, 'reduction ratio or input height too small')
   else
      assert(outT ~= nil and outW ~= nil and outH ~= nil)
   end

   return outT, outW, outH
end

-- Call this to turn off regeneration of random pooling regions each
-- updateOutput call.
function VolumetricFractionalMaxPooling:fixPoolingRegions(val)
   if val == nil then
      val = true
   end

   self.newRandomPool = val
   return self
end

function VolumetricFractionalMaxPooling:updateOutput(input)
   self.indices = self.indices or torch.LongTensor()
   if torch.typename(input):find('torch%.Cuda.*Tensor') then
      self.indices = torch.CudaLongTensor and self.indices:cudaLong() or self.indices
   else
      self.indices = self.indices:long()
   end
   self:initSampleBuffer_(input)
   local outT, outW, outH = self:getOutputSizes_(input)

   input.THNN.VolumetricFractionalMaxPooling_updateOutput(
      input:cdata(),
      self.output:cdata(),
      outT, outW, outH, self.poolSizeT, self.poolSizeW, self.poolSizeH,
      self.indices:cdata(), self.randomSamples:cdata())
   return self.output
end

function VolumetricFractionalMaxPooling:updateGradInput(input, gradOutput)
   assert(self.randomSamples ~= nil,
          'must call updateOutput/forward first')

   local outT, outW, outH = self:getOutputSizes_(input)

   input.THNN.VolumetricFractionalMaxPooling_updateGradInput(
      input:cdata(),
      gradOutput:cdata(),
      self.gradInput:cdata(),
      outT, outW, outH, self.poolSizeT, self.poolSizeW, self.poolSizeH,
      self.indices:cdata())
   return self.gradInput
end

-- backward compat
function VolumetricFractionalMaxPooling:empty()
   self:clearState()
end

function VolumetricFractionalMaxPooling:clearState()
   self.indices = nil
   self.randomSamples = nil
   return parent.clearState(self)
end

function VolumetricFractionalMaxPooling:__tostring__()
   return string.format('%s(%dx%dx%d, %d,%d,%d)', torch.type(self),
                        self.outT and self.outT or self.ratioT,
                        self.outW and self.outW or self.ratioW,
                        self.outH and self.outH or self.ratioH,
                        self.poolSizeT, self.poolSizeW, self.poolSizeH)
end
