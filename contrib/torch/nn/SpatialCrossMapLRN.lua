local SpatialCrossMapLRN, parent = torch.class('nn.SpatialCrossMapLRN', 'nn.Module')

function SpatialCrossMapLRN:__init(size, alpha, beta, k)
  parent.__init(self)

  self.size = size
  self.alpha = alpha or 0.0001
  self.beta = beta or 0.75
  self.k = k or 1
end

function SpatialCrossMapLRN:updateOutput(input)
  assert(input:dim() == 3 or input:dim() == 4,
         'Input must be 3D or 4D')

  self.scale = self.scale or input.new()

  if torch.typename(input):find('torch%.Cuda.*Tensor') then
     input.THNN.SpatialCrossMapLRN_updateOutput(
        input:cdata(),
        self.output:cdata(),
        self.scale:cdata(),
        self.size,
        self.alpha,
        self.beta,
        self.k
     )
  else
     local isBatch = true
     if input:dim() == 3 then
       input = nn.utils.addSingletonDimension(input)
       isBatch = false
     end

     local batchSize   = input:size(1)
     local channels    = input:size(2)
     local inputHeight = input:size(3)
     local inputWidth  = input:size(4)

     self.output:resizeAs(input)
     self.scale:resizeAs(input)

     -- use output storage as temporary buffer
     local inputSquare = self.output
     inputSquare:pow(input, 2)

     local prePad = (self.size - 1)/2 + 1
     local prePadCrop = prePad > channels and channels or prePad

     local scaleFirst = self.scale:select(2,1)
     scaleFirst:zero()
     -- compute first feature map normalization
     for c = 1, prePadCrop do
       scaleFirst:add(inputSquare:select(2, c))
     end

     -- reuse computations for next feature maps normalization
     -- by adding the next feature map and removing the previous
     for c = 2, channels do
       local scalePrevious = self.scale:select(2, c -1)
       local scaleCurrent  = self.scale:select(2, c)
       scaleCurrent:copy(scalePrevious)
       if c < channels - prePad + 2 then
	 local squareNext   = inputSquare:select(2, c + prePad - 1)
	 scaleCurrent:add(1, squareNext)
       end
       if c > prePad  then
	 local squarePrevious = inputSquare:select(2, c - prePad )
	 scaleCurrent:add(-1, squarePrevious)
       end
     end

     self.scale:mul(self.alpha/self.size):add(self.k)

     self.output:pow(self.scale,-self.beta)
     self.output:cmul(input)

     if not isBatch then
       self.output = self.output[1]
     end
  end

  return self.output
end

function SpatialCrossMapLRN:updateGradInput(input, gradOutput)
  assert(input:dim() == 3 or input:dim() == 4,
         'Input must be 3D or 4D')

  if torch.typename(input):find('torch%.Cuda.*Tensor') then
     input.THNN.SpatialCrossMapLRN_updateGradInput(
        input:cdata(),
        gradOutput:cdata(),
        self.gradInput:cdata(),
        self.scale:cdata(),
        self.output:cdata(),
        self.size,
        self.alpha,
        self.beta,
        self.k
     )
  else
     local isBatch = true
     if input:dim() == 3 then
       input = nn.utils.addSingletonDimension(input)
       gradOutput = nn.utils.addSingletonDimension(gradOutput)
       self.output = nn.utils.addSingletonDimension(self.output)
       isBatch = false
     end

     local batchSize   = input:size(1)
     local channels    = input:size(2)
     local inputHeight = input:size(3)
     local inputWidth  = input:size(4)

     self.paddedRatio = self.paddedRatio or input.new()
     self.accumRatio = self.accumRatio or input.new()
     self.paddedRatio:resize(channels + self.size - 1, inputHeight, inputWidth)
     self.accumRatio:resize(inputHeight,inputWidth)

     local cacheRatioValue = 2*self.alpha*self.beta/self.size
     local inversePrePad = self.size - (self.size - 1) / 2

     self.gradInput:resizeAs(input)
     self.gradInput:pow(self.scale,-self.beta):cmul(gradOutput)

     self.paddedRatio:zero()
     local paddedRatioCenter = self.paddedRatio:narrow(1, inversePrePad, channels)
     for n = 1, batchSize do
       paddedRatioCenter:cmul(gradOutput[n],self.output[n])
       paddedRatioCenter:cdiv(self.scale[n])
       self.accumRatio:sum(self.paddedRatio:narrow(1,1,self.size-1), 1)
       for c = 1, channels do
	 self.accumRatio:add(self.paddedRatio[c+self.size-1])
	 self.gradInput[n][c]:addcmul(-cacheRatioValue, input[n][c], self.accumRatio)
	 self.accumRatio:add(-1, self.paddedRatio[c])
       end
     end

     if not isBatch then
       self.gradInput = self.gradInput[1]
       self.output = self.output[1]
     end
  end

  return self.gradInput
end


function SpatialCrossMapLRN:clearState()
   nn.utils.clear(self, 'scale', 'paddedRatio', 'accumRatio')
  return parent.clearState(self)
end
