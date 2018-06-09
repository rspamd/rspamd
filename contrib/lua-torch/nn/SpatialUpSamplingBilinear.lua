require 'nn.THNN'
local SpatialUpSamplingBilinear, parent =
   torch.class('nn.SpatialUpSamplingBilinear', 'nn.Module')

--[[
Applies a 2D bilinear up-sampling over an input image composed of several
input planes.

The Y and X dimensions are assumed to be the last 2 tensor dimensions.  For
instance, if the tensor is 4D, then dim 3 is the y dimension and dim 4 is the x.

scale_factor is assumed to be a positive integer.
owidth  = (width-1)*(scale_factor-1) + width
oheight  = (height-1)*(scale_factor-1) + height

Alternatively, owidth and oheight can be directly provided as input.
--]]

function SpatialUpSamplingBilinear:__init(params)
   parent.__init(self)

   self.owidth, self.oheight, self.scale_factor = nil, nil, nil
   if torch.type(params) == 'table' then
      self.owidth, self.oheight = params.owidth, params.oheight
   else
      self.scale_factor = params
      if self.scale_factor < 1 then
         error('scale_factor must be greater than 1')
      end
      if math.floor(self.scale_factor) ~= self.scale_factor then
         error('scale_factor must be integer')
      end
   end
   self.inputSize = torch.LongStorage(4)
   self.outputSize = torch.LongStorage(4)
end

local function makeContiguous(self, input, gradOutput)
   if not input:isContiguous() then
      self._input = self._input or input.new()
      self._input:resizeAs(input):copy(input)
      input = self._input
   end
   if gradOutput then
      if not gradOutput:isContiguous() then
         self._gradOutput = self._gradOutput or gradOutput.new()
         self._gradOutput:resizeAs(gradOutput):copy(gradOutput)
         gradOutput = self._gradOutput
      end
   end
   return input, gradOutput
end

function SpatialUpSamplingBilinear:setSize(input)
   local xdim = input:dim()
   local ydim = xdim - 1
   for i = 1, input:dim() do
      self.inputSize[i] = input:size(i)
      self.outputSize[i] = input:size(i)
   end
   if self.scale_factor ~= nil then
      self.outputSize[ydim] = self.outputSize[ydim] * self.scale_factor
      self.outputSize[xdim] = self.outputSize[xdim] * self.scale_factor
   else
      self.outputSize[ydim] = self.oheight
      self.outputSize[xdim] = self.owidth
   end
end

function SpatialUpSamplingBilinear:updateOutput(input)
   assert(input:dim() == 4 or input:dim()==3,
            'SpatialUpSamplingBilinear only supports 3D or 4D tensors' )
   input = makeContiguous(self, input)
   local inputwas3D = false
   if input:dim() == 3 then
      input=input:view(-1, input:size(1), input:size(2), input:size(3))
      inputwas3D = true
   end
   local xdim = input:dim()
   local ydim = xdim - 1
   self:setSize(input)
   input.THNN.SpatialUpSamplingBilinear_updateOutput(
      input:cdata(),
      self.output:cdata(),
      self.outputSize[ydim],
      self.outputSize[xdim]
   )
   if inputwas3D then
      input = input:squeeze(1)
      self.output = self.output:squeeze(1)
   end
   return self.output
end

function SpatialUpSamplingBilinear:updateGradInput(input, gradOutput)
   assert(input:dim() == 4 or input:dim()==3,
            'SpatialUpSamplingBilinear only support 3D or 4D tensors' )
   assert(input:dim() == gradOutput:dim(),
	  'Input and gradOutput should be of same dimension' )
   input, gradOutput = makeContiguous(self, input, gradOutput)
   local inputwas3D = false
   if input:dim() == 3 then
      input = input:view(-1, input:size(1), input:size(2), input:size(3))
      gradOutput = gradOutput:view(-1, gradOutput:size(1), gradOutput:size(2),
				   gradOutput:size(3))
      inputwas3D = true
   end
   local xdim = input:dim()
   local ydim = xdim - 1
   self.gradInput:resizeAs(input)
   input.THNN.SpatialUpSamplingBilinear_updateGradInput(
      gradOutput:cdata(),
      self.gradInput:cdata(),
      input:size(1),
      input:size(2),
      input:size(3),
      input:size(4),
      self.outputSize[ydim],
      self.outputSize[xdim]
   )
   if inputwas3D then
      input = input:squeeze(1)
      gradOutput = gradOutput:squeeze(1)
      self.gradInput = self.gradInput:squeeze(1)
   end
   return self.gradInput
end


function SpatialUpSamplingBilinear:__tostring__()
   local s
   if self.scale_factor ~= nil then
      s = string.format('%s(%d)', torch.type(self), self.scale_factor)
   else
      s = string.format('%s(%d, %d)',
         torch.type(self), self.oheight, self.owidth)
   end
   return s
end
