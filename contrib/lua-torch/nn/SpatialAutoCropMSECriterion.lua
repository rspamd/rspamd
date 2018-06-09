--[[
   SpatialAutoCropMSECriterion.
   Implements the MSECriterion when the spatial resolution of the input is less than
   or equal to the spatial resolution of the target. It achieves this center-cropping
   the target to the same spatial resolution of the input and the MSE is then
   calculated between these cropped inputs
]]
local SpatialAutoCropMSECriterion, parent = torch.class('nn.SpatialAutoCropMSECriterion', 'nn.MSECriterion')

function SpatialAutoCropMSECriterion:__init(sizeAverage)
    parent.__init(self, sizeAverage)
end

local function centerCrop(input, cropSize)
   assert(input:dim() == 3 or input:dim() == 4, "input should be a 3D or  4D tensor")
   assert(#cropSize == 2, "cropSize should have two elements only")
   local _input = input
   if input:dim() == 3 then
      _input = input:view(1, input:size(1), input:size(2), input:size(3))
   end
   assert(cropSize[1] > 0 and cropSize[1] <= _input:size(3),
         "0 < cropSize[1] <= input:size(3) not satisfied")
   assert(cropSize[2] > 0 and cropSize[2] <= _input:size(4),
        "0 < cropSize[1] <= input:size(3) not satisfied")

   local inputHeight = _input:size(3)
   local inputWidth = _input:size(4)

   local rowStart = 1 + math.floor((inputHeight - cropSize[1])/2.0)
   local rowEnd = rowStart + cropSize[1] - 1
   local colStart = 1 +  math.floor((inputWidth - cropSize[2])/2.0)
   local colEnd = colStart + cropSize[2] - 1
   if input:dim() == 3 then
      return input[{{}, {rowStart, rowEnd}, {colStart, colEnd}}]
   else
      return input[{{}, {}, {rowStart, rowEnd}, {colStart, colEnd}}]
   end
end

local function getTensorHeightAndWidth(tensor)
   local heightIdx = 2
   local widthIdx = 3
   if tensor:dim() == 4 then
      heightIdx = 3
      widthIdx = 4
   end
   return tensor:size(heightIdx), tensor:size(widthIdx)
end

local function inputResolutionIsSmallerThanTargetResolution(input, target)
   local inputHeight, inputWidth = getTensorHeightAndWidth(input)
   local targetHeight, targetWidth = getTensorHeightAndWidth(target)
   return inputHeight <= targetHeight and inputWidth <= targetWidth
end

function SpatialAutoCropMSECriterion:updateOutput(input, target)
   assert(input:dim() == target:dim(), "input and target should have the same number of dimensions")
   assert(input:dim() == 4 or input:dim() == 3, "input and target must have 3 or 4 dimensions")
   assert(inputResolutionIsSmallerThanTargetResolution(input, target),
   "Spatial resolution of input should be less than or equal to the spatial resolution of the target")

   local inputHeight, inputWidth = getTensorHeightAndWidth(input)
   local targetCropped = centerCrop(target, {inputHeight, inputWidth})
   return parent.updateOutput(self, input, targetCropped)
end


function SpatialAutoCropMSECriterion:updateGradInput(input, gradOutput)
   assert(input:dim() == gradOutput:dim(), "input and gradOutput should have the same number of dimensions")
   assert(input:dim() == 4 or input:dim() == 3, "input and gradOutput must have 3 or 4 dimensions")
   assert(input:isSameSizeAs(gradOutput), "gradOutput and input must have the same size")

   return parent.updateGradInput(self, input, gradOutput)
end
