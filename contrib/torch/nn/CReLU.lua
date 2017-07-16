local CReLU, parent = torch.class('nn.CReLU', 'nn.Sequential')

-- Implements the CReLU activation function as described by
-- W. Shang et al. in "Understanding and Improving Convolutional Neural Networks
-- via Concatenated Rectified Linear Units"
function CReLU:__init(nInputDims, inplace)
   parent.__init(self)
   self.nInputDims = nInputDims
   self.inplace = inplace or false

   local concatTable = nn.ConcatTable()
   concatTable:add(nn.Identity())
   concatTable:add(nn.MulConstant(-1))
   self:add(concatTable)
   self:add(nn.JoinTable(2))
   self:add(nn.ReLU(self.inplace))
end

function CReLU:updateOutput(input)
   local input_
   local batched = input:dim() == (self.nInputDims + 1)
   if not batched then
      input_ = input:view(1, -1)
  else
      input_ = input:view(input:size(1), -1)
  end
   parent.updateOutput(self, input_)
   local osize = input:size()
   if not batched then
      osize[1] = osize[1] * 2
   else
      osize[2] = osize[2] * 2
   end
   self.output:resize(osize)
   return self.output
end

function CReLU:backward(input, gradOutput)
   return self:updateGradInput(input, gradOutput)
end

function CReLU:updateGradInput(input, gradOutput)
   local batched = input:dim() == (self.nInputDims + 1)
   if not batched then
      parent.updateGradInput(self, input:view(1, -1), gradOutput:view(1, -1))
   else
      parent.updateGradInput(self, input:view(input:size(1), -1),
                                   gradOutput:view(input:size(1), -1))
   end

   self.gradInput:resizeAs(input)
   return self.gradInput
end

function CReLU:__tostring__()
   return "CReLU()"
end
