local Mean, parent = torch.class('nn.Mean', 'nn.Sum')

--[[

This file is still here because of backward compatibility.

Please use instead "nn.Sum(dimension, nInputDims, sizeAverage)"

]]--


function Mean:__init(dimension, nInputDims)
   parent.__init(self, dimension, nInputDims, true)
end
